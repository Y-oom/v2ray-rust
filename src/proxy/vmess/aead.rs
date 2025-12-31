use crate::common::aead_helper::AeadCipherHelper;
use crate::common::net::PollUtil;
use crate::common::LW_BUFFER_SIZE;
use crate::proxy::vmess::vmess_stream::{CHUNK_SIZE, MAX_SIZE};
use crate::{debug_log, impl_read_utils};
use aes_gcm::Aes128Gcm;
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures_util::ready;
use gentian::gentian;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{cmp, io, slice};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// VMess AEAD 写入器，用于加密并写入数据
pub struct VmessAeadWriter {
    security: VmessSecurity,       // 加密算法（AES-128-GCM 或 ChaCha20-Poly1305）
    buffer: BytesMut,              // 写入缓冲区
    nonce: [u8; 32],              // 加密 nonce
    pos: usize,                   // 当前写入位置
    iv: BytesMut,                 // 初始化向量
    count: u16,                   // 数据块计数器
    data_len: usize,              // 数据长度
    state: u32,                   // 状态机生成器使用的状态
    write_res: Poll<io::Result<usize>>, // 写入结果
}
/// VMess 支持的加密算法
pub enum VmessSecurity {
    Aes128Gcm(Aes128Gcm),                  // AES-128-GCM 加密
    ChaCha20Poly1305(ChaCha20Poly1305),   // ChaCha20-Poly1305 加密
}

impl VmessSecurity {
    #[inline(always)]
    pub fn overhead_len(&self) -> usize {
        16
    }
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        12
    }
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        16
    }
}

impl VmessAeadWriter {
    pub fn new(iv: &[u8], security: VmessSecurity) -> VmessAeadWriter {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        VmessAeadWriter {
            security,
            buffer,
            nonce: [0u8; 32],
            pos: 0,
            iv,
            count: 0,
            data_len: 0,
            state: 0,
            write_res: Poll::Pending,
        }
    }

    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        w: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            if data.len() == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut minimal_data_to_write =
                cmp::min(CHUNK_SIZE - self.security.overhead_len(), data.len());
            let data = &data[..minimal_data_to_write];
            debug_log!("vmess: before encrypted data len:{}", data.len());
            self.encrypted_buffer(data);
            self.write_res = co_await(self.write_data(w, ctx));
            self.buffer.clear();
            debug_log!(
                "vmess: write data done,last writen len:{}",
                self.write_res.get_poll_res()
            );
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }

    /// 加密数据到缓冲区
    /// VMess AEAD 格式: [2字节长度(未加密)] + [加密数据 + 16字节认证标签]
    fn encrypted_buffer(&mut self, data: &[u8]) {
        self.data_len = data.len();
        debug_log!("raw data len:{}", self.data_len);
        // 1. 写入长度字段（未加密）
        self.buffer
            .reserve(self.data_len + 2 + self.security.tag_len());
        self.buffer
            .put_u16((self.data_len + self.security.tag_len()) as u16);
        debug_log!("encrypted buffer len1:{}", self.buffer.len());
        // 2. 构造加密数据缓冲区（数据 + AEAD 标签空间）
        let mbuf = &mut self.buffer.chunk_mut()[..self.data_len + self.security.tag_len()];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buffer.put_slice(data);
        debug_log!("encrypted buffer len2:{}", self.buffer.len());

        // 3. 构造 nonce（计数器 + IV）
        self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
        self.nonce[2..12].copy_from_slice(&self.iv[2..12]);
        // 4. 就地加密数据，并生成 AEAD 认证标签
        let aad = [0u8; 0];  // 空的附加认证数据
        let nonce_len = self.security.nonce_len();
        match &mut self.security {
            VmessSecurity::Aes128Gcm(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };  // 跳过 16 字节标签
            }
            VmessSecurity::ChaCha20Poly1305(cipher) => {
                cipher.encrypt_inplace_with_slice(&self.nonce[..nonce_len], &aad, mbuf);
                unsafe { self.buffer.advance_mut(16) };  // 跳过 16 字节标签
            }
        }
        debug_log!("encrypted buffer len3:{}", self.buffer.len());
        self.count += 1;  // 递增计数器，用于下一个数据块
        self.pos = 0
    }

    #[inline]
    fn write_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buffer.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buffer[self.pos..]))?;
            debug_log!("cur write len:{}", n);
            self.pos += n;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "write zero byte into writer",
                )));
            }
        }
        Poll::Ready(Ok(self.data_len))
    }
}

/// VMess AEAD 读取器，用于读取并解密数据
pub struct VmessAeadReader {
    security: VmessSecurity,            // 加密算法
    pub buffer: BytesMut,              // 读取缓冲区（pub 用于替换缓冲区）
    state: u32,                        // 状态机生成器使用的状态
    read_res: Poll<io::Result<()>>,   // 读取结果
    nonce: [u8; 32],                  // 解密 nonce
    iv: BytesMut,                     // 初始化向量
    data_length: usize,               // 数据长度
    count: u16,                       // 数据块计数器
    minimal_data_to_put: usize,       // 最小待放入数据量
    read_zero: bool,                  // 是否读取到零字节
}

impl VmessAeadReader {
    pub fn new(iv: &[u8], security: VmessSecurity) -> VmessAeadReader {
        let iv = BytesMut::from(iv);
        let buffer = BytesMut::new();
        VmessAeadReader {
            security,
            buffer,
            state: 0,
            read_res: Poll::Pending,
            nonce: [0u8; 32],
            iv,
            data_length: 0,
            count: 0,
            minimal_data_to_put: 0,
            read_zero: false,
        }
    }

    impl_read_utils!();

    /// 就地解密缓冲区数据
    /// 返回 true 表示解密成功，false 表示 AEAD 标签验证失败
    fn decrypted_data(&mut self) -> bool {
        let aad = [0u8; 0];  // 空的附加认证数据
        let nonce_len = self.security.nonce_len();
        match &mut self.security {
            VmessSecurity::Aes128Gcm(cipher) => cipher.decrypt_inplace_with_slice(
                &self.nonce[..nonce_len],
                &aad,
                &mut self.buffer[..self.data_length],
            ),
            VmessSecurity::ChaCha20Poly1305(cipher) => cipher.decrypt_inplace_with_slice(
                &self.nonce[..nonce_len],
                &aad,
                &mut self.buffer[..self.data_length],
            ),
        }
    }

    /// 从流中读取并解密 AEAD 加密的数据
    /// VMess AEAD 格式: [2字节长度] + [加密数据 + 16字节AEAD标签]
    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            // 1. 读取长度字段（2字节，未加密）
            debug_log!(
                "try read aead length, counter:{},buffer_len:{}",
                self.count,
                self.buffer.len()
            );
            self.read_res = co_await(self.read_at_least(r, ctx, 2));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.data_length = self.buffer.get_u16() as usize;
            if self.data_length > MAX_SIZE {
                let err = io::Error::new(ErrorKind::InvalidData, "buffer size too large!");
                return Poll::Ready(Err(err));
            }
            self.read_reserve(self.data_length);
            // 2. 读取加密数据（包含 AEAD 标签）
            self.read_res = co_await(self.read_at_least(r, ctx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            // 3. 构造 nonce（计数器 + IV）
            self.nonce[0..2].copy_from_slice(&self.count.to_be_bytes());
            self.nonce[2..12].copy_from_slice(&self.iv[2..12]);

            // 4. 解密数据（包含 AEAD 标签验证）
            if !self.decrypted_data() {
                debug_log!("read decrypted failed");
                return Poll::Ready(Err(io::Error::new(ErrorKind::Other, "invalid aead tag")));
            }
            self.count += 1;  // 递增计数器

            debug_log!(
                "data_length(include aead tag): {},buffer_len:{}",
                self.data_length,
                self.buffer.len()
            );
            self.data_length -= 16; // 移除 16 字节 AEAD 标签
            // 5. 将解密后的数据放入目标缓冲区
            while self.calc_data_to_put(dst) != 0 {
                dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
                self.data_length -= self.minimal_data_to_put;
                self.buffer.advance(self.minimal_data_to_put);
                debug_log!("buffer len:{}", self.buffer.len());
                debug_log!("put data len:{}", self.minimal_data_to_put);
                co_yield(Poll::Ready(Ok(())));
            }
            self.buffer.advance(16);  // 跳过 AEAD 标签
        }
    }
}
