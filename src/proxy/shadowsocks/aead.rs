use std::{
    cmp,
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{Context, Poll},
    u16,
};

use bytes::{Buf, BufMut, BytesMut};

use crate::common::{net::PollUtil, LW_BUFFER_SIZE};
use futures_util::ready;
use gentian::gentian;

use crate::impl_read_utils;
use crate::proxy::shadowsocks::aead_helper::{AeadCipher, CipherKind};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// AEAD 数据包最大负载大小
/// ShadowSocks AEAD 格式限制：2字节长度字段只能表示最多 0x3FFF (16383) 字节
pub const MAX_PACKET_SIZE: usize = 0x3FFF;  // 16383 字节

/// AEAD 解密读取器
/// 自动从底层流读取加密数据，并解密为明文
/// 协议格式：[2字节加密长度+16字节标签] + [加密数据+16字节标签] + ...
pub struct DecryptedReader {
    buffer: BytesMut,                // 读取缓冲区
    cipher: AeadCipher,              // AEAD 密码机制
    tag_size: usize,                 // AEAD 认证标签大小（固定 16 字节）
    state: u32,                      // 状态机状态（用于 gentian 协程）
    data_length: usize,              // 当前数据块的长度
    minimal_data_to_put: usize,      // 等待放入目标缓冲区的最小字节数
    read_res: Poll<io::Result<()>>,  // 上一次读取操作的结果
    read_zero: bool,                 // 记录是否读到 EOF
}

impl DecryptedReader {
    /// 创建新的 AEAD 解密读取器
    ///
    /// # 参数
    /// - method: 加密算法（AES-128-GCM, AES-256-GCM, 或 ChaCha20-Poly1305）
    /// - key: 主密钥（通过密码派生）
    /// - iv_or_salt: 初始化向量/盐值，第一个数据包中发送给对方
    pub fn new(method: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> DecryptedReader {
        DecryptedReader {
            buffer: BytesMut::with_capacity(LW_BUFFER_SIZE * 2),
            cipher: AeadCipher::new(method, key, iv_or_salt),
            tag_size: method.tag_len(),
            state: 0,
            data_length: 0,
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            read_zero: false,
        }
    }

    impl_read_utils!();
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
            self.read_res = co_await(self.read_at_least(r, ctx, self.tag_size + 2));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            self.data_length = DecryptedReader::decrypt_length(
                &mut self.cipher,
                &mut self.buffer.as_mut()[0..self.tag_size + 2],
            )? + self.tag_size;
            self.buffer.advance(self.tag_size + 2);
            self.read_reserve(self.data_length);
            self.read_res = co_await(self.read_at_least(r, ctx, self.data_length));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            if !self
                .cipher
                .decrypt(&mut self.buffer.as_mut()[0..self.data_length])
            {
                return Poll::Ready(Err(io::Error::new(ErrorKind::Other, "invalid aead tag")));
            }
            self.data_length -= self.tag_size;
            while self.calc_data_to_put(dst) != 0 {
                dst.put_slice(&self.buffer.as_ref()[0..self.minimal_data_to_put]);
                self.data_length -= self.minimal_data_to_put;
                self.buffer.advance(self.minimal_data_to_put);
                co_yield(Poll::Ready(Ok(())));
            }
            self.buffer.advance(self.tag_size);
        }
    }

    /// 解密长度字段
    ///
    /// ShadowSocks AEAD 的长度字段也是加密的：
    /// 原始: [2字节明文长度] + 加密得到 [2字节加密长度 + 16字节标签]
    /// 输入缓冲区 m 包含 [加密长度(2字节) + 标签(16字节)]
    /// 成功后，m 的前 2 字节为明文长度值
    fn decrypt_length(cipher: &mut AeadCipher, m: &mut [u8]) -> io::Result<usize> {
        let plen = {
            // 解密长度字段（2字节长度 + 16字节标签）
            if !cipher.decrypt(m) {
                return Err(io::Error::new(ErrorKind::Other, "invalid tag-in"));
            }

            // 从解密后的前 2 字节读取长度（大端序）
            u16::from_be_bytes([m[0], m[1]]) as usize
        };

        // 检查长度是否超过最大限制
        if plen > MAX_PACKET_SIZE {
            let err = io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "buffer size too large ({:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero",
                    plen
                ),
            );
            return Err(err);
        }
        Ok(plen)
    }
}

/// AEAD 加密写入器
/// 自动加密明文数据并写入底层流
/// 协议格式：[盐值] + [加密长度+标签] + [加密数据+标签] + ...
/// （第一个包包含盐值，后续包不包含）
pub struct EncryptedWriter {
    cipher: AeadCipher,           // AEAD 密码机制
    tag_size: usize,              // AEAD 认证标签大小（固定 16 字节）
    state: u32,                   // 状态机状态（用于 gentian 协程）
    buf: BytesMut,                // 写入缓冲区
    pos: usize,                   // 当前缓冲区写入位置
    data_len: usize,              // 最后一次加密的数据长度
    write_res: Poll<io::Result<usize>>, // 上一次写入操作的结果（用于状态机）
}

impl EncryptedWriter {
    /// 创建新的 AEAD 加密写入器
    ///
    /// # 特殊处理
    /// 生成的盐值会立即放入缓冲区的开头，以便在第一个数据包中发送给对方
    /// ShadowSocks 服务器通过接收这个盐值来初始化解密器
    pub fn new(method: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> EncryptedWriter {
        // 盐值需要通过第一个数据包发送给对方
        let mut buf = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        buf.put(iv_or_salt);  // 将盐值放在缓冲区开头

        EncryptedWriter {
            cipher: AeadCipher::new(method, key, iv_or_salt),
            tag_size: method.tag_len(),
            state: 0,
            buf,
            pos: 0,
            data_len: 0,
            write_res: Poll::Pending,
        }
    }

    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_write_encrypted<W>(
        &mut self,
        ctx: &mut Context<'_>,
        w: &mut W,
        mut data: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            // we already put nonce
            let minimal_data_to_write = cmp::min(MAX_PACKET_SIZE, data.len());
            self.buf
                .reserve(minimal_data_to_write + 2 + self.tag_size * 2);
            data = &data[..minimal_data_to_write];
            self.encrypted_buffer(data);
            self.write_res = co_await(self.write_data(w, ctx));
            self.buf.clear();
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }

    #[inline]
    fn write_data<W>(&mut self, w: &mut W, ctx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin,
    {
        while self.pos < self.buf.len() {
            let n = ready!(Pin::new(&mut *w).poll_write(ctx, &self.buf[self.pos..]))?;
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

    /// 将明文数据加密并缓冲
    /// ShadowSocks AEAD 两步加密过程：
    /// 1. 加密长度字段：2字节明文长度 → 加密 → 2字节密文 + 16字节标签
    /// 2. 加密数据：明文 → 加密 → 密文 + 16字节标签
    fn encrypted_buffer(&mut self, data: &[u8]) {
        self.data_len = data.len();

        // 第一步：加密长度字段
        // 在缓冲区中写入 2 字节长度（大端序）+ 16 字节标签空间
        let mbuf = &mut self.buf.chunk_mut()[..2 + self.tag_size];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buf.put_u16(self.data_len as u16);  // 写入长度值
        self.cipher.encrypt(mbuf);              // 就地加密，生成密文 + 标签
        unsafe { self.buf.advance_mut(self.tag_size) };  // 跳过标签部分

        // 第二步：加密数据
        // 在缓冲区中写入数据 + 标签空间
        let mbuf = &mut self.buf.chunk_mut()[..self.data_len + self.tag_size];
        let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        self.buf.put_slice(data);              // 写入明文数据
        self.cipher.encrypt(mbuf);             // 就地加密，生成密文 + 标签
        unsafe {
            self.buf.advance_mut(self.tag_size);  // 跳过标签部分
        }

        self.pos = 0;  // 重置写入位置，准备发送
    }
}
