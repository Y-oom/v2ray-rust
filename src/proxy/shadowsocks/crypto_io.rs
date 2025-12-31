//! ShadowSocks TCP 加密通讯接口

use std::{
    io,
    marker::Unpin,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};

use super::aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter};
use crate::common::net::poll_read_buf;
use crate::proxy::shadowsocks::context::SharedBloomContext;

use futures_util::ready;
use std::io::{Error, ErrorKind};

use crate::common::random_iv_or_salt;
use crate::proxy::shadowsocks::aead_helper::CipherKind;
use crate::proxy::{ProxyUdpStream, UdpRead, UdpWrite};
use crate::{impl_async_read, impl_async_useful_traits, impl_async_write, impl_flush_shutdown};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 解密读取器枚举
/// 支持无加密和 AEAD 两种模式
enum DecryptedReader {
    None,              // 无加密模式
    Aead(AeadDecryptedReader), // AEAD 加密模式
}

/// 加密写入器枚举
/// 支持无加密和 AEAD 两种模式
enum EncryptedWriter {
    None,              // 无加密模式
    Aead(AeadEncryptedWriter),  // AEAD 加密模式
}

/// 初始化解密读取器的状态机
enum ReadStatus {
    /// 等待接收初始化向量（IV）或 AEAD nonce（盐值）
    ///
    /// # 状态转移
    /// ShadowSocks 客户端在建立连接后，首先必须接收服务器发来的盐值来初始化解密器
    ///
    /// # 包含的数据
    /// - 第一个参数: 全局 BloomContext（用于重放攻击检测）
    /// - 第二个参数: 读取缓冲区（用于接收盐值）
    /// - 第三个参数: 加密算法类型
    /// - 第四个参数: 主密钥
    WaitIv(SharedBloomContext, BytesMut, CipherKind, Bytes),

    /// 连接已建立，解密读取器已初始化
    /// 可以正常读取和解密数据
    Established,
}

/// ShadowSocks 加密通讯流
/// 包装底层传输流，提供自动的加密/解密功能
/// 流程:
/// 1. 初始化阶段：等待接收服务器的盐值
/// 2. 已建立阶段：自动加密发送的数据，自动解密接收的数据
pub struct CryptoStream<S> {
    stream: S,                  // 底层传输流
    dec: Option<DecryptedReader>, // 解密读取器（可选，需要初始化）
    enc: EncryptedWriter,       // 加密写入器（初始化时已创建）
    read_status: ReadStatus,    // 读取状态机
}

impl<S: Unpin> Unpin for CryptoStream<S> {}

impl<S> CryptoStream<S> {
    /// 创建新的 ShadowSocks 加密通讯流
    ///
    /// # 初始化步骤
    /// 1. 如果使用无加密模式，直接跳过盐值阶段进入 Established
    /// 2. 否则，生成唯一的盐值并初始化 EncryptedWriter（用于发送数据）
    /// 3. 设置 ReadStatus 为 WaitIv，等待接收服务器的盐值来初始化解密器
    ///
    /// # 参数
    /// - context: 全局 BloomContext（用于重放攻击检测）
    /// - stream: 底层传输流
    /// - enc_key: 主密钥（通过密码派生）
    /// - method: 加密算法类型
    pub fn new(
        context: SharedBloomContext,
        stream: S,
        enc_key: Bytes,
        method: CipherKind,
    ) -> CryptoStream<S> {
        let key = enc_key;

        // 无加密模式特殊处理
        if method == CipherKind::None {
            return CryptoStream::<S>::new_none(stream);
        }

        let prev_len = method.salt_len();

        // 生成唯一的盐值
        let iv = match method {
            CipherKind::None => Vec::new(),
            _ => {
                loop {
                    let mut salt = vec![0u8; prev_len];
                    if prev_len > 0 {
                        // 生成随机盐值
                        random_iv_or_salt(&mut salt);
                    }

                    // 检查盐值是否唯一（防止重放攻击）
                    if context.check_nonce_and_set(&salt) {
                        // 盐值已存在，生成新的
                        continue;
                    }
                    break salt;  // 生成了唯一的盐值
                }
            }
        };

        // 创建加密写入器（会将盐值放在缓冲区开头）
        let enc = match method {
            CipherKind::None => EncryptedWriter::None,
            _ => EncryptedWriter::Aead(AeadEncryptedWriter::new(method, &key, &iv)),
        };

        CryptoStream {
            stream,
            dec: None,  // 解密器尚未初始化，需要等待接收服务器的盐值
            enc,
            read_status: ReadStatus::WaitIv(
                context,
                BytesMut::with_capacity(prev_len),
                method,
                key,
            ),
        }
    }

    /// 创建无加密的 CryptoStream（plaintext 模式）
    fn new_none(stream: S) -> CryptoStream<S> {
        CryptoStream {
            stream,
            dec: Some(DecryptedReader::None),  // 无加密读取器
            enc: EncryptedWriter::None,        // 无加密写入器
            read_status: ReadStatus::Established, // 直接进入已建立状态
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncRead + Unpin,
{
    /// TCP 握手阶段：接收服务器的盐值并初始化解密读取器
    ///
    /// # 状态转移
    /// WaitIv → Established
    ///
    /// # 流程
    /// 1. 等待接收盐值（字节数 = method.salt_len()）
    /// 2. 校验盐值是否重复（防止重放攻击）
    /// 3. 使用盐值初始化解密读取器
    /// 4. 转到 Established 状态，允许读取和解密数据
    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref ctx, ref mut buf, method, ref key) = self.read_status {
            // 读取完整的盐值
            while buf.len() != buf.capacity() {
                let n = ready!(poll_read_buf(&mut self.stream, cx, buf))?;
                // 读取失败（对端关闭连接）
                if n == 0 {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                }
            }

            let nonce = buf.as_ref();
            // 收到盐值后，检查是否重复（防止重放攻击）
            if ctx.check_nonce_and_set(nonce) {
                let err = Error::new(ErrorKind::Other, "detected repeated iv/salt");
                return Poll::Ready(Err(err));
            }

            // 根据加密算法类型初始化支持读取器
            let dec = match method {
                CipherKind::None => DecryptedReader::None,
                _ => {
                    // 使用服务器发来的盐值初始化 AEAD 解密器
                    DecryptedReader::Aead(AeadDecryptedReader::new(method, key, nonce))
                }
            };

            self.dec = Some(dec);
            self.read_status = ReadStatus::Established;  // 握手完成，进入已建立状态
        }

        Poll::Ready(Ok(()))
    }

    /// 读取并解密数据
    ///
    /// # 流程
    /// 1. 先完成 TCP 握手（接收盐值）
    /// 2. 然后根据加密类型读取并解密数据
    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 首先完成握手（接收服务器的盐值）
        ready!(this.poll_read_handshake(ctx))?;

        // 握手完成后，根据加密类型读取数据
        match *this.dec.as_mut().unwrap() {
            DecryptedReader::None => Pin::new(&mut this.stream).poll_read(ctx, buf),  // 无加密
            DecryptedReader::Aead(ref mut r) => r.poll_read_decrypted(ctx, &mut this.stream, buf), // AEAD 解密
        }
    }
}

impl<S> CryptoStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// 加密并写入数据
    ///
    /// # 行为
    /// 根据加密类型，自动加密数据后写入到底层流
    /// - 无加密模式：直接传递给底层流
    /// - AEAD 模式：自动加密并添加认证标签
    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.enc {
            EncryptedWriter::None => Pin::new(&mut this.stream).poll_write(ctx, buf), // 无加密
            EncryptedWriter::Aead(ref mut w) => w.poll_write_encrypted(ctx, &mut this.stream, buf), // AEAD 加密
        }
    }

    impl_flush_shutdown!();
}
impl_async_useful_traits!(CryptoStream);

impl<S: ProxyUdpStream> UdpRead for CryptoStream<S> {}

impl<S: ProxyUdpStream> UdpWrite for CryptoStream<S> {}
