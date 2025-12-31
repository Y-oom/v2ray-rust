//! ShadowSocks UDP 加密协议实现
//! （改编自 shadowsocks-rust 源代码）
//!
//! 支持两种加密模式：流密码和 AEAD
//!
//! ## 流密码模式（已弃用）
//! ```plain
//! +-------+----------+
//! |  IV   | Payload  |
//! +-------+----------+
//! | 固定  | 可变     |
//! +-------+----------+
//! ```
//!
//! ## AEAD 加密模式（当前推荐）
//! ```plain
//! UDP（加密后的密文）
//! +--------+----------+----------+
//! | NONCE  |  数据   |  认证标签 |
//! +--------+----------+----------+
//! | 固定   | 可变    | 固定(16字节)|
//! +--------+----------+----------+
//! ```
use byte_string::ByteStr;
use std::io::{self, Cursor, Error, ErrorKind};

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::debug_log;
use crate::proxy::shadowsocks::aead_helper::{AeadCipher, CipherKind};
use crate::proxy::shadowsocks::context::BloomContext;
use crate::proxy::shadowsocks::context::SharedBloomContext;
use crate::proxy::{Address, ProxyUdpStream, UdpRead, UdpWrite};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::ready;
use gentian::gentian;
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 加密负载数据为 ShadowSocks UDP 加密数据包
///
/// # UDP 数据包格式（无加密）
/// Address + Payload
///
/// # UDP 数据包格式（AEAD 加密）
/// Salt + Encrypted(Address + Payload + TAG)
///
/// # 参数
/// - context: 全局 BloomContext（用于 nonce 生成和重放检测）
/// - method: 加密算法类型
/// - key: 主密钥
/// - addr: 目标地址
/// - payload: 待加密的负载数据
/// - dst: 输出缓冲区
pub fn encrypt_payload(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    match method {
        CipherKind::None => {
            // 无加密模式：直接连接地址和负载
            dst.reserve(addr.serialized_len() + payload.len());
            addr.write_to_buf(dst);
            dst.put_slice(payload);
        }
        // AEAD 加密模式
        _ => encrypt_payload_aead(context, method, key, addr, payload, dst),
    }
}

/// 使用 AEAD 加密模式加密 UDP 负载
///
/// # 数据包布局
/// ```
/// [Salt(盐值)] + [加密数据 + 认证标签]
///   salt_len        addr_len + payload_len + tag_len
/// ```
///
/// # 加密步骤
/// 1. 生成唯一的随机盐值
/// 2. 使用盐值初始化 AEAD 密码机制
/// 3. 将地址和负载放入缓冲区
/// 4. 预留 AEAD 认证标签空间
/// 5. 就地加密整个 (地址+负载) 以生成密文和标签
fn encrypt_payload_aead(
    context: &BloomContext,
    method: CipherKind,
    key: &[u8],
    addr: &Address,
    payload: &[u8],
    dst: &mut BytesMut,
) {
    let salt_len = method.salt_len();
    let addr_len = addr.serialized_len();

    // 预留空间: 盐值 + 地址 + 负载 + AEAD 标签
    dst.reserve(salt_len + addr_len + payload.len() + method.tag_len());

    // 生成并放入盐值
    dst.resize(salt_len, 0);
    let salt = &mut dst[..salt_len];

    if salt_len > 0 {
        // 生成唯一的盐值（allowduplicates=false，因为 UDP 可能丢包，不需要防重放）
        context.generate_nonce(salt, false);
        trace!("UDP packet generated aead salt {:?}", ByteStr::new(salt));
    }

    // 用生成的盐值初始化 AEAD 密码
    let mut cipher = AeadCipher::new(method, key, salt);

    // 将地址和负载追加到缓冲区
    addr.write_to_buf(dst);
    dst.put_slice(payload);

    // 为 AEAD 认证标签预留空间
    unsafe {
        dst.advance_mut(method.tag_len());
    }

    // 对盐值后面的所有数据进行就地加密
    // 包括: 地址 + 负载 + 标签空间
    let m = &mut dst[salt_len..];
    cipher.encrypt(m);  // 就地加密，生成密文 + 认证标签
}

/// 解密 ShadowSocks UDP 加密数据包负载
///
/// # 返回值
/// (负载长度, 目标地址)
///
/// # 参数
/// - method: 加密算法类型
/// - key: 主密钥
/// - payload: 输入/输出缓冲区（包含加密数据包，输出为明文负载）
///
/// # 无加密模式
/// 直接从数据包中解析地址，移动负载数据到缓冲区开头
///
/// # AEAD 加密模式
/// 分离盐值、解密地址+负载、解析地址、计算最终负载位置
pub fn decrypt_payload(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    match method {
        CipherKind::None => {
            // 无加密模式
            let mut cur = Cursor::new(payload);
            match Address::read_from_cursor(&mut cur) {
                Ok(address) => {
                    let pos = cur.position() as usize;
                    let payload = cur.into_inner();
                    // 将负载数据移到缓冲区开头
                    payload.copy_within(pos.., 0);
                    Ok((payload.len() - pos, address))
                }
                Err(..) => {
                    let err = Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
                    Err(err)
                }
            }
        }
        // AEAD 加密模式
        _ => decrypt_payload_aead(method, key, payload),
    }
}

/// 解密 AEAD 加密的 UDP 负载
///
/// # 数据流
/// 输入:  [盐值(salt_len)] + [密文地址] + [密文负载] + [AEAD标签]
/// 输出:  [明文负载(移到缓冲区开头)]
///
/// # 步骤
/// 1. 分离盐值和加密数据
/// 2. 用盐值初始化解密器
/// 3. 就地解密（验证 AEAD 标签）
/// 4. 从解密后的数据中解析地址
/// 5. 将负载数据移到缓冲区开头
fn decrypt_payload_aead(
    method: CipherKind,
    key: &[u8],
    payload: &mut [u8],
) -> io::Result<(usize, Address)> {
    let plen = payload.len();
    let salt_len = method.salt_len();

    // 检查最小长度
    if plen < salt_len {
        let err = Error::new(ErrorKind::InvalidData, "udp packet too short for salt");
        return Err(err);
    }

    // 分离盐值和加密数据
    let (salt, data) = payload.split_at_mut(salt_len);
    // 注意：UDP 不需要检查重放（数据可能丢包或乱序）

    trace!("UDP packet got AEAD salt {:?}", ByteStr::new(salt));

    let tag_len = method.tag_len();
    let mut cipher = AeadCipher::new(method, key, salt);

    // 检查加密数据是否包含标签
    if data.len() < tag_len {
        return Err(Error::new(ErrorKind::Other, "udp packet too short for tag"));
    }

    // 就地解密，验证 AEAD 标签
    if !cipher.decrypt(data) {
        return Err(Error::new(ErrorKind::Other, "invalid tag-in"));
    }

    // 移除 AEAD 标签（只保留解密后的数据）
    let data_len = data.len() - tag_len;
    let data = &mut data[..data_len];

    // 从解密后的数据中解析地址和其长度
    let (dn, addr) = parse_packet(data)?;

    // 计算负载长度和位置
    let data_length = data_len - dn;
    let data_start_idx = salt_len + dn;  // 负载在原缓冲区中的位置
    let data_end_idx = data_start_idx + data_length;

    // 将负载数据复制到缓冲区开头，去掉地址部分
    payload.copy_within(data_start_idx..data_end_idx, 0);

    Ok((data_length, addr))
}

/// 解析 UDP 数据包中的地址信息
///
/// # 返回值
/// (地址字节数, 地址对象)
fn parse_packet(buf: &[u8]) -> io::Result<(usize, Address)> {
    let mut cur = Cursor::new(buf);
    match Address::read_from_cursor(&mut cur) {
        Ok(address) => {
            let pos = cur.position() as usize;  // 地址序列化后的长度
            Ok((pos, address))
        }
        Err(..) => {
            let err = Error::new(ErrorKind::InvalidData, "parse udp packet Address failed");
            Err(err)
        }
    }
}

/// ShadowSocks UDP 通讯流
/// 用于 UDP 模式下的加密/解密通讯
pub struct ShadowSocksUdpStream<T> {
    stream: T,                      // 底层 UDP 流
    addr: Address,                  // 服务器地址（用于发送所有数据包）
    context: SharedBloomContext,    // 全局上下文（用于盐值生成）
    write_buffer: BytesMut,         // 写入缓冲区（用于加密数据）
    method: CipherKind,             // 加密算法类型
    key: Bytes,                     // 主密钥
    state: u32,                     // 状态机状态（用于 gentian 协程）
    write_res: Poll<io::Result<usize>>, // 写入操作结果（用于状态机）
}

impl<T> ShadowSocksUdpStream<T> {
    /// 创建新的 ShadowSocks UDP 通讯流
    ///
    /// # 参数
    /// - io: 底层 UDP 流实现
    /// - addr: 服务器地址（所有发送的数据包都会发往这个地址）
    /// - context: 全局 BloomContext（用于 nonce 生成）
    /// - method: 加密算法类型（AES-128-GCM, AES-256-GCM, 或 ChaCha20-Poly1305）
    /// - key: 主密钥（通过密码派生）
    ///
    /// # 初始化
    /// 设置初始状态为 0（用于 gentian 协程状态管理）
    /// 创建空的写入缓冲区（用于临时存储加密后的数据）
    pub fn new(
        io: T,
        addr: Address,
        context: SharedBloomContext,
        method: CipherKind,
        key: Bytes,
    ) -> Self {
        debug_log!("build ss udp stream, addr is:{}", addr);
        Self {
            stream: io,
            addr,
            context,
            write_buffer: Default::default(),
            method,
            key,
            state: 0,
            write_res: Poll::Pending,
        }
    }
}

impl<T: UdpRead + Unpin> ShadowSocksUdpStream<T> {
    /// UDP 接收流程处理函数
    ///
    /// # 工作流程
    /// 1. 从底层 UDP 流接收加密数据包
    /// 2. 调用 `decrypt_payload()` 解密数据包并提取目标地址
    /// 3. 更新缓冲区填充长度（指向解密后的负载）
    /// 4. 返回发送方地址（用于请求的上游地址转发）
    ///
    /// # 返回值
    /// Poll<io::Result<Address>> - 返回原始请求的目标地址（通过 UDP 数据包传递的）
    /// 实际的发送方地址由 UdpRead trait 处理
    fn priv_poll_recv_from(
        this: &mut ShadowSocksUdpStream<T>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        // 从底层 UDP 流接收加密后的数据包
        let r = Pin::new(&mut this.stream);
        let _ = ready!(r.poll_recv_from(cx, dst))?;
        // 解密数据包并提取目标地址
        // decrypt_payload 会修改 dst.filled_mut() 使其指向解密后的负载（去掉地址部分）
        let (n, addr) = decrypt_payload(this.method, &this.key, dst.filled_mut())?;
        // 更新缓冲区填充长度為解密后的负载长度
        dst.set_filled(n);
        debug_log!("recv from addr:{}, len:{}", addr, dst.filled().len());
        // 返回原始请求的目标地址（从 UDP 加密数据包中解析出的地址）
        Ok(addr).into()
    }
}
impl<T: UdpRead + Unpin> UdpRead for ShadowSocksUdpStream<T> {
    /// UdpRead trait 实现：接收并自动解密 UDP 数据包
    ///
    /// 将调用委托给 `priv_poll_recv_from()` 来处理实际的接收和解密逻辑
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let this = self.get_mut();
        Self::priv_poll_recv_from(this, cx, buf)
    }
}

impl<T: UdpWrite + Unpin> UdpWrite for ShadowSocksUdpStream<T> {
    /// UdpWrite trait 实现：加密并发送 UDP 数据包
    ///
    /// 将调用委托给 `priv_poll_write()` 来处理实际的加密和发送逻辑。
    /// 虽然接收 `target` 地址参数，但会将所有数据包发送到初始化时设置的服务器地址 `self.addr`
    /// （因为在 ShadowSocks 协议中，真实的目标地址被加密并放在数据包的地址字段中）
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: &Address,
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.priv_poll_write(cx, buf, target)
    }
}

impl<T: ProxyUdpStream> AsyncRead for ShadowSocksUdpStream<T> {
    /// AsyncRead trait 的桩实现
    ///
    /// UDP 流不支持连续的字节流读取（AsyncRead），只支持按数据包读取。
    /// 使用 `UdpRead` trait 代替来接收数据包。
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        unimplemented!()
    }
}

impl<T: ProxyUdpStream> AsyncWrite for ShadowSocksUdpStream<T> {
    /// AsyncWrite trait 的桩实现
    ///
    /// UDP 流不支持连续的字节流写入（AsyncWrite），只支持按数据包写入。
    /// 使用 `UdpWrite` trait 代替来发送数据包。
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        unimplemented!();
    }

    /// UDP 流不需要 flush 操作
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unimplemented!();
    }

    /// UDP 流不需要 shutdown 操作（无连接协议）
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unimplemented!();
    }
}

impl<T: UdpWrite + Unpin> ShadowSocksUdpStream<T> {
    /// 使用 gentian 协程实现的 UDP 发送流程
    ///
    /// # 协程机制
    /// 使用 `#[gentian]` 宏将普通的 Rust 代码转换为异步状态机
    /// - `co_await()` 等待异步操作完成，操作结果保存在状态中
    /// - `co_yield()` 返回 Poll::Pending，保留当前状态以便下次恢复
    ///
    /// # 发送流程
    /// 1. 调用 `encrypt_payload()` 将目标地址和数据一起加密
    ///    （加密后格式：[Salt(16字节)] + [加密地址] + [加密数据] + [AEAD标签]）
    /// 2. 通过 `poll_send_to()` 将加密数据包发送到服务器地址 `self.addr`
    ///    （而不是原始目标地址 `addr`，真实地址已被加密在数据包中）
    /// 3. 发送完成后清空缓冲区，回到循环开始
    ///
    /// # 参数
    /// - data: 待加密的明文数据
    /// - addr: 原始目标地址（会被加密并放在数据包的地址字段中）
    ///
    /// # 返回值
    /// Poll<io::Result<usize>> - 返回原始数据的字节数（如果是多包则为第一包的字节数）
    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn priv_poll_write(
        &mut self,
        cx: &mut Context<'_>,
        data: &[u8],
        addr: &Address,
    ) -> Poll<io::Result<usize>> {
        loop {
            // 第一步：加密数据和目标地址，放入写入缓冲区
            encrypt_payload(
                &self.context,
                self.method,
                &self.key,
                addr,
                data,
                &mut self.write_buffer,
            );
            debug_log!(
                "encrypted buffer len:{},data len:{},tar addr:{}",
                self.write_buffer.len(),
                data.len(),
                addr
            );
            debug_log!("poll sendto {}, before addr:{}", self.addr, addr);
            // 第二步：发送加密后的数据包到服务器（self.addr 是预配置的服务器地址）
            // 虽然接收的是原始地址 addr，但实际发送到服务器地址 self.addr
            // 真实目标地址已被加密在数据包负载中
            self.write_res = co_await(Pin::new(&mut self.stream).poll_send_to(
                cx,
                &self.write_buffer,
                &self.addr,
            ));
            // 第三步：发送完成后清空缓冲区，为下一次循环做准备
            self.write_buffer.clear();
            // 使用 co_yield 返回当前的发送结果，并恢复状态机
            co_yield(std::mem::replace(&mut self.write_res, Poll::Pending));
        }
    }
}
