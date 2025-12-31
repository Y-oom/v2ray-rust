use aes_gcm::Aes128Gcm;
use std::hash::Hasher;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::aead_helper::AeadCipherHelper;
use crate::common::fnv1a::Fnv1aHasher;
use crate::common::net::PollUtil;
use crate::common::{random_iv_or_salt, sha256};
use crate::proxy::vmess::aead::{VmessAeadReader, VmessAeadWriter, VmessSecurity};
use crate::proxy::vmess::aead_header::{seal_vmess_aead_header, VmessHeaderReader};
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::{Address, UdpRead, UdpWrite};
use crate::{
    debug_log, impl_async_read, impl_async_useful_traits, impl_async_write, impl_flush_shutdown,
    md5,
};
use gentian::gentian;
use rand::random;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

// VMess 协议常量定义
pub const MAX_SIZE: usize = 17 * 1024;              // 最大数据块大小：17KB
pub const CHUNK_SIZE: usize = 1 << 14;              // 数据块大小：16KB
pub const VERSION: u8 = 1;                          // VMess 协议版本
pub const OPT_CHUNK_STREAM: u8 = 1;                 // 选项：分块流模式
pub const COMMAND_UDP: u8 = 0x02;                   // 命令：UDP 转发
pub const COMMAND_TCP: u8 = 0x01;                   // 命令：TCP 转发
pub const AES_128_GCM_SECURITY_NUM: u8 = 0x03;      // 加密类型：AES-128-GCM
pub const CHACHA20POLY1305_SECURITY_NUM: u8 = 0x04; // 加密类型：ChaCha20-Poly1305
#[allow(dead_code)]
pub const NONE_SECURITY_NUM: u8 = 0x05;             // 加密类型：无加密（不推荐）

/// VMess 流包装器，处理 VMess 协议的加密/解密和头部处理
pub struct VmessStream<S> {
    stream: S,                                 // 底层传输流
    option: VmessOption,                       // VMess 配置选项
    reader: VmessAeadReader,                   // AEAD 读取器（解密数据）
    writer: VmessAeadWriter,                   // AEAD 写入器（加密数据）
    salt: [u8; 64],                           // 密钥派生盐值（包含请求和响应密钥/IV）
    respv: u8,                                // 响应版本号（用于验证）
    header_reader: Box<VmessHeaderReader>,    // 响应头读取器
    header_buffer: BytesMut,                  // 请求头缓冲区
    header_pos: usize,                        // 请求头写入位置
    state_1: u32,                             // 状态机状态（用于读取）
    state_2: u32,                             // 状态机状态（用于写入）
    header_write_res: Poll<io::Result<usize>>, // 头部写入结果
    header_read_res: Poll<io::Result<()>>,    // 头部读取结果
}

impl<S> VmessStream<S> {
    /// 构造 VMess 请求头数据
    /// 格式: [版本(1)] + [请求体IV(16)] + [请求体密钥(16)] + [响应版本(1)] + [选项(1)]
    ///      + [安全类型(1)] + [保留(1)] + [命令(1)] + [目标地址(变长)] + [填充(0-15)] + [校验和(4)]
    fn construct_header_data(&mut self) {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);              // VMess 版本号
        buf.put(self.req_body_iv());      // 请求体 IV（16 字节）
        buf.put(self.req_body_key());     // 请求体密钥（16 字节）
        debug_log!("req body key:{:02X?}", &self.req_body_key());
        buf.put_u8(self.respv);           // 响应版本号（用于验证服务器响应）
        buf.put_u8(OPT_CHUNK_STREAM);     // 选项：启用分块流
        let x = random::<u8>() % 16;      // 随机填充长度（0-15）
        buf.put_u8((x << 4) | self.option.security_num);  // 高4位：填充长度，低4位：加密类型
        buf.put_u8(0);                    // 保留字段
        buf.put_u8(if self.option.is_udp {
            debug_log!("vmess command udp detected");
            COMMAND_UDP               // UDP 转发命令
        } else {
            COMMAND_TCP               // TCP 转发命令
        });
        self.option.addr.write_to_buf_vmess(&mut buf);  // 写入目标地址
        if x > 0 {
            // 添加随机填充（混淆流量特征）
            let mut padding = [0u8; 16];
            random_iv_or_salt(&mut padding);
            buf.put(&padding[0..x as usize]);
        }
        // 计算 FNV1a 校验和
        let mut hasher = Fnv1aHasher::default();
        hasher.write(&buf);
        buf.put_u32(hasher.finish() as u32);
        // 使用 UUID + 固定盐值派生命令密钥
        let cmd_key = md5!(
            self.option.uuid.as_bytes(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
        );
        // 封装 AEAD 加密的请求头
        self.header_buffer = seal_vmess_aead_header(&cmd_key, &buf)
    }

    #[inline]
    pub fn req_body_iv(&self) -> &[u8] {
        &self.salt[0..16]  // 请求体 IV（字节 0-15）
    }

    #[inline]
    pub fn req_body_key(&self) -> &[u8] {
        &self.salt[16..32]  // 请求体密钥（字节 16-31）
    }
    // 响应体密钥和 IV 访问器（已注释，直接从 salt 数组访问）
    // #[inline]
    // pub fn resp_body_key(&self) -> &[u8] {
    //     &self.salt[32..48]  // 响应体密钥（字节 32-47）
    // }
    // #[inline]
    // pub fn resp_body_iv(&self) -> &[u8] {
    //     &self.salt[48..]  // 响应体 IV（字节 48-63）
    // }

    /// 创建新的 VMess 流实例
    /// Salt 数组布局（64字节）：
    /// - [0-15]:   请求体 IV（随机生成）
    /// - [16-31]:  请求体密钥（随机生成）
    /// - [32-47]:  响应体密钥（SHA256(请求体密钥) 的前16字节）
    /// - [48-63]:  响应体 IV（SHA256(请求体IV) 的前16字节）
    pub fn new(vmess_option: VmessOption, stream: S) -> VmessStream<S> {
        let mut salt = [0u8; 64];
        random_iv_or_salt(&mut salt);  // 生成随机盐值
        let respv = salt[32];  // 使用随机字节作为响应版本号
        let reader_cipher: VmessSecurity;
        let writer_cipher: VmessSecurity;
        let reader: VmessAeadReader;
        let writer: VmessAeadWriter;
        // 通过 SHA256 派生响应密钥和 IV（确保请求和响应使用不同的密钥）
        let resp_body_key = sha256(&salt[16..32]);
        let resp_body_iv = sha256(&salt[0..16]);
        salt[32..48].copy_from_slice(&resp_body_key[..16]);
        salt[48..64].copy_from_slice(&resp_body_iv[..16]);
        let req_body_iv = &salt[0..16];
        let req_body_key = &salt[16..32];
        debug_log!("req body key:{:02X?}", &req_body_key[..16]);
        let resp_body_key = &salt[32..48];
        debug_log!("resp body key:{:02X?}", &resp_body_key[..16]);
        let resp_body_iv = &salt[48..];
        // 根据加密类型初始化加密器和解密器
        match vmess_option.security_num {
            AES_128_GCM_SECURITY_NUM => {
                // AES-128-GCM：直接使用 16 字节密钥
                writer_cipher = VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(req_body_key));
                writer = VmessAeadWriter::new(req_body_iv, writer_cipher);
                reader_cipher = VmessSecurity::Aes128Gcm(Aes128Gcm::new_with_slice(resp_body_key));
                reader = VmessAeadReader::new(resp_body_iv, reader_cipher);
            }
            CHACHA20POLY1305_SECURITY_NUM => {
                // ChaCha20-Poly1305：需要 32 字节密钥，通过两次 MD5 扩展
                let mut key = [0u8; 32];
                let tmp = md5!(req_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(&key[16..]);
                key[16..32].copy_from_slice(&tmp);
                writer_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                writer = VmessAeadWriter::new(req_body_iv, writer_cipher);

                let tmp = md5!(resp_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(&key[16..]);
                key[16..32].copy_from_slice(&tmp);
                reader_cipher =
                    VmessSecurity::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(&key));
                reader = VmessAeadReader::new(resp_body_iv, reader_cipher);
            }
            _ => {
                unimplemented!();  // 不支持的加密类型
            }
        }
        let mut v = VmessStream {
            stream,
            option: vmess_option,
            reader,
            writer,
            salt,
            respv,
            header_reader: Box::new(VmessHeaderReader::new(
                &resp_body_key[..16],
                &resp_body_iv[..16],
                respv,
            )),
            header_buffer: BytesMut::new(),
            header_pos: 0,
            state_1: 0,
            state_2: 0,
            header_write_res: Poll::Pending,
            header_read_res: Poll::Pending,
        };
        v.construct_header_data();
        v
    }
}

impl<S> VmessStream<S>
where
    S: AsyncReadExt + Unpin,
{
    /// 读取响应头并切换到流式读取模式
    /// 两阶段流程：
    /// 1. 等待并验证服务器响应头
    /// 2. 切换到正常的 AEAD 流式解密读取
    #[gentian]
    #[gentian_attr(state=this.state_1,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn poll_read_header(
        this: &mut VmessStream<S>,
        ctx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 阶段1：等待服务器响应头
            while !(*this.header_reader).received_resp() {
                this.header_read_res =
                    (*this.header_reader).poll_read_decrypted(ctx, &mut this.stream);
                if this.header_read_res.is_error() {
                    return std::mem::replace(&mut this.header_read_res, Poll::Pending);
                } else if this.header_read_res.is_ready() {
                    break;
                }
                co_yield(Poll::Pending);
            }
            // 转移缓冲区：将响应头读取器的剩余数据移交给流读取器
            this.reader.buffer = this.header_reader.get_buffer();
            // 阶段2：流式读取加密数据
            loop {
                co_yield(this.reader.poll_read_decrypted(ctx, &mut this.stream, dst));
            }
        }
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Self::poll_read_header(this, ctx, buf)
    }
}

impl<S> VmessStream<S>
where
    S: AsyncWrite + Unpin,
{
    /// 写入请求头并切换到流式写入模式
    /// 两阶段流程：
    /// 1. 发送 VMess 请求头（仅首次写入时执行）
    /// 2. 切换到正常的 AEAD 流式加密写入
    #[gentian]
    #[gentian_attr(state=this.state_2,ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    fn poll_write_header(
        this: &mut VmessStream<S>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            // 阶段1：写入请求头（只执行一次）
            debug_log!("vmess try write aead header");
            while this.header_pos < this.header_buffer.len() {
                this.header_write_res = Pin::new(&mut this.stream)
                    .poll_write(ctx, &this.header_buffer[this.header_pos..]);
                this.header_pos += this.header_write_res.get_poll_res();
                if this.header_write_res.is_error() {
                    debug_log!("vmess try write aead header error");
                    return std::mem::replace(&mut this.header_write_res, Poll::Pending);
                }
                if this.header_pos < this.header_buffer.len() {
                    debug_log!(
                        "vmess header pos:{},header buffer len:{}",
                        this.header_pos,
                        this.header_buffer.len()
                    );
                    co_yield(Poll::Pending);
                }
            }
            debug_log!("vmess try write aead header done");
            // 阶段2：流式写入加密数据
            loop {
                co_yield(this.writer.poll_write_encrypted(ctx, &mut this.stream, buf));
            }
        }
    }

    impl_flush_shutdown!();

    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Self::poll_write_header(this, ctx, buf)
    }
}

impl_async_useful_traits!(VmessStream);

/// UDP 读取实现
/// 注意：VMess 无法实现完全锥型 NAT，只返回握手包中的第一个地址
impl<S: AsyncWrite + AsyncRead + Send + Unpin> UdpRead for VmessStream<S> {
    /// VMess UDP 限制：无法实现完全锥型 NAT
    /// 因此始终返回握手时指定的目标地址
    fn poll_recv_from(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Address>> {
        let addr = self.option.addr.clone();
        self.priv_poll_read(cx, buf).map_ok(|_| addr)
    }
}

/// UDP 写入实现
/// 注意：VMess 无法实现完全锥型 NAT，无法更改目标地址
impl<S: AsyncWrite + AsyncRead + Send + Unpin> UdpWrite for VmessStream<S> {
    /// VMess UDP 限制：无法更改目标地址
    /// 如果启用 strict-vmess-udp 特性，会验证目标地址是否一致
    fn poll_send_to(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        #[allow(unused_variables)] target: &Address,
    ) -> Poll<io::Result<usize>> {
        #[cfg(feature = "strict-vmess-udp")]
        {
            use crate::common::new_error;
            // 严格模式：拒绝与首次握手不同的目标地址
            if self.option.addr != *target {
                return Err(new_error(
                    "Vmess can't change target udp address different from first packet. Try using a full-cone protocol instead.",
                ))
                    .into();
            }
        }
        self.priv_poll_write(cx, buf)
    }
}
