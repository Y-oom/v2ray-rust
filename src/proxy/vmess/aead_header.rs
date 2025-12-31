use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;
use std::slice::from_raw_parts_mut;

use crate::{debug_log, impl_read_utils};

use crate::common::aead_helper::AeadCipherHelper;
use crate::common::net::PollUtil;
use crate::common::{random_iv_or_salt, BlockCipherHelper, AES_128_GCM_TAG_LEN, LW_BUFFER_SIZE};
use crate::proxy::vmess::kdf::{
    vmess_kdf_1_one_shot, vmess_kdf_3_one_shot, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use aes::Aes128;
use aes_gcm::Aes128Gcm;
use futures_util::ready;
use gentian::gentian;
use std::io::ErrorKind;
use std::task::{Context, Poll};
use std::{cmp, io};
use tokio::io::{AsyncRead, ReadBuf};

/// 创建认证 ID（Auth ID）
/// 格式: AES128(时间戳(8字节) + 随机数(4字节) + CRC32(4字节))
fn create_auth_id(cmd_key: &[u8], time: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_slice(time);  // 8 字节时间戳
    let mut random_bytes = [0u8; 4];
    random_iv_or_salt(&mut random_bytes);
    buf.put_slice(&random_bytes);  // 4 字节随机数
    let zero = crc32fast::hash(&*buf);  // 计算 CRC32 校验和
    buf.put_u32(zero);  // 4 字节 CRC32
    // 使用 KDF 派生加密密钥
    let key = vmess_kdf_1_one_shot(cmd_key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY);
    let block = Aes128::new_with_slice(&key[0..16]);
    block.encrypt_with_slice(&mut buf);  // AES-128 加密整个 16 字节块
    buf
}

/// 封装 VMess AEAD 请求头
/// 格式: [Auth ID(16)] + [加密的长度字段(2+16)] + [连接 Nonce(8)] + [加密的负载数据(n+16)]
pub fn seal_vmess_aead_header(cmd_key: &[u8], data: &[u8]) -> BytesMut {
    #[cfg(not(test))]
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_be_bytes();
    #[cfg(test)]
    let time = {
        let mut b = BytesMut::new();
        b.put_u64(99);
        b
    };
    let mut generated_auth_id = create_auth_id(cmd_key, &time);
    let id_len = generated_auth_id.len();  // Auth ID 长度为 16 字节
    let mut connection_nonce = [0u8; 8];
    random_iv_or_salt(&mut connection_nonce);

    // 预留空间: (长度字段 + nonce + 数据 + 2*AEAD标签) 字节
    // 总长度 = 16(AuthID) + 18(加密长度+标签) + 8(nonce) + (数据长度+标签)
    generated_auth_id.reserve(2 + connection_nonce.len() + data.len() + 2 * AES_128_GCM_TAG_LEN);
    {
        // 第一步：加密负载长度字段
        // 使用 KDF 派生长度加密的密钥和 nonce
        let payload_header_length_aeadkey = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            &*generated_auth_id,
            &connection_nonce,
        );
        let payload_header_length_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
            &generated_auth_id,
            &connection_nonce,
        );
        let nonce = &payload_header_length_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_length_aeadkey[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..2 + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_u16(data.len() as u16);  // 写入负载长度
        // 使用 Auth ID 作为 AAD（附加认证数据）加密长度字段
        cipher.encrypt_inplace_with_slice(nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };  // 跳过标签
    }
    generated_auth_id.put_slice(&connection_nonce);  // 写入连接 Nonce
    {
        // 第二步：加密负载数据
        // 使用 KDF 派生负载加密的密钥和 nonce
        let payload_header_aead_key = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let payload_header_aead_nonce = vmess_kdf_3_one_shot(
            cmd_key,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
            &generated_auth_id[..id_len],
            &connection_nonce,
        );
        let nonce = &payload_header_aead_nonce[..12];
        let cipher = Aes128Gcm::new_with_slice(&payload_header_aead_key[0..16]);
        let mbuf = &mut generated_auth_id.chunk_mut()[..data.len() + AES_128_GCM_TAG_LEN];
        let mbuf = unsafe { from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };
        generated_auth_id.put_slice(data);  // 写入负载数据
        // 使用 Auth ID 作为 AAD 加密负载数据
        cipher.encrypt_inplace_with_slice(nonce, &generated_auth_id[..id_len], mbuf);
        unsafe { generated_auth_id.advance_mut(AES_128_GCM_TAG_LEN) };  // 跳过标签
    }
    generated_auth_id
}

/// VMess 响应头读取器，用于读取并解密服务器响应头
pub struct VmessHeaderReader {
    buffer: BytesMut,                   // 读取缓冲区
    state: u32,                         // 状态机生成器使用的状态
    resp_header_len_enc: Aes128Gcm,    // 响应头长度字段解密器
    header_len_iv: [u8; 12],           // 长度字段 IV
    resp_header_payload_enc: Aes128Gcm, // 响应头负载解密器
    header_payload_iv: [u8; 12],       // 负载 IV
    respv: u8,                         // 响应版本号
    data_length: usize,                // 数据长度
    minimal_data_to_put: usize,        // 最小待放入数据量
    read_res: Poll<io::Result<()>>,   // 读取结果
    received_resp: bool,               // 是否已接收响应
    read_zero: bool,                   // 是否读取到零字节
}

impl VmessHeaderReader {
    pub fn new(resp_body_key: &[u8], resp_body_iv: &[u8], respv: u8) -> VmessHeaderReader {
        let header_key =
            vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY);
        let header_iv = vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV);
        let payload_key =
            vmess_kdf_1_one_shot(resp_body_key, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY);
        let payload_iv =
            vmess_kdf_1_one_shot(resp_body_iv, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV);
        let resp_header_len_enc = Aes128Gcm::new_with_slice(&header_key[..16]);
        let resp_header_payload_enc = Aes128Gcm::new_with_slice(&payload_key[..16]);
        let buffer = BytesMut::with_capacity(LW_BUFFER_SIZE * 2);
        VmessHeaderReader {
            buffer,
            state: 0,
            resp_header_len_enc,
            header_len_iv: <[u8; 12]>::try_from(&header_iv[..12]).unwrap(),
            resp_header_payload_enc,
            header_payload_iv: <[u8; 12]>::try_from(&payload_iv[..12]).unwrap(),
            respv,
            data_length: 0,
            minimal_data_to_put: 0,
            read_res: Poll::Pending,
            received_resp: false,
            read_zero: false,
        }
    }

    pub fn get_buffer(&mut self) -> BytesMut {
        std::mem::take(&mut self.buffer)
    }

    impl_read_utils!();
    /// 读取并解密 VMess 响应头
    /// 响应格式: [加密的长度(2+16字节)] + [加密的负载(n+16字节)]
    #[gentian]
    #[gentian_attr(ret_val=Err(ErrorKind::UnexpectedEof.into()).into())]
    pub fn poll_read_decrypted<R>(
        &mut self,
        ctx: &mut Context<'_>,
        r: &mut R,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            // 1. 读取并解密长度字段（2字节数据 + 16字节AEAD标签）
            self.read_res = co_await(self.read_at_least(r, ctx, 18));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                debug_log!("vmess: aead header read length error");
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            let aad = [0u8; 0];  // 空的附加认证数据
            debug_log!("vmess: try aead header decrypt len");
            if !self.resp_header_len_enc.decrypt_inplace_with_slice(
                &self.header_len_iv,
                &aad,
                &mut self.buffer[..18],
            ) {
                debug_log!("vmess: aead header decrypt failed");
                let err =
                    io::Error::new(ErrorKind::InvalidData, "decrypted resp header len failed!");
                return Poll::Ready(Err(err));
            }
            self.data_length = self.buffer.get_u16() as usize;
            self.buffer.advance(16);  // 跳过 AEAD 标签
            // 2. 读取并解密负载数据
            debug_log!(
                "vmess: try aead header read data, buffer len:{}",
                self.buffer.len()
            );
            self.read_res = co_await(self.read_at_least(r, ctx, self.data_length + 16));
            if self.read_res.is_error() {
                if self.read_zero {
                    return Poll::Ready(Ok(()));
                }
                debug_log!("vmess: aead header read data error");
                return std::mem::replace(&mut self.read_res, Poll::Pending);
            }
            debug_log!("vmess: try aead header decrypt data");
            let aad = [0u8; 0];
            if !self.resp_header_payload_enc.decrypt_inplace_with_slice(
                &self.header_payload_iv,
                &aad,
                &mut self.buffer[..self.data_length + 16],
            ) {
                debug_log!("vmess: aead header data decrypt failed");
                let err = io::Error::new(
                    ErrorKind::InvalidData,
                    "decrypted resp header payload failed!",
                );
                return Poll::Ready(Err(err));
            }
            // 验证响应头格式：至少包含 16字节标签 + 4字节VMess命令
            if self.buffer.len() < 20 {
                debug_log!("vmess: buffer length error");
                let err = io::Error::new(ErrorKind::InvalidData, "unexpected buffer length!");
                return Poll::Ready(Err(err));
            }
            // 验证响应版本号
            if self.buffer[0] != self.respv {
                debug_log!("vmess: respv error");
                let err = io::Error::new(ErrorKind::InvalidData, "unexpected response header!");
                return Poll::Ready(Err(err));
            }
            // 检查动态端口（暂不支持）
            if self.buffer[2] != 0 {
                debug_log!("vmess: dynamic port error");
                let err =
                    io::Error::new(ErrorKind::InvalidData, "dynamic port is not supported now!");
                return Poll::Ready(Err(err));
            }
            self.buffer.advance(self.data_length + 16);  // 跳过已处理的数据
            self.data_length = self.buffer.len();
            self.received_resp = true;
            debug_log!("aead header read done");
            return Poll::Ready(Ok(()));
        }
    }

    pub fn received_resp(&self) -> bool {
        self.received_resp
    }
}

#[cfg(test)]
mod vmess_tests {
    use crate::common::sha256;
    use crate::proxy::decode_hex;
    use crate::proxy::vmess::aead_header::{create_auth_id, seal_vmess_aead_header};
    use bytes::{BufMut, BytesMut};

    #[test]
    fn test_create_auth_id() {
        let id = b"1234567890123456";
        let mut time = BytesMut::default();
        time.put_u64(99);
        let x = create_auth_id(id, &time); // without random bytes
        let expected = decode_hex("4ec6a618d72597e0a492ac59b5db162f").unwrap();
        assert_eq!(&expected, &x)
    }

    #[test]
    fn test_seal_vmess_aead_header() {
        let id = b"1234567890123456";
        let x = seal_vmess_aead_header(id, b"vmess");
        println!("header :{:02X}", x);
        let expected = decode_hex("4ec6a618d72597e0a492ac59b5db162faee11503a83b4b6f7785d2fd1d3dd51aabe400000000000000001eb64334545d67f30c2d8fc100bfa5132f1a583c5b").unwrap();
        println!("len:{}", x.len());
        assert_eq!(&expected, &x)
    }

    #[test]
    fn dummy() {
        let id = b"1234567890123456";
        let res = sha256(id);
        println!("sha256:{:02X?}", &res[..32]);
    }
}
