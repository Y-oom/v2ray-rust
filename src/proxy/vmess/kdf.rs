// VMess KDF (密钥派生函数) 实现
// 使用嵌套 HMAC-SHA256 来派生加密密钥
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

// HMAC 内外填充常量
const IPAD: u8 = 0x36;  // 内部填充字节
const OPAD: u8 = 0x5C;  // 外部填充字节

// KDF 盐值常量，用于不同用途的密钥派生
pub const KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY: &[u8; 22] = b"AES Auth ID Encryption";  // Auth ID 加密密钥
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8; 24] = b"AEAD Resp Header Len Key";  // 响应头长度加密密钥
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8; 23] = b"AEAD Resp Header Len IV";  // 响应头长度 IV
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8; 20] = b"AEAD Resp Header Key";  // 响应头负载密钥
pub const KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8; 19] = b"AEAD Resp Header IV";  // 响应头负载 IV
pub const KDF_SALT_CONST_VMESS_AEAD_KDF: &[u8; 14] = b"VMess AEAD KDF";  // VMess AEAD KDF 基础盐值
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8; 21] = b"VMess Header AEAD Key";  // 请求头负载密钥
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8; 23] = b"VMess Header AEAD Nonce";  // 请求头负载 Nonce
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8; 28] =
    b"VMess Header AEAD Key_Length";  // 请求头长度字段密钥
pub const KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8; 30] =
    b"VMess Header AEAD Nonce_Length";  // 请求头长度字段 Nonce
macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
            hasher_outer: $hasher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 64;
            pub const TAG_LEN: usize = 32;

            pub fn new(mut hasher: $hasher, key: &[u8]) -> Self {
                // H(K XOR opad, H(K XOR ipad, text))
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];
                let hasher_outer = hasher.clone();
                if key.len() > Self::BLOCK_LEN {
                    let mut hh = hasher.clone();
                    hh.update(key);
                    let hkey = hh.finalize();

                    ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
                } else {
                    ikey[..key.len()].copy_from_slice(&key);
                    okey[..key.len()].copy_from_slice(&key);
                }

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= IPAD;
                    okey[idx] ^= OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
                let h1 = self.hasher.finalize();

                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(&h1);

                let h2 = self.hasher_outer.finalize();

                return h2;
            }
        }
    };
}
/// VMess KDF 第一层：基于 HMAC-SHA256 的密钥派生
#[derive(Clone)]
pub struct VmessKdf1 {
    okey: [u8; Self::BLOCK_LEN],  // 外部密钥（异或 OPAD）
    hasher: HmacSha256,           // 内部哈希器
    hasher_outer: HmacSha256,     // 外部哈希器
}
impl VmessKdf1 {
    pub const BLOCK_LEN: usize = 64;  // HMAC-SHA256 块长度
    pub const TAG_LEN: usize = 32;    // SHA256 输出长度

    /// 创建新的 KDF 实例
    /// 实现标准的 HMAC 构造: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
    pub fn new(mut hasher: HmacSha256, key: &[u8]) -> Self {
        let mut ikey = [0u8; Self::BLOCK_LEN];  // 内部密钥
        let mut okey = [0u8; Self::BLOCK_LEN];  // 外部密钥
        let hasher_outer = hasher.clone();
        // 如果密钥长度超过块长度，先对密钥进行哈希
        if key.len() > Self::BLOCK_LEN {
            let mut hh = hasher.clone();
            hh.update(key);
            let hkey = hh.finalize().into_bytes();

            ikey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
            okey[..Self::TAG_LEN].copy_from_slice(&hkey[..Self::TAG_LEN]);
        } else {
            ikey[..key.len()].copy_from_slice(key);
            okey[..key.len()].copy_from_slice(key);
        }

        // 应用 HMAC 填充：内部密钥异或 IPAD，外部密钥异或 OPAD
        for idx in 0..Self::BLOCK_LEN {
            ikey[idx] ^= IPAD;
            okey[idx] ^= OPAD;
        }
        hasher.update(&ikey);  // 初始化内部哈希器
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn finalize(mut self) -> [u8; Self::TAG_LEN] {
        let h1 = self.hasher.finalize().into_bytes();

        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(&h1);

        self.hasher_outer.finalize().into_bytes().into()
    }
}

// 使用宏生成嵌套的 KDF 层
impl_hmac_with_hasher!(VmessKdf2, VmessKdf1);  // KDF 第二层：HMAC(VmessKdf1)
impl_hmac_with_hasher!(VmessKdf3, VmessKdf2);  // KDF 第三层：HMAC(VmessKdf2)

/// 获取第一层 KDF 实例
/// 使用 "VMess AEAD KDF" 作为基础盐值
#[inline]
fn get_vmess_kdf_1(key1: &[u8]) -> VmessKdf1 {
    VmessKdf1::new(
        HmacSha256::new_from_slice(KDF_SALT_CONST_VMESS_AEAD_KDF).unwrap(),
        key1,
    )
}

/// 一次性 KDF-1 派生：HMAC(key1, id)
/// 用于简单的密钥派生场景
pub fn vmess_kdf_1_one_shot(id: &[u8], key1: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_1(key1);
    h.update(id);
    h.finalize()
}

/// 获取第二层 KDF 实例
#[inline]
fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

/// 获取第三层 KDF 实例
#[inline]
fn get_vmess_kdf_3(key1: &[u8], key2: &[u8], key3: &[u8]) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

/// 一次性 KDF-3 派生：嵌套三层 HMAC
/// 用于需要多个输入参数的复杂密钥派生场景（如头部加密）
/// 等价于: HMAC(HMAC(HMAC("VMess AEAD KDF", key1), key2), key3, id)
pub fn vmess_kdf_3_one_shot(id: &[u8], key1: &[u8], key2: &[u8], key3: &[u8]) -> [u8; 32] {
    let mut h = get_vmess_kdf_3(key1, key2, key3);
    h.update(id);
    h.finalize()
}

#[cfg(test)]
mod vmess_kdf_test {

    use crate::proxy::decode_hex;
    use crate::proxy::vmess::kdf::{
        get_vmess_kdf_3, vmess_kdf_3_one_shot, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
    };

    #[test]
    fn test_vmess_kdf() {
        let id = b"1234567890123456";
        let mut h = get_vmess_kdf_3(
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        );
        h.update(id);
        let expected =
            decode_hex("2745934f3b987d077b4082ec0f76060f33d7f4d89dd172f434c275bf91b1360b").unwrap();
        let value = h.finalize();
        assert_eq!(&expected, &value);
        let value = vmess_kdf_3_one_shot(
            id,
            KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        );
        assert_eq!(&expected, &value);
    }
}
