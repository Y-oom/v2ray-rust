use crate::debug_log;
use aes::{cipher::BlockDecrypt, cipher::BlockEncrypt, cipher::KeyInit, Aes128};
use generic_array::GenericArray;
use sha2::Digest;
use sha2::{Sha224, Sha256};
use std::io;

pub mod aead_helper;  // AEAD 加密辅助工具
pub mod fnv1a;        // FNV-1a 哈希实现
pub mod macro_def;    // 各类实用宏定义
pub mod net;          // 网络 I/O 相关的实用函数

// ============== 常数定义 ==============
/// 低水位缓冲区大小：1 KB
/// 用于需要小缓冲区的 I/O 操作
pub const LW_BUFFER_SIZE: usize = 1024;
/// 高水位缓冲区大小：64 KB
/// 用于批量数据转发的大缓冲区
pub const HW_BUFFER_SIZE: usize = 65_536;
/// AES-128-GCM 认证标签长度：16 字节
pub const AES_128_GCM_TAG_LEN: usize = 16;

/// 创建统一格式的 I/O 错误
///
/// # 参数
/// - message: 错误信息（会被转换为字符串）
///
/// # 返回值
/// 返回 io::Error，其类型为 Other，消息格式为 "Error: {message}"
pub fn new_error<T: ToString>(message: T) -> io::Error {
    debug_log!("new error message:{}", message.to_string());
    return io::Error::new(
        io::ErrorKind::Other,
        format!("Error: {}", message.to_string()),
    );
}

/// 分组密码辅助 trait
///
/// 提供统一的创建和加解密接口，支持通过字节切片进行操作
pub trait BlockCipherHelper {
    /// 使用二进制密钥创建加密器
    fn new_with_slice(key: &[u8]) -> Self;
    /// 在原地加密一个分组
    fn encrypt_with_slice(&self, block: &mut [u8]);
    /// 在原地解密一个分组
    fn decrypt_with_slice(&self, block: &mut [u8]);
}

/// AES-128 分组密码实现
///
/// AES-128 使用 128 位（16 字节）密钥和 128 位（16 字节）分组大小
impl BlockCipherHelper for Aes128 {
    /// 从密钥字节创建 AES-128 加密器
    #[inline]
    fn new_with_slice(key: &[u8]) -> Self {
        let key = GenericArray::from_slice(key);
        Aes128::new(key)
    }

    /// 在原地加密一个 16 字节的分组
    #[inline]
    fn encrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.encrypt_block(key)
    }

    /// 在原地解密一个 16 字节的分组
    #[inline]
    fn decrypt_with_slice(&self, block: &mut [u8]) {
        let key = GenericArray::from_mut_slice(block);
        self.decrypt_block(key)
    }
}

/// 计算数据的 SHA-256 哈希
///
/// # 参数
/// - b: 待哈希的数据字节
///
/// # 返回值
/// 32 字节的 SHA-256 哈希值
pub fn sha256(b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&b);
    hasher.finalize().into()
}

/// 计算数据的 SHA-224 哈希
///
/// # 参数
/// - b: 待哈希的数据字节
///
/// # 返回值
/// 28 字节的 SHA-224 哈希值
#[inline]
pub fn sha224(b: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(&b);
    hasher.finalize().into()
}

/// 生成随机 IV（初始化向量）或 Salt（盐值）
///
/// 在非测试编译中，生成真正的随机字节。
/// 特别注意：会循环重试直到生成非全零的值（确保不生成全 0 盐值）
///
/// # 参数
/// - iv_or_salt: 用来存储随机字节的缓冲区
#[cfg(not(test))]
pub fn random_iv_or_salt(iv_or_salt: &mut [u8]) {
    // 如果缓冲区为空，无需生成
    if iv_or_salt.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    // 循环生成直到获得非全零的值
    // （避免所有字节都是 0 的边缘情况）
    loop {
        rand::Rng::fill(&mut rng, iv_or_salt);
        let is_zeros = iv_or_salt.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}

/// 测试环境中的虚拟实现（不生成随机值）
#[cfg(test)]
pub fn random_iv_or_salt(_iv_or_salt: &mut [u8]) {}

/// OpenSSL 风格的密钥派生函数（EVP_BytesToKey）
///
/// 这是 OpenSSL 的 EVP_BytesToKey 的简化实现，用于从密码派生密钥。
/// 算法使用 MD5 哈希和迭代方式。
///
/// # 工作流程
/// 1. 首次迭代：hash(password) → 16 字节摘要
/// 2. 第二次迭代：hash(摘要1 + password) → 16 字节摘要
/// 3. 后续迭代：hash(摘要(n-1) + password) → 16 字节摘要
/// 4. 将摘要内容填充到密钥，直到填满指定长度
///
/// # 参数
/// - password: 原始密码字节
/// - key: 输出密钥缓冲区（会被填充）
///
/// # 示例
/// ```ignore
/// let mut key = [0u8; 32];
/// openssl_bytes_to_key(b"mypassword", &mut key);
/// // key 现在包含 32 字节的派生密钥
/// ```
pub fn openssl_bytes_to_key(password: &[u8], key: &mut [u8]) {
    use md5::Md5;
    let key_len = key.len();

    let mut last_digest: Option<[u8; 16]> = None;

    let mut offset = 0usize;
    // 循环生成足够的摘要来填充密钥
    while offset < key_len {
        let mut m = Md5::new();
        // 如果不是第一次迭代，先加入前一个摘要
        if let Some(digest) = last_digest {
            m.update(&digest);
        }
        // 加入密码
        m.update(password);
        // 计算摘要
        let digest = m.finalize();
        // 将摘要的一部分复制到密钥（最后一次可能不足 16 字节）
        let amt = std::cmp::min(key_len - offset, 16);
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);
        // 下一次迭代
        offset += 16;
        last_digest = Some(digest.into());
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{openssl_bytes_to_key, BlockCipherHelper};
    use crate::md5;
    use aes::Aes128;

    #[test]
    fn bytes_to_key() {
        let mut key1 = [0u8; 32];
        openssl_bytes_to_key("123456".as_bytes(), key1.as_mut());
        let res=b"\xe1\n\xdc9I\xbaY\xab\xbeV\xe0W\xf2\x0f\x88>e\xb4\xad'\x0b;\x98\t\x8d%j\xb3/[\x8f\xba";
        assert_eq!(res, &key1);
    }

    #[test]
    fn test_md5() {
        // just check code compiling
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(b"hello world");
        let res1: [u8; 16] = hasher.finalize().into();
        let res2 = md5!(b"hello world");
        assert_eq!(res1, res2);
    }

    #[test]
    fn test_aes_128() {
        // just check code compiling
        let k = [0u8; 16];
        let c = Aes128::new_with_slice(&k);
        let mut x = [0u8; 16];
        c.encrypt_with_slice(&mut x[..]);
        println!("{:02X?}", x);
    }
}
