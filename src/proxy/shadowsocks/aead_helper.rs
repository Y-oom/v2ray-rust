use crate::common::aead_helper::{AeadCipherHelper, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use crate::proxy::shadowsocks::ss_hkdf_sha1;

/// ShadowSocks 支持的加密算法类型
#[derive(Clone, Copy, PartialEq)]
pub enum CipherKind {
    None,                  // 无加密（plaintext）
    Aes128Gcm,            // AES-128-GCM：128位密钥，12字节 nonce
    Aes256Gcm,            // AES-256-GCM：256位密钥，12字节 nonce
    ChaCha20Poly1305,     // ChaCha20-Poly1305：256位密钥，12字节 nonce
}

impl CipherKind {
    /// 根据派生密钥创建具体的密码算法实例
    fn new(&self, sub_key: &[u8]) -> CipherInner {
        match self {
            CipherKind::None => {
                unreachable!()
            }
            CipherKind::Aes128Gcm => CipherInner::Aes128Gcm(Aes128Gcm::new_with_slice(sub_key)),
            CipherKind::Aes256Gcm => CipherInner::Aes256Gcm(Aes256Gcm::new_with_slice(sub_key)),
            CipherKind::ChaCha20Poly1305 => {
                CipherInner::ChaCha20Poly1305(ChaCha20Poly1305::new_with_slice(sub_key))
            }
        }
    }

    /// 获取盐值（IV）长度，ShadowSocks 中盐值长度等于密钥长度
    #[inline]
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    /// 获取单次加密的 nonce（随机数）长度
    /// AEAD 算法的 nonce 长度固定为 12 字节（96位）
    #[inline]
    pub fn nonce_len(&self) -> usize {
        match self {
            CipherKind::None => 0,
            CipherKind::Aes128Gcm => 12,      // 12 字节
            CipherKind::Aes256Gcm => 12,      // 12 字节
            CipherKind::ChaCha20Poly1305 => 12, // 12 字节
        }
    }

    /// 获取密钥长度
    pub fn key_len(&self) -> usize {
        match self {
            CipherKind::None => 0,
            CipherKind::Aes128Gcm => 16,      // AES-128：16 字节
            CipherKind::Aes256Gcm => 32,      // AES-256：32 字节
            CipherKind::ChaCha20Poly1305 => 32, // ChaCha20：32 字节
        }
    }

    /// 获取 AEAD 认证标签长度（所有算法都是 16 字节）
    pub fn tag_len(&self) -> usize {
        16  // 128 位认证标签
    }
}

/// AEAD 密码算法的内部实现
enum CipherInner {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CipherInner {
    /// 就地加密缓冲区
    /// 输入: plaintext_in_ciphertext_out 是明文 + AEAD 标签空间
    /// 输出: 密文 + AEAD 标签（覆盖原缓冲区）
    pub fn encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        match self {
            CipherInner::Aes128Gcm(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
            CipherInner::Aes256Gcm(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
            CipherInner::ChaCha20Poly1305(ref c) => {
                c.encrypt_inplace_with_slice(nonce, b"", plaintext_in_ciphertext_out);
            }
        }
    }

    /// 就地解密缓冲区
    /// 输入: ciphertext_in_plaintext_out 是密文 + AEAD 标签
    /// 输出: 明文（在验证 AEAD 标签成功后覆盖原缓冲区）
    /// 返回: true 表示验证和解密成功，false 表示 AEAD 标签验证失败
    pub fn decrypt_slice(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match self {
            CipherInner::Aes128Gcm(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
            CipherInner::Aes256Gcm(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
            CipherInner::ChaCha20Poly1305(ref c) => {
                c.decrypt_inplace_with_slice(nonce, b"", ciphertext_in_plaintext_out)
            }
        }
    }
}

/// ShadowSocks AEAD 密码机制的包装器
/// 自动管理 nonce 的递增，实现计数器模式
pub struct AeadCipher {
    cipher: CipherInner,      // 底层 AEAD 密码算法
    nonce: [u8; 24],         // nonce 缓冲区（最多 24 字节，实际使用 12 字节）
    nlen: usize,              // 实际使用的 nonce 长度
}

impl AeadCipher {
    /// 创建新的 AEAD 密码机制
    ///
    /// ShadowSocks AEAD 使用 HKDF-SHA1 派生子密钥：
    /// sub_key = HKDF-SHA1(salt, master_key, "ss-subkey", 64字节)
    /// 使用派生的子密钥初始化密码算法
    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> AeadCipher {
        // 使用盐值和主密钥派生子密钥（HKDF-SHA1）
        let sub_key = ss_hkdf_sha1(iv_or_salt, key);
        // 使用派生的子密钥初始化具体的密码算法
        let cipher = kind.new(&sub_key[..key.len()]);
        AeadCipher {
            cipher,
            nonce: [0u8; 24],  // nonce 初始化为 0
            nlen: kind.nonce_len(),
        }
    }

    /// 加密数据（自动递增 nonce）
    pub fn encrypt(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = &self.nonce[..self.nlen];
        self.cipher
            .encrypt_slice(nonce, plaintext_in_ciphertext_out);
        // 使用后递增 nonce 以防止重放攻击
        self.increase_nonce();
    }

    /// 解密数据（自动递增 nonce）
    /// 返回 true 表示解密成功且 AEAD 标签验证通过
    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self
            .cipher
            .decrypt_slice(nonce, ciphertext_in_plaintext_out);
        // 使用后递增 nonce（无论成功或失败）
        self.increase_nonce();
        ret
    }

    /// 小端字节序递增 nonce（计数器模式）
    /// nonce[0] 是最低有效字节，支持进位传播
    #[inline]
    fn increase_nonce(&mut self) {
        // 对第一个字节加 1，并处理进位
        let mut c = self.nonce[0] as u16 + 1;
        self.nonce[0] = c as u8;
        c >>= 8;  // 进位（0 或 1）

        // 从第二个字节开始处理进位
        let mut n = 1;
        while n < self.nlen {
            c += self.nonce[n] as u16;
            self.nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }
}
