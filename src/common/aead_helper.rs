use aes::cipher::generic_array::typenum::Unsigned;
use aes_gcm::{aead::Tag, AeadInPlace, KeyInit};
pub use aes_gcm::{Aes128Gcm, Aes256Gcm};
pub use chacha20poly1305::ChaCha20Poly1305;

/// AEAD 加密辅助 trait
///
/// 提供统一的 AEAD 加密/解密接口，支持在原地（in-place）进行加密和解密操作。
/// 所有实现者都必须支持 AEAD 算法（认证加密）和分离式标签处理。
pub trait AeadCipherHelper: AeadInPlace {
    /// 使用二进制密钥创建加密器
    ///
    /// # 参数
    /// - key: 加密密钥（长度取决于算法类型，如 AES-128 需要 16 字节，AES-256 需要 32 字节）
    fn new_with_slice(key: &[u8]) -> Self;

    /// 在原地加密数据，标签放在缓冲区末尾
    ///
    /// # 参数
    /// - nonce: 随机数/计数器（长度通常为 12 字节）
    /// - aad: 附加认证数据（可以为空）
    /// - buffer: 缓冲区格式：[明文数据][AEAD标签区域]
    ///   执行后：[密文数据][AEAD标签]
    ///
    /// # 工作流程
    /// 1. 计算标签在缓冲区中的位置（末尾）
    /// 2. 将缓冲区分为消息部分和标签部分
    /// 3. 执行分离式加密，生成密文和认证标签
    /// 4. 将标签复制到缓冲区末尾
    fn encrypt_inplace_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        // 执行分离式加密，获取独立的认证标签（不包含在密文中）
        let x = self
            .encrypt_in_place_detached(nonce.into(), aad, msg)
            .expect("encryption failure!");
        // 将认证标签复制到缓冲区末尾
        tag.copy_from_slice(&x);
    }

    /// 在原地解密数据，标签从缓冲区末尾读取
    ///
    /// # 参数
    /// - nonce: 随机数/计数器（需要与加密时使用的相同）
    /// - aad: 附加认证数据（需要与加密时使用的相同）
    /// - buffer: 缓冲区格式：[密文数据][AEAD标签]
    ///   执行后：[明文数据][标签区域（已被覆盖为明文）]
    ///
    /// # 返回值
    /// - true: 解密和认证成功
    /// - false: 认证失败（可能是密文被篡改或使用了错误的密钥/nonce）
    ///
    /// # 工作流程
    /// 1. 从缓冲区末尾分离认证标签
    /// 2. 执行分离式解密和验证
    /// 3. 返回验证结果
    fn decrypt_inplace_with_slice(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> bool {
        let tag_pos = buffer.len() - Self::TagSize::to_usize();
        let (msg, tag) = buffer.split_at_mut(tag_pos);
        // 执行分离式解密和认证标签验证
        // 如果认证失败（标签不匹配），返回 false
        self.decrypt_in_place_detached(nonce.into(), aad, msg, Tag::<Self>::from_slice(tag))
            .is_ok()
    }
}

/// AES-128-GCM 实现（128 位密钥 = 16 字节）
impl AeadCipherHelper for Aes128Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        Aes128Gcm::new(key.into())
    }
}

/// AES-256-GCM 实现（256 位密钥 = 32 字节）
impl AeadCipherHelper for Aes256Gcm {
    fn new_with_slice(key: &[u8]) -> Self {
        Aes256Gcm::new(key.into())
    }
}

/// ChaCha20-Poly1305 实现（256 位密钥 = 32 字节）
impl AeadCipherHelper for ChaCha20Poly1305 {
    fn new_with_slice(key: &[u8]) -> Self {
        ChaCha20Poly1305::new(key.into())
    }
}
