use std::hash::Hasher;

/// FNV-1a 哈希算法实现（32 位版本）
///
/// FNV 是一种非密码学哈希函数，因其简单和快速而广泛使用。
/// 本实现为 FNV-1a 变体，它比原始 FNV-1 有更好的分布特性。
///
/// 常数说明：
/// - 初始哈希值（FNV offset basis）: 0x811c9dc5
/// - 质数（FNV prime）: 0x01000193
pub struct Fnv1aHasher(u32);

impl Default for Fnv1aHasher {
    /// 创建并初始化一个新的 FNV-1a 哈希器
    ///
    /// 初始值为 FNV offset basis (0x811c9dc5)，这是 FNV-1a 的标准初始值
    #[inline]
    fn default() -> Fnv1aHasher {
        Fnv1aHasher(0x811c9dc5u32)
    }
}

impl Hasher for Fnv1aHasher {
    /// 获取最终哈希值（转换为 64 位）
    ///
    /// 虽然内部使用 32 位，但接口返回 64 位以符合 Rust 标准库约定
    /// 实际有效数据仅为低 32 位
    #[inline]
    fn finish(&self) -> u64 {
        self.0 as u64
    }

    /// FNV-1a 哈希算法的核心循环
    ///
    /// FNV-1a 算法步骤（对每个字节）：
    /// 1. hash = hash XOR byte（异或操作）
    /// 2. hash = hash * FNV_prime（乘以质数）
    ///
    /// # 参数
    /// - bytes: 待哈希的数据字节
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let Fnv1aHasher(mut hash) = *self;

        for byte in bytes.iter() {
            // 第一步：与当前字节进行异或
            hash ^= *byte as u32;
            // 第二步：乘以 FNV 质数（使用 wrapping_mul 处理溢出）
            // 0x01000193 = 16777619 是 32 位 FNV 质数
            hash = hash.wrapping_mul(0x01000193);
        }

        *self = Fnv1aHasher(hash);
    }
}
