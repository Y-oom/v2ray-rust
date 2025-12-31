use bloomfilter::Bloom;
use spin::Mutex as SpinMutex;

use crate::common::random_iv_or_salt;
use std::sync::Arc;

/// PingPong 布隆过滤器
/// 实现自动轮换的重放攻击检测机制
///
/// 原理：使用两个独立的布隆过滤器交替使用（环形缓冲区）
/// - 每个过滤器容量为各自容量的一半
/// - 当当前过滤器满后，自动切换到另一个过滤器并清空
/// - 这样可以定期清除旧的 nonce 记录，防止布隆过滤器无限增长
/// （该实现借鉴自 shadowsocks-libev 的 ppbloom）
struct PingPongBloom {
    blooms: [Bloom<[u8]>; 2],  // 两个交替的布隆过滤器
    bloom_count: [usize; 2],   // 每个过滤器中的当前元素计数
    item_count: usize,         // 每个过滤器的容量
    current: usize,            // 当前使用的过滤器索引（0 或 1）
}

impl PingPongBloom {
    /// 服务器端布隆过滤器容量（借用 shadowsocks-libev 的默认值）
    /// 适合高并发服务器，防止内存溢出
    const BF_NUM_ENTRIES_FOR_SERVER: usize = 1_000_000;  // 100 万条

    /// 客户端布隆过滤器容量（借用 shadowsocks-libev 的默认值）
    /// 适合本地客户端，资源占用较少
    const BF_NUM_ENTRIES_FOR_CLIENT: usize = 10_000;     // 1 万条

    /// 服务器端布隆过滤器的假正率（误报率）
    /// 对应约 18 位哈希函数，极低 FP 率以提高安全性
    const BF_ERROR_RATE_FOR_SERVER: f64 = 1e-6;          // 百万分之一

    /// 客户端布隆过滤器的假正率
    /// 极高的安全要求以防止伪造
    const BF_ERROR_RATE_FOR_CLIENT: f64 = 1e-15;         // 千万亿分之一

    /// 创建新的 PingPong 布隆过滤器
    fn new(is_local: bool) -> PingPongBloom {
        // 根据是否为本地客户端选择容量和误报率
        let (mut item_count, fp_p) = if is_local {
            (
                Self::BF_NUM_ENTRIES_FOR_CLIENT,
                Self::BF_ERROR_RATE_FOR_CLIENT,
            )
        } else {
            (
                Self::BF_NUM_ENTRIES_FOR_SERVER,
                Self::BF_ERROR_RATE_FOR_SERVER,
            )
        };

        // 两个过滤器各占总容量的一半
        item_count /= 2;

        PingPongBloom {
            blooms: [
                Bloom::new_for_fp_rate(item_count, fp_p),
                Bloom::new_for_fp_rate(item_count, fp_p),
            ],
            bloom_count: [0, 0],
            item_count,
            current: 0,
        }
    }

    /// 检查数据是否存在，不存在则添加
    ///
    /// # 返回值
    /// - true: 数据已存在于某个过滤器中（检测到重复 nonce，可能是重放攻击）
    /// - false: 数据是新的，已自动添加到当前过滤器
    ///
    /// # 行为
    /// 1. 检查两个过滤器中是否存在该数据
    /// 2. 如果存在，立即返回 true（检测到重复）
    /// 3. 如果不存在且当前过滤器未满，添加到当前过滤器
    /// 4. 如果不存在但当前过滤器已满，轮换到另一个过滤器并清空，然后添加
    fn check_and_set(&mut self, buf: &[u8]) -> bool {
        // 检查两个过滤器中是否存在该数据
        for bloom in &self.blooms {
            if bloom.check(buf) {
                return true;  // 找到重复项
            }
        }

        // 检查当前过滤器是否已满
        if self.bloom_count[self.current] >= self.item_count {
            // 当前过滤器已满，轮换到另一个过滤器
            self.current = (self.current + 1) % 2;

            // 清空新的当前过滤器并重置计数
            self.bloom_count[self.current] = 0;
            self.blooms[self.current].clear();
        }

        // 向当前过滤器添加数据
        // 注意：不能使用 check_and_set，因为我们需要先检查两个过滤器再插入
        self.blooms[self.current].set(buf);
        self.bloom_count[self.current] += 1;

        false  // 数据是新的，已添加
    }
}

/// ShadowSocks 全局上下文配置
/// 用于重放攻击检测，在整个服务器运行期间共享
pub struct BloomContext {
    /// PingPong 布隆过滤器
    /// 用于检测重复的 IV/Nonce，防止重放攻击
    /// 详见：https://github.com/shadowsocks/shadowsocks-org/issues/44
    nonce_ppbloom: SpinMutex<PingPongBloom>,
}

/// 全局共享的 BloomContext（原子引用计数指针）
pub type SharedBloomContext = Arc<BloomContext>;

impl BloomContext {
    /// 创建新的 BloomContext 实例
    ///
    /// # 参数
    /// - is_local: true 创建客户端用的小容量过滤器，false 创建服务器用的大容量过滤器
    pub fn new(is_local: bool) -> BloomContext {
        BloomContext {
            nonce_ppbloom: SpinMutex::new(PingPongBloom::new(is_local)),
        }
    }

    /// 检查 nonce 是否存在或是否重复
    ///
    /// # 返回值
    /// - true: nonce 已存在（检测到重放攻击风险）
    /// - false: nonce 是新的且已记录到过滤器中
    ///
    /// # 特殊情况
    /// - 如果 nonce 为空（plaintext 无加密模式），总是返回 false
    pub fn check_nonce_and_set(&self, nonce: &[u8]) -> bool {
        // 无加密模式（plaintext cipher）没有 nonce
        // 在这种情况下，始终认为没有重复
        if nonce.is_empty() {
            return false;
        }

        let mut ppbloom = self.nonce_ppbloom.lock();
        ppbloom.check_and_set(nonce)
    }

    /// 生成随机的 nonce（初始化向量或盐值）
    ///
    /// # 参数
    /// - nonce: 输出缓冲区（大小决定了 nonce 长度）
    /// - unique: 如果为 true，生成唯一的 nonce（与已记录的不重复）；
    ///          如果为 false，允许重复（仅生成随机值）
    ///
    /// # 行为
    /// - 如果 nonce 缓冲区为空，不生成任何内容
    /// - 如果 unique=true，会重试直到生成唯一的 nonce
    /// - 如果 unique=false，生成一次后立即返回
    pub fn generate_nonce(&self, nonce: &mut [u8], unique: bool) {
        if nonce.is_empty() {
            return;
        }

        loop {
            // 生成随机数填充缓冲区
            random_iv_or_salt(nonce);

            // 如果需要唯一性，检查是否重复
            // 如果检测到重复，继续生成新的 nonce
            if unique && self.check_nonce_and_set(nonce) {
                continue;
            }

            break;  // 成功生成或无需唯一性检查
        }
    }
}
