use std::io;
use std::mem::MaybeUninit;

use crate::common::LW_BUFFER_SIZE;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures_util::ready;
use log::info;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::net::copy_with_capacity::copy_with_capacity_and_atomic_counter;
use crate::debug_log;
pub use copy_with_capacity::copy_with_capacity_and_counter;

pub mod copy_with_capacity;  // 自定义容量的数据转发实现

/// 从异步读取流读取数据到 BytesMut 缓冲区
///
/// 这是 Tokio 提供的 poll_read_buf（已弃用）的替代实现。
/// 直接读取到 BytesMut 的未初始化区域，避免额外内存复制。
///
/// # 参数
/// - io: 异步读取流
/// - cx: 异步任务上下文
/// - buf: 目标 BytesMut 缓冲区
///
/// # 返回值
/// - Poll::Ready(Ok(n)) - 读取了 n 字节（可能为 0 表示 EOF）
/// - Poll::Ready(Err(...)) - 读取出错
/// - Poll::Pending - 暂无可读数据
///
/// # 工作原理
/// 1. 检查缓冲区是否有剩余空间
/// 2. 从未初始化区域直接读取
/// 3. 更新缓冲区的填充指针
/// 4. 返回读取字节数
pub fn poll_read_buf<T>(
    io: &mut T,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
) -> Poll<io::Result<usize>>
where
    T: AsyncRead + Unpin,
{
    // 如果缓冲区没有剩余空间，返回 0
    if !buf.has_remaining_mut() {
        return Poll::Ready(Ok(0));
    }
    let n = {
        // 获取缓冲区的未初始化区域
        let dst = buf.chunk_mut();
        // 强制转换为 MaybeUninit 数组（启用未初始化写入）
        let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
        // 创建 ReadBuf 来追踪已初始化的数据
        let mut buf = ReadBuf::uninit(dst);
        let ptr = buf.filled().as_ptr();
        // 轮询读取（使用 ready! 宏如果 Pending 则返回）
        ready!(Pin::new(io).poll_read(cx, &mut buf)?);

        // 安全检查：确保指针未改变（缓冲区地址保持一致）
        assert_eq!(ptr, buf.filled().as_ptr());
        buf.filled().len()
    };

    // 安全性保证：因为 ReadBuf::filled 的不变式，这个数字一定是已初始化的字节数
    unsafe {
        // 向前移动 BytesMut 的填充指针
        buf.advance_mut(n);
    }
    Poll::Ready(Ok(n))
}

/// Poll 异步操作结果的实用工具 trait
///
/// 提供便利方法来检查和处理 Poll<io::Result<T>> 类型，
/// 避免重复的模式匹配代码
pub trait PollUtil {
    /// 关联类型：Poll 的成功值类型
    type T;

    /// 丢弃 Poll 的成功值，只保留 Poll 和错误信息
    /// 用于不关心具体返回值只在意操作是否完成的场景
    fn drop_poll_result(self) -> Poll<io::Result<()>>;

    /// 检查操作是否仍待处理或已出错
    /// 返回 true 表示操作未能立即完成（需要后续重试）
    fn is_pending_or_error(&self) -> bool;

    /// 检查操作是否已出错
    /// 返回 true 表示遇到了 I/O 错误
    fn is_error(&self) -> bool;

    /// 从 Poll 中提取成功值
    /// 如果是 Pending 或 Err，返回类型的默认值
    fn get_poll_res(&self) -> Self::T;
}

/// 为所有实现了 Default 和 Copy 的类型 T 提供通用实现
impl<T: Default + Copy> PollUtil for Poll<io::Result<T>> {
    type T = T;

    /// 将 Poll<io::Result<T>> 转换为 Poll<io::Result<()>>
    ///
    /// 保留 Poll 状态和错误信息，但丢弃成功值
    fn drop_poll_result(self) -> Poll<io::Result<()>> {
        match self {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// 检查是否是 Pending 或 Err 状态
    ///
    /// 当操作还未完成或遇到错误时返回 true，
    /// 只有操作成功完成时才返回 false
    fn is_pending_or_error(&self) -> bool {
        match self {
            Poll::Ready(Err(_)) => true,
            Poll::Ready(Ok(_)) => false,
            Poll::Pending => true,
        }
    }

    /// 仅检查是否是 Err 状态
    ///
    /// 返回 true 表示有 I/O 错误，
    /// 其他状态（Ready(Ok) 或 Pending）返回 false
    fn is_error(&self) -> bool {
        match self {
            Poll::Ready(Err(_)) => true,
            Poll::Ready(Ok(_)) => false,
            Poll::Pending => false,
        }
    }

    /// 安全地提取 Poll 的成功值
    ///
    /// - 如果是 Poll::Ready(Ok(t))，返回 t
    /// - 如果是 Poll::Ready(Err(_)) 或 Poll::Pending，返回 T::default()
    ///
    /// 这对于数值结果特别有用（返回 0），但对于复杂类型应谨慎使用
    fn get_poll_res(&self) -> Self::T {
        match self {
            Poll::Ready(Err(_)) => T::default(),
            Poll::Ready(Ok(t)) => *t,
            Poll::Pending => T::default(),
        }
    }
}
/// 在两个异步 I/O 流之间进行双向数据转发
///
/// 该函数建立一个双向数据中继，在入站和出站流之间进行并发数据转发。
/// 它使用 tokio::select! 宏同时处理两个方向的转发，确保高效的双工通信。
///
/// # 工作流程
/// 1. 将入站流分离为读和写两个半部分
/// 2. 将出站流分离为读和写两个半部分
/// 3. 使用 tokio::select! 并发运行两个转发任务：
///    - 出站读 → 入站写（下行数据）
///    - 入站读 → 出站写（上行数据）
/// 4. 任意一个转发完成（EOF）时，整个转发结束
/// 5. 记录统计信息
///
/// # 参数
/// - inbound_stream: 入站流（来自客户端）
/// - outbound_stream: 出站流（连接到目标服务器）
/// - relay_buffer_size: 缓冲区倍数（实际大小为 LW_BUFFER_SIZE * relay_buffer_size）
///
/// # 返回值
/// - Ok(()) - 转发正常完成
/// - Err(...) - 转发过程中遇到 I/O 错误
///
/// # 性质
/// - 异步非阻塞：使用 await 实现，适合异步运行时
/// - 双向并发：两个方向的转发并发执行，提高吞吐量
/// - 字节统计：记录下行和上行的传输字节数并记录日志
pub async fn relay<T1, T2>(
    inbound_stream: T1,
    outbound_stream: T2,
    relay_buffer_size: usize,
) -> io::Result<()>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    // 将两个全双工流各分离成读和写两个半部分
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);

    // 初始化两个方向的字节计数器
    let mut down = 0u64;  // 下行：出站 → 入站
    let mut up = 0u64;    // 上行：入站 → 出站

    // 并发运行两个转发任务，任意一个完成即认为转发结束
    tokio::select! {
            // 下行转发：从出站读取数据，写入到入站
            _ = copy_with_capacity_and_counter(&mut outbound_r,&mut inbound_w,&mut down,LW_BUFFER_SIZE*relay_buffer_size)=>{
            }
            // 上行转发：从入站读取数据，写入到出站
            _ = copy_with_capacity_and_counter(&mut inbound_r, &mut outbound_w,&mut up,LW_BUFFER_SIZE*relay_buffer_size)=>{
            }
    }

    // 记录转发统计信息
    info!("downloaded bytes:{}, uploaded bytes:{}", down, up);
    Ok(())
}
/// 使用原子计数器进行双向数据转发（支持实时统计）
///
/// 这是 relay() 函数的增强版本，使用原子变量而非普通引用来管理字节计数。
/// 使用原子操作允许在转发进行中并发读取传输统计信息，无需等待转发完成。
///
/// # 工作流程
/// 1. 将入站流分离为读和写两个半部分
/// 2. 将出站流分离为读和写两个半部分
/// 3. 使用 tokio::select! 并发运行两个转发任务：
///    - 出站读 → 入站写（下行数据），更新 outbound_down/inbound_down 计数
///    - 入站读 → 出站写（上行数据），更新 inbound_up/outbound_up 计数
/// 4. 任意一个转发完成（EOF）时，整个转发结束
/// 5. 使用 Relaxed 内存顺序读取并记录统计信息
///
/// # 参数
/// - inbound_stream: 入站流（来自客户端）
/// - outbound_stream: 出站流（连接到目标服务器）
/// - inbound_up: 原子计数器：入站上行字节数（客户端 → 服务器）
/// - inbound_down: 原子计数器：入站下行字节数（服务器 → 客户端）
/// - outbound_up: 原子计数器：出站上行字节数（客户端 → 服务器）
/// - outbound_down: 原子计数器：出站下行字节数（服务器 → 客户端）
/// - relay_buffer_size: 缓冲区倍数（实际大小为 LW_BUFFER_SIZE * relay_buffer_size）
///
/// # 返回值
/// - Ok(()) - 转发正常完成
/// - Err(...) - 转发过程中遇到 I/O 错误
///
/// # 性质
/// - 异步非阻塞：使用 await 实现，适合异步运行时
/// - 双向并发：两个方向的转发并发执行
/// - 实时统计：使用原子操作允许外部并发读取转移统计
/// - 四向字节计数：分别统计入站/出站的上下行数据，提供更细粒度的监控
///
/// # 使用场景
/// 当需要在转发进行中监测各个方向的数据量时（如实时带宽显示），使用此函数而非 relay()
pub async fn relay_with_atomic_counter<T1, T2>(
    inbound_stream: T1,
    outbound_stream: T2,
    inbound_up: &AtomicU64,
    inbound_down: &AtomicU64,
    outbound_up: &AtomicU64,
    outbound_down: &AtomicU64,
    relay_buffer_size: usize,
) -> io::Result<()>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    // 将两个全双工流各分离成读和写两个半部分
    let (mut outbound_r, mut outbound_w) = tokio::io::split(outbound_stream);
    let (mut inbound_r, mut inbound_w) = tokio::io::split(inbound_stream);

    // 并发运行两个转发任务，任意一个完成即认为转发结束
    tokio::select! {
            // 下行转发：从出站读取数据，写入到入站
            // 更新下行相关的原子计数器
            _ = copy_with_capacity_and_atomic_counter(&mut outbound_r,
            &mut inbound_w,
            outbound_down,
            inbound_down,
            LW_BUFFER_SIZE*relay_buffer_size)=>{
            }
            // 上行转发：从入站读取数据，写入到出站
            // 更新上行相关的原子计数器
            _ = copy_with_capacity_and_atomic_counter(&mut inbound_r,
            &mut outbound_w,
            inbound_up,
            outbound_up,
            LW_BUFFER_SIZE*relay_buffer_size)=>{
            }
    }

    // 使用 Relaxed 内存顺序读取统计信息并记录
    // Relaxed 足够且更高效，因为这里只是信息记录，不需要严格的内存同步
    debug_log!(
        "api atomic counter downloaded bytes:{}, uploaded bytes:{}",
        inbound_down.load(std::sync::atomic::Ordering::Relaxed),
        inbound_up.load(std::sync::atomic::Ordering::Relaxed)
    );
    Ok(())
}
