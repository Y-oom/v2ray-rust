use futures_util::ready;
use std::future::Future;
use std::io;

use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 具有自定义缓冲区容量的数据转发结构
///
/// 用于在两个异步 I/O 对象之间转发数据，支持自定义缓冲区大小。
/// 该结构体实现 Future trait，在轮询时驱动读写操作。
///
/// # 工作流程
/// 1. 从 reader 中读取数据到内部缓冲区
/// 2. 将缓冲区中的数据写入到 writer
/// 3. 更新传输字节计数
/// 4. 当 reader 返回 0 字节时認為读取完成（EOF）
/// 5. 写入完成后刷新 writer 并返回总传输字节数
#[derive(Debug)]
struct CopyWithCapacity<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,           // 读取来源
    read_done: bool,             // 是否读取完毕（到达 EOF）
    writer: &'a mut W,           // 写入目标
    pos: usize,                  // 缓冲区中当前读取位置
    cap: usize,                  // 缓冲区中有效数据长度
    amt: &'a mut u64,            // 传输总字节数计数
    buf: Box<[u8]>,              // 内部缓冲区
}

/// 使用指定缓冲区容量和计数器实现异步数据转发
///
/// 从 reader 读取数据，写入到 writer，并更新计数器以统计传输字节数。
///
/// # 参数
/// - reader: 读取来源（异步读取流）
/// - writer: 写入目标（异步写入流）
/// - counter: 指向 u64 的可变引用，用来累加传输的字节数
/// - buf_capacity: 内部缓冲区大小（字节数）
///
/// # 返回值
/// - Ok(total_bytes) - 成功转发的总字节数
/// - Err(...) - 如果读写过程中出错
///
/// # 特点
/// - 直接修改 counter 指向的值，累加每次写入的字节数
/// - 适合需要精确追踪传输总量的场景
pub async fn copy_with_capacity_and_counter<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    counter: &'a mut u64,
    buf_capacity: usize,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    CopyWithCapacity {
        reader,
        read_done: false,
        writer,
        amt: counter,
        pos: 0,
        cap: 0,
        buf: vec![0; buf_capacity].into_boxed_slice(),
    }
    .await
}

impl<R, W> Future for CopyWithCapacity<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    /// 实现转发循环的状态机轮询
    ///
    /// 主循环包含三个阶段：
    /// 1. 缓冲区是否为空且未读完：从 reader 读取新数据
    /// 2. 缓冲区中有数据：向 writer 写出数据
    /// 3. 所有数据已写入且读取完成：刷新 writer 并结束
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        loop {
            // 阶段 1: 缓冲区为空且未读到 EOF，需要从 reader 读取新数据
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                // 轮询 reader 的 poll_read，返回 Pending 则跳出循环
                ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                if n == 0 {
                    // 读到 0 字节说明到达 EOF
                    self.read_done = true;
                } else {
                    // 成功读取了 n 字节，重置位置指针
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // 阶段 2: 缓冲区中有数据，逐块写入到 writer
            while self.pos < self.cap {
                let me = &mut *self;
                // 尝试写入 buf[pos..cap] 的数据
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    // writer 返回 0 字节写入，说明发生了底层错误 (WriteZero)
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    // 成功写入了 i 字节，更新位置和计数
                    self.pos += i;
                    *self.amt += i as u64;
                }
            }

            // 阶段 3: 所有缓冲数据已写入，且已读到 EOF，现在刷新并结束
            if self.pos == self.cap && self.read_done {
                let me = &mut *self;
                // 刷新 writer 以确保所有数据都被发送
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                // 返回传输的总字节数
                return Poll::Ready(Ok(*self.amt));
            }
        }
    }
}

/// 使用原子计数器的数据转发结构（支持并发读取计数）
///
/// 与 CopyWithCapacity 类似，但使用原子变量而非可变引用来管理计数，
/// 这允许在转发进行中并发读取入站和出站的传输字节数。
///
/// # 字段说明
/// - amt_in: 入站（读取）字节数计数（原子）
/// - amt_out: 出站（写入）字节数计数（原子）
#[derive(Debug)]
struct CopyWithCapacityAtomic<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,              // 读取来源
    read_done: bool,                // 是否读取完毕
    writer: &'a mut W,              // 写入目标
    pos: usize,                     // 缓冲区当前读取位置
    cap: usize,                     // 缓冲区有效数据长度
    amt_in: &'a AtomicU64,          // 入站字节数（原子）
    amt_out: &'a AtomicU64,         // 出站字节数（原子）
    buf: Box<[u8]>,                 // 内部缓冲区
}

/// 使用原子计数器实现异步数据转发
///
/// 类似于 copy_with_capacity_and_counter，但使用原子变量来统计传输字节数。
/// 这样外部代码可以在转发进行中并发读取当前的传输统计。
///
/// # 参数
/// - reader: 读取来源
/// - writer: 写入目标
/// - counter_in: 入站字节数计数（原子）
/// - counter_out: 出站字节数计数（原子）
/// - buf_capacity: 缓冲区大小
///
/// # 返回值
/// - Ok(()) - 转发成功
/// - Err(...) - 读写过程中出错
///
/// # 特点
/// - 使用 fetch_add 原子操作更新计数，支持并发读取
/// - 适合需要实时变更统计的场景（如带宽监测）
pub async fn copy_with_capacity_and_atomic_counter<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    counter_in: &'a AtomicU64,
    counter_out: &'a AtomicU64,
    buf_capacity: usize,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    CopyWithCapacityAtomic {
        reader,
        read_done: false,
        writer,
        amt_in: counter_in,
        amt_out: counter_out,
        pos: 0,
        cap: 0,
        buf: vec![0; buf_capacity].into_boxed_slice(),
    }
    .await
}

impl<R, W> Future for CopyWithCapacityAtomic<'_, R, W>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<()>;

    /// 原子计数版本的转发循环轮询
    ///
    /// 与 CopyWithCapacity::poll 几乎相同，主要区别是：
    /// - 使用 amt_in.fetch_add() 和 amt_out.fetch_add()（原子操作）
    /// - 而非直接修改引用指向的值
    /// 这样支持外部并发读取计数，不需要等待转发完成
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            // 阶段 1: 缓冲区为空且未读完，读取新数据
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);
                ready!(Pin::new(&mut *me.reader).poll_read(cx, &mut buf))?;
                let n = buf.filled().len();
                // 使用原子操作将入站字节数增加 n
                // Relaxed 内存顺序足够，因为这里不需要严格同步
                self.amt_in.fetch_add(n as u64, Relaxed);
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                }
            }

            // 阶段 2: 缓冲区中有数据，写入到 writer
            while self.pos < self.cap {
                let me = &mut *self;
                let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, &me.buf[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    // 使用原子操作将出站字节数增加 i
                    self.amt_out.fetch_add(i as u64, Relaxed);
                }
            }

            // 阶段 3: 数据转发完成，刷新 writer
            if self.pos == self.cap && self.read_done {
                let me = &mut *self;
                ready!(Pin::new(&mut *me.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }
        }
    }
}
