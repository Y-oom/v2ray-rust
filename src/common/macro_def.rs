/// MD5 哈希计算宏
///
/// 接受一个或多个字节切片，计算它们的 MD5 哈希值
///
/// # 示例
/// ```ignore
/// let hash = md5!(b"hello", b"world");  // 计算 "helloworld" 的 MD5
/// ```
#[macro_export]
macro_rules! md5 {
    ($($x:expr),*) => {{
        use md5::{Md5, Digest};
        let mut digest = Md5::new();
        // 依次更新所有输入
        $(digest.update($x);)*
        // 完成哈希计算并转换为 16 字节数组
        let res:[u8;16]=digest.finalize().into();
        res
    }}
}

/// 为自定义写入流类型自动实现 AsyncWrite trait
///
/// 这个宏生成 AsyncWrite trait 的完整实现，
/// 通过委托到结构体内部的三个私有方法：
/// - priv_poll_write: 处理写入操作
/// - priv_poll_flush: 处理刷新缓冲
/// - priv_poll_shutdown: 处理关闭连接
///
/// # 用法
/// ```ignore
/// impl_async_write!(MyStream);  // 自动为 MyStream<S> 实现 AsyncWrite
/// ```
#[macro_export]
macro_rules! impl_async_write {
    ($name:tt) => {
        impl<S> AsyncWrite for $name<S>
        where
            S: AsyncWrite + Unpin,
        {
            /// 委托给内部的 priv_poll_write 方法
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, Error>> {
                self.priv_poll_write(cx, buf)
            }

            /// 委托给内部的 priv_poll_flush 方法
            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
                self.priv_poll_flush(cx)
            }

            /// 委托给内部的 priv_poll_shutdown 方法
            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Result<(), Error>> {
                self.priv_poll_shutdown(cx)
            }
        }
    };
}
/// 为自定义读取流类型自动实现 AsyncRead trait
///
/// 这个宏生成 AsyncRead trait 的完整实现，
/// 通过委托到结构体内部的私有方法：
/// - priv_poll_read: 处理读取操作
///
/// # 用法
/// ```ignore
/// impl_async_read!(MyStream);  // 自动为 MyStream<S> 实现 AsyncRead
/// ```
#[macro_export]
macro_rules! impl_async_read {
    ($name:tt) => {
        impl<S> AsyncRead for $name<S>
        where
            S: AsyncRead + Unpin,
        {
            /// 委托给内部的 priv_poll_read 方法
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.priv_poll_read(cx, buf)
            }
        }
    };
}

// #[macro_export]
// macro_rules! impl_split_stream {
//     ($name:tt) => {
//         impl<S> $name<S>
//         where
//             S: AsyncRead + AsyncWrite + Unpin,
//         {
//             pub fn split(self) -> (ReadHalf<$name<S>>, WriteHalf<$name<S>>) {
//                 tokio::io::split(self)
//             }
//         }
//     };
// }

/// 为自定义流类型同时实现 AsyncRead 和 AsyncWrite traits
///
/// 这个便利宏一次性为结构体实现两个异步 I/O traits。
/// 相当于同时调用：
/// - impl_async_read!(MyStream)
/// - impl_async_write!(MyStream)
///
/// # 用法
/// ```ignore
/// impl_async_useful_traits!(MyStream);  // 自动为 MyStream<S> 同时实现 AsyncRead 和 AsyncWrite
/// ```
#[macro_export]
macro_rules! impl_async_useful_traits {
    ($name:tt) => {
        //impl_split_stream!($name);
        // 实现 AsyncRead trait
        impl_async_read!($name);
        // 实现 AsyncWrite trait
        impl_async_write!($name);
    };
}

/// 为包含 stream 字段的结构体生成 flush/shutdown 方法
///
/// 这个宏假设结构体有一个名为 `stream` 的成员字段，
/// 并将 flush 和 shutdown 调用直接委托给它。
///
/// # 用法
/// ```ignore
/// struct MyStream<S> {
///     stream: S,
///     // 其他字段...
/// }
///
/// impl<S> MyStream<S> {
///     impl_flush_shutdown!();
/// }
/// ```
#[macro_export]
macro_rules! impl_flush_shutdown {
    () => {
        /// 刷新底层流的缓冲区
        /// 直接委托到内部 stream 的 poll_flush
        fn priv_poll_flush(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncWrite::poll_flush(Pin::new(&mut self.stream), ctx)
        }

        /// 关闭底层流的写入端
        /// 直接委托到内部 stream 的 poll_shutdown
        fn priv_poll_shutdown(
            mut self: Pin<&mut Self>,
            ctx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), ctx)
        }
    };
}

/// 为使用缓冲读取的结构体生成读取实用方法
///
/// 该宏生成以下三个方法：
/// - read_reserve: 确保缓冲区有足够的容量
/// - read_at_least: 从流中读取至少指定字节数据
/// - calc_data_to_put: 计算应该放入输出缓冲区的数据量
///
/// # 结构体成员要求
/// 使用此宏的结构体必须有以下成员：
/// - `buffer: BytesMut` - 内部读取缓冲区
/// - `minimal_data_to_put: usize` - 最小可放入字节数
/// - `data_length: usize` - 待读取的总数据量
/// - `read_zero: bool` - 是否读到 EOF 标记
///
/// # 用法
/// ```ignore
/// struct MyReader {
///     buffer: BytesMut,
///     minimal_data_to_put: usize,
///     data_length: usize,
///     read_zero: bool,
///     // 其他字段...
/// }
///
/// impl MyReader {
///     impl_read_utils!();
/// }
/// ```
#[macro_export]
macro_rules! impl_read_utils {
    () => {
        /// 为缓冲区预分配所需容量
        ///
        /// 如果当前容量不足，会进行扩展以避免频繁分配
        #[allow(dead_code)]
        #[inline]
        fn read_reserve(&mut self, required_data_size: usize) {
            if self.buffer.capacity() < required_data_size {
                self.buffer.reserve(required_data_size);
            }
        }

        /// 从异步读取流中读取至少指定字节数的数据
        ///
        /// # 参数
        /// - r: 异步读取流
        /// - ctx: 异步任务上下文
        /// - length: 所需的最小字节数
        ///
        /// # 返回值
        /// - Poll::Ready(Ok(())) - 成功读取至少所需字节
        /// - Poll::Ready(Err(...)) - 在读到足够数据前 EOF（返回 UnexpectedEof）
        /// - Poll::Pending - 暂无可读数据，等待下次唤醒
        ///
        /// # 副作用
        /// 当读到 EOF 时，设置 read_zero = true
        #[inline]
        fn read_at_least<R>(
            &mut self,
            r: &mut R,
            ctx: &mut Context<'_>,
            length: usize,
        ) -> Poll<io::Result<()>>
        where
            R: AsyncRead + Unpin,
        {
            use $crate::common::net::poll_read_buf;
            // 循环读取直到缓冲区中有足够的数据
            while self.buffer.len() < length {
                let n = ready!(poll_read_buf(r, ctx, &mut self.buffer))?;
                // 如果读到 0 字节，说明到达了 EOF
                if n == 0 {
                    self.read_zero = true;
                    // 返回 UnexpectedEof 错误（在读到足够数据前就遇到了 EOF）
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                }
            }
            Poll::Ready(Ok(()))
        }

        /// 计算应该复制到输出缓冲区的数据量
        ///
        /// 根据可用数据量（self.data_length）和输出缓冲区剩余空间，
        /// 计算本次应该复制的字节数
        ///
        /// # 返回值
        /// 本次应该复制的字节数（保存在 self.minimal_data_to_put）
        #[allow(dead_code)]
        #[inline]
        fn calc_data_to_put(&mut self, dst: &mut ReadBuf<'_>) -> usize {
            // 取 remaining（待读的数据）和 output buffer 剩余空间的较小值
            self.minimal_data_to_put = cmp::min(self.data_length, dst.remaining());
            self.minimal_data_to_put
        }
    };
}

/// 为 UDP 读取流的包装类型生成解引用实现
///
/// 该宏生成 `poll_recv_from` 方法，将调用委托给被包装的内部类型。
/// 通常用于为智能指针或 newtype 实现 UdpRead trait。
///
/// # 用法
/// ```ignore
/// struct MyUdpStream<S>(S);
///
/// impl<S: UdpRead> UdpRead for MyUdpStream<S> {
///     deref_udp_read!();
/// }
/// ```
#[macro_export]
macro_rules! deref_udp_read {
    () => {
        /// 从 UDP 流接收数据，委托给内部被包装的类型
        fn poll_recv_from(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<Address>> {
            // 解引用获取内部类型，然后委托 poll_recv_from 调用
            Pin::new(&mut **self).poll_recv_from(cx, buf)
        }
    };
}

/// 为 UDP 写入流的包装类型生成解引用实现
///
/// 该宏生成 `poll_send_to` 方法，将调用委托给被包装的内部类型。
/// 通常用于为智能指针或 newtype 实现 UdpWrite trait。
///
/// # 用法
/// ```ignore
/// struct MyUdpStream<S>(S);
///
/// impl<S: UdpWrite> UdpWrite for MyUdpStream<S> {
///     deref_udp_write!();
/// }
/// ```
#[macro_export]
macro_rules! deref_udp_write {
    () => {
        /// 向 UDP 流发送数据，委托给内部被包装的类型
        fn poll_send_to(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: &Address,
        ) -> Poll<io::Result<usize>> {
            // 解引用获取内部类型，然后委托 poll_send_to 调用
            Pin::new(&mut **self).poll_send_to(cx, buf, target)
        }
    };
}
