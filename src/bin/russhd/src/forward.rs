//! Bounded buffering and transport for TCP forwarding.

use std::collections::VecDeque;
use std::io;

use russh::{Channel, ChannelId, ChannelMsg, ReceiveCredit};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

mod open;
mod tasks;
pub use open::{direct_tcpip, memory_pressure, validate_target};
pub use tasks::{Reservation, Tasks};

const BLOCK_SIZE: usize = 32 * 1024;

/// Run inside a connection-owned `Tasks` reservation: its cancellation covers
/// every await here, including cleanup while the session's send queue is full.
pub async fn relay<S, R>(
    channel: Channel<S>,
    socket: R,
    credit: ReceiveCredit,
    window: usize,
    mut pressure: impl FnMut() -> bool,
) -> io::Result<()>
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
    R: AsyncRead + AsyncWrite + Unpin,
{
    credit.defer_close();
    let (mut incoming, outgoing) = channel.split();
    let mut writer = outgoing.make_writer();
    let (mut from_socket, mut to_socket) = tokio::io::split(socket);
    // Preserve this future and its window reservation through every select.
    let mut sending = Some(Box::pin(async move {
        tokio::io::copy(&mut from_socket, &mut writer).await?;
        writer.shutdown().await
    }));
    let mut queue = Queue::new(window);
    let mut eof = false;
    let mut closed = false;
    let mut sent_eof = false;
    let mut socket_shutdown = false;
    let result = async {
        loop {
            if (closed && queue.is_empty()) || (sent_eof && socket_shutdown) {
                break Ok(());
            }
            tokio::select! {
                // Keep receiving at the byte limit and after EOF, so control
                // events and russh's tolerated window overrun cannot park reads.
                message = incoming.wait(), if !closed => match message {
                    Some(ChannelMsg::Data { data }) if !eof => {
                        queue.append(&data, &mut pressure)?;
                    }
                    Some(ChannelMsg::Eof) => eof = true,
                    Some(ChannelMsg::Close) => {
                        closed = true;
                        sending = None;
                    }
                    Some(ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. }) => {
                        break Err(io::Error::new(io::ErrorKind::InvalidData,
                            "unexpected forwarding channel data"));
                    }
                    None => break Err(io::ErrorKind::ConnectionAborted.into()),
                    _ => {}
                },
                result = async {
                    match sending.as_mut() {
                        Some(work) => work.as_mut().await,
                        None => std::future::pending().await,
                    }
                } => {
                    result?;
                    sending = None;
                    sent_eof = true;
                },
                written = async {
                    match queue.front() {
                        Some(data) => to_socket.write(data).await,
                        None => to_socket.shutdown().await.map(|()| 0),
                    }
                }, if !queue.is_empty() || (eof && !socket_shutdown) => {
                    let written = written?;
                    if queue.is_empty() {
                        socket_shutdown = true;
                    } else {
                        if written == 0 {
                            break Err(io::ErrorKind::WriteZero.into());
                        }
                        queue.consume(written);
                        credit.consumed(written as u32);
                    }
                },
            }
        }
    }
    .await;
    // Drain the socket before acknowledging a peer close. Keep the task alive
    // through both close messages so connection shutdown cannot discard data.
    drop(sending);
    drop(to_socket);
    drop(incoming);
    drop(queue);
    let closing = outgoing.close().await.map_err(io::Error::other);
    result.and(closing)?;
    credit.wait_closed().await.map_err(io::Error::other)
}

/// Coalesces SSH packets without retaining an allocation for each packet.
struct Queue {
    blocks: VecDeque<Vec<u8>>,
    offset: usize,
    len: usize,
    limit: usize,
}

impl Queue {
    fn new(limit: usize) -> Self {
        Self {
            blocks: VecDeque::new(),
            offset: 0,
            len: 0,
            limit,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn front(&self) -> Option<&[u8]> {
        self.blocks.front().map(|block| &block[self.offset..])
    }

    /// Check pressure before each new block, while using existing tail space.
    /// On error, the relay ends and discards any partially appended data.
    fn append(&mut self, mut data: &[u8], mut pressure: impl FnMut() -> bool) -> io::Result<()> {
        if data.len() > self.limit - self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "forward exceeded its receive window",
            ));
        }
        while !data.is_empty() {
            if self
                .blocks
                .back()
                .is_none_or(|tail| tail.len() == BLOCK_SIZE)
            {
                if pressure() {
                    return Err(io::ErrorKind::OutOfMemory.into());
                }
                // Partial blocks at both ends need one extra slot. Reserve the
                // bounded bookkeeping once, then allocate payload lazily.
                let max_blocks = self.limit.div_ceil(BLOCK_SIZE) + 1;
                if self.blocks.capacity() < max_blocks {
                    self.blocks
                        .try_reserve_exact(max_blocks - self.blocks.len())
                        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
                }
                let mut block = Vec::new();
                block
                    .try_reserve_exact(BLOCK_SIZE)
                    .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
                self.blocks.push_back(block);
            }
            let tail = self.blocks.back_mut().unwrap();
            let count = data.len().min(BLOCK_SIZE - tail.len());
            tail.extend_from_slice(&data[..count]);
            self.len += count;
            data = &data[count..];
        }
        Ok(())
    }

    /// Retire bytes written from `front()`, releasing each drained block.
    fn consume(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        assert!(count <= self.front().unwrap().len());
        self.len -= count;
        self.offset += count;
        if self.offset == self.blocks.front().unwrap().len() {
            self.blocks.pop_front();
            self.offset = 0;
        }
    }
}

#[cfg(all(test, unix))]
mod relay_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiny_packets_coalesce_and_preserve_byte_order() {
        let mut queue = Queue::new(2 * BLOCK_SIZE);
        for byte in 0..40_000 {
            queue.append(&[byte as u8], || false).unwrap();
        }
        assert_eq!(queue.len, 40_000);
        assert_eq!(queue.blocks.len(), 2);
        let first = queue.front().unwrap();
        assert_eq!(first.len(), BLOCK_SIZE);
        assert!(first.iter().enumerate().all(|(i, &byte)| byte == i as u8));
        queue.consume(BLOCK_SIZE);
        let last = queue.front().unwrap();
        assert_eq!(last.len(), 40_000 - BLOCK_SIZE);
        assert!(
            last.iter()
                .enumerate()
                .all(|(i, &byte)| byte == (i + BLOCK_SIZE) as u8)
        );
        queue.consume(40_000 - BLOCK_SIZE);
        assert!(queue.is_empty());
        assert!(queue.blocks.is_empty());
        assert_eq!(queue.front(), None);
    }

    #[test]
    fn partial_ends_fit_the_window_with_one_extra_block() {
        let mut queue = Queue::new(2 * BLOCK_SIZE);
        for _ in 0..100 {
            queue.append(&vec![1; 2 * BLOCK_SIZE], || false).unwrap();
            queue.consume(1);
            queue.append(&[2], || false).unwrap();
            assert_eq!(queue.len, 2 * BLOCK_SIZE);
            assert_eq!(queue.blocks.len(), 3);
            assert_eq!(
                queue.append(&[3], || false).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(queue.len, 2 * BLOCK_SIZE);
            queue.consume(BLOCK_SIZE - 1);
            queue.consume(BLOCK_SIZE);
            assert_eq!(queue.front(), Some(&[2][..]));
            queue.consume(1);
            assert!(queue.blocks.is_empty());
        }
    }

    #[test]
    fn pressure_sheds_growth_but_allows_allocated_tail_space() {
        let mut queue = Queue::new(2 * BLOCK_SIZE);
        assert_eq!(
            queue.append(&[1], || true).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(queue.blocks.capacity(), 0);
        queue.append(&[1], || false).unwrap();
        queue.append(&vec![2; BLOCK_SIZE - 1], || true).unwrap();
        assert_eq!(
            queue.append(&[3], || true).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(queue.len, BLOCK_SIZE);
        queue.consume(BLOCK_SIZE);
        assert!(queue.blocks.is_empty());

        let mut checks = 0;
        let error = queue
            .append(&vec![4; 2 * BLOCK_SIZE], || {
                checks += 1;
                checks == 2
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(checks, 2);
        assert_eq!(queue.len, BLOCK_SIZE);
        assert_eq!(queue.blocks.len(), 1);
    }

    #[test]
    fn empty_data_does_not_allocate_or_signal_eof() {
        let mut queue = Queue::new(0);
        queue
            .append(&[], || panic!("empty data allocated"))
            .unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.blocks.capacity(), 0);
        assert_eq!(
            queue.append(&[1], || false).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(queue.blocks.is_empty());
    }
}
