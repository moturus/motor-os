use alloc::collections::VecDeque;

use moto_ipc::io_channel;
use moto_rt::mutex::Mutex;

use super::channel::NetChannel;

/// IPC pages containing stream bytes not yet claimed by the channel driver.
///
/// The protocol owner supplies marker and wire messages. This helper owns the
/// pages and keeps adding a page plus publishing its marker under one lock, so
/// the driver cannot claim a partially-published entry.
pub(super) struct PendingStreamTx {
    pages: Mutex<VecDeque<PendingTxPage>>,
}

struct PendingTxPage {
    page: io_channel::IoPage,
    filled: usize,
}

impl PendingStreamTx {
    pub(super) fn new() -> Self {
        Self {
            pages: Mutex::new(VecDeque::new()),
        }
    }

    pub(super) fn clear(&self) {
        self.pages.lock().clear();
    }

    pub(super) fn has_room(&self) -> bool {
        self.pages
            .lock()
            .back()
            .is_some_and(|back| back.filled < io_channel::PAGE_SIZE)
    }

    /// Append into the unclaimed back page. Its already-published marker will
    /// bind the final length when the channel driver claims the page.
    pub(super) fn append(&self, bufs: &[&[u8]], offset: usize) -> usize {
        let mut pages = self.pages.lock();
        let Some(back) = pages.back_mut() else {
            return 0;
        };
        if back.filled == io_channel::PAGE_SIZE {
            return 0;
        }
        let copied = copy_at(bufs, offset, &mut back.page.bytes_mut()[back.filled..]);
        back.filled += copied;
        copied
    }

    /// Add a new page and publish its marker atomically with respect to the
    /// channel driver's claim. A full staging queue retracts and frees it.
    pub(super) fn try_push(
        &self,
        page: io_channel::IoPage,
        bufs: &[&[u8]],
        offset: usize,
        channel: &NetChannel,
        marker: io_channel::Msg,
    ) -> Result<usize, ()> {
        let filled = copy_at(bufs, offset, page.bytes_mut());
        debug_assert!(filled > 0);

        let mut pages = self.pages.lock();
        pages.push_back(PendingTxPage { page, filled });
        if channel.post_msg(marker).is_ok() {
            return Ok(filled);
        }

        // The lock stayed held, so this entry is still the back. Dropping it
        // returns the page to the channel.
        let _ = pages.pop_back();
        Err(())
    }

    /// Transfer up to `page_ids.len()` leading pages to a wire message. The
    /// shared-page wire format requires every page except the last to be full,
    /// so a partial page ends this claim.
    pub(super) fn claim(&self, page_ids: &mut [u16]) -> (usize, usize) {
        let mut pages = self.pages.lock();
        let mut count = 0;
        let mut total = 0;
        while count < page_ids.len() {
            let Some(entry) = pages.pop_front() else {
                break;
            };
            let filled = entry.filled;
            total += filled;
            page_ids[count] = io_channel::IoPage::into_u16(entry.page);
            count += 1;
            if filled < io_channel::PAGE_SIZE {
                break;
            }
        }
        (count, total)
    }
}

fn copy_at(src: &[&[u8]], mut offset: usize, dst: &mut [u8]) -> usize {
    let mut written = 0;
    for buf in src {
        if offset >= buf.len() {
            offset -= buf.len();
            continue;
        }
        let src_bytes = &buf[offset..];
        offset = 0;

        let to_write = src_bytes.len().min(dst.len() - written);
        dst[written..(written + to_write)].copy_from_slice(&src_bytes[..to_write]);
        written += to_write;
        if written == dst.len() {
            break;
        }
    }
    written
}
