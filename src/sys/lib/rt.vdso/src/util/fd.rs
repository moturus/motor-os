//! File descriptor helper.
//!
//! Although Motor OS does not use file descriptors internally,
//! a lot of Rust crates assume FDs are available, so to make
//! our lives easier we expose File and Networking APIs in terms
//! of FDs.

use super::spin::Mutex;
use crate::stdio::Stdio;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use moto_rt::RtFd;

pub enum Fd {
    File(crate::rt_fs::File),
    Stdio(Stdio),
    Pipe(Mutex<moto_ipc::sync_pipe::Pipe>),
    ReadDir(crate::rt_fs::ReadDir),
    TcpStream(Arc<crate::rt_net::TcpStream>),
    TcpListener(Arc<crate::rt_net::TcpListener>),
}

type Entry<T> = Mutex<Option<Arc<T>>>;

fn new_entry<T>() -> Entry<T> {
    Mutex::new(None)
}

/// Exposes a way to map RtFd to Arc<T>. The implementation
/// can probably be made faster using unsafe stuff, but that
/// would be premature optimization at the moment.
pub struct Descriptors<T> {
    descriptors: Mutex<Vec<Entry<T>>>,
    freelist: Mutex<Vec<RtFd>>,
}

impl<T> Descriptors<T> {
    pub const fn new() -> Self {
        Self {
            descriptors: Mutex::new(Vec::new()),
            freelist: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, val: Arc<T>) -> RtFd {
        let fd = self.get_free_fd();
        let descriptors = self.descriptors.lock();
        let entry: &mut Option<Arc<T>> = &mut descriptors.get(fd as usize).unwrap().lock();
        *entry = Some(val);
        fd
    }

    pub fn get(&self, fd: RtFd) -> Option<Arc<T>> {
        let descriptors = self.descriptors.lock();
        if let Some(entry) = descriptors.get(fd as usize) {
            entry.lock().clone()
        } else {
            None
        }
    }

    pub fn pop(&self, fd: RtFd) -> Option<Arc<T>> {
        let val = {
            let descriptors = self.descriptors.lock();
            if let Some(entry) = descriptors.get(fd as usize) {
                entry.lock().take()
            } else {
                return None;
            }
        };
        if val.is_some() {
            self.freelist.lock().push(fd);
        }
        val
    }

    fn get_free_fd(&self) -> RtFd {
        if let Some(fd) = self.freelist.lock().pop() {
            return fd;
        }

        let res = {
            let mut descriptors = self.descriptors.lock();
            descriptors.push(new_entry());
            descriptors.len() - 1
        };
        assert!(res < (RtFd::MAX as usize));
        res as RtFd
    }
}

pub static DESCRIPTORS: crate::util::fd::Descriptors<Fd> = crate::util::fd::Descriptors::new();
