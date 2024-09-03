//! The channel interface.

use core::fmt;
use core::iter::FusedIterator;
use core::panic::{RefUnwindSafe, UnwindSafe};
use core::time::Duration;
use moto_rt::time::Instant;

use crate::context::Context;
use crate::counter;
use crate::err::{
    RecvError, RecvTimeoutError, SendError, SendTimeoutError, TryRecvError, TrySendError,
};
use crate::flavors;
use crate::select::{Operation, SelectHandle, Token};

pub fn bounded<T>(cap: usize) -> (Sender<T>, Receiver<T>) {
    assert!(cap > 0);
    let (s, r) = counter::new(flavors::array::Channel::with_capacity(cap));
    let s = Sender {
        flavor: SenderFlavor::Array(s),
    };
    let r = Receiver {
        flavor: ReceiverFlavor::Array(r),
    };
    (s, r)
}

pub struct Sender<T> {
    flavor: SenderFlavor<T>,
}

enum SenderFlavor<T> {
    Array(counter::Sender<flavors::array::Channel<T>>),
}

unsafe impl<T: Send> Send for Sender<T> {}
unsafe impl<T: Send> Sync for Sender<T> {}

impl<T> UnwindSafe for Sender<T> {}
impl<T> RefUnwindSafe for Sender<T> {}

impl<T> Sender<T> {
    pub fn try_send(&self, msg: T) -> Result<(), TrySendError<T>> {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.try_send(msg),
        }
    }

    pub fn send(&self, msg: T) -> Result<(), SendError<T>> {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.send(msg, None),
        }
        .map_err(|err| match err {
            SendTimeoutError::Disconnected(msg) => SendError(msg),
            SendTimeoutError::Timeout(_) => unreachable!(),
        })
    }

    pub fn send_timeout(&self, msg: T, timeout: Duration) -> Result<(), SendTimeoutError<T>> {
        match Instant::now().checked_add_duration(&timeout) {
            Some(deadline) => self.send_deadline(msg, deadline),
            None => self.send(msg).map_err(SendTimeoutError::from),
        }
    }

    pub fn send_deadline(&self, msg: T, deadline: Instant) -> Result<(), SendTimeoutError<T>> {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.send(msg, Some(deadline)),
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.is_empty(),
        }
    }

    pub fn is_full(&self) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.is_full(),
        }
    }

    pub fn len(&self) -> usize {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.len(),
        }
    }

    pub fn capacity(&self) -> Option<usize> {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.capacity(),
        }
    }

    pub fn same_channel(&self, other: &Self) -> bool {
        match (&self.flavor, &other.flavor) {
            (SenderFlavor::Array(ref a), SenderFlavor::Array(ref b)) => a == b,
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        unsafe {
            match &self.flavor {
                SenderFlavor::Array(chan) => chan.release(|c| c.disconnect()),
            }
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let flavor = match &self.flavor {
            SenderFlavor::Array(chan) => SenderFlavor::Array(chan.acquire()),
        };

        Self { flavor }
    }
}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Sender { .. }")
    }
}

pub struct Receiver<T> {
    flavor: ReceiverFlavor<T>,
}

enum ReceiverFlavor<T> {
    Array(counter::Receiver<flavors::array::Channel<T>>),
}

unsafe impl<T: Send> Send for Receiver<T> {}
unsafe impl<T: Send> Sync for Receiver<T> {}

impl<T> UnwindSafe for Receiver<T> {}
impl<T> RefUnwindSafe for Receiver<T> {}

impl<T> Receiver<T> {
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.try_recv(),
        }
    }

    pub fn recv(&self) -> Result<T, RecvError> {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.recv(None),
        }
        .map_err(|_| RecvError)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        match Instant::now().checked_add_duration(&timeout) {
            Some(deadline) => self.recv_deadline(deadline),
            None => self.recv().map_err(RecvTimeoutError::from),
        }
    }

    pub fn recv_deadline(&self, deadline: Instant) -> Result<T, RecvTimeoutError> {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.recv(Some(deadline)),
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.is_empty(),
        }
    }

    pub fn is_full(&self) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.is_full(),
        }
    }

    pub fn len(&self) -> usize {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.len(),
        }
    }

    pub fn capacity(&self) -> Option<usize> {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.capacity(),
        }
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter { receiver: self }
    }

    pub fn try_iter(&self) -> TryIter<'_, T> {
        TryIter { receiver: self }
    }

    pub fn same_channel(&self, other: &Self) -> bool {
        match (&self.flavor, &other.flavor) {
            (ReceiverFlavor::Array(a), ReceiverFlavor::Array(b)) => a == b,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        unsafe {
            match &self.flavor {
                ReceiverFlavor::Array(chan) => chan.release(|c| c.disconnect()),
            }
        }
    }
}

impl<T> Clone for Receiver<T> {
    fn clone(&self) -> Self {
        let flavor = match &self.flavor {
            ReceiverFlavor::Array(chan) => ReceiverFlavor::Array(chan.acquire()),
        };

        Self { flavor }
    }
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Receiver { .. }")
    }
}

impl<'a, T> IntoIterator for &'a Receiver<T> {
    type Item = T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> IntoIterator for Receiver<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { receiver: self }
    }
}

pub struct Iter<'a, T> {
    receiver: &'a Receiver<T>,
}

impl<T> FusedIterator for Iter<'_, T> {}

impl<T> Iterator for Iter<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

impl<T> fmt::Debug for Iter<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("Iter { .. }")
    }
}

pub struct TryIter<'a, T> {
    receiver: &'a Receiver<T>,
}

impl<T> Iterator for TryIter<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.try_recv().ok()
    }
}

impl<T> fmt::Debug for TryIter<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("TryIter { .. }")
    }
}

pub struct IntoIter<T> {
    receiver: Receiver<T>,
}

impl<T> FusedIterator for IntoIter<T> {}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

impl<T> fmt::Debug for IntoIter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("IntoIter { .. }")
    }
}

impl<T> SelectHandle for Sender<T> {
    fn try_select(&self, token: &mut Token) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().try_select(token),
        }
    }

    fn deadline(&self) -> Option<Instant> {
        None
    }

    fn register(&self, oper: Operation, cx: &Context) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().register(oper, cx),
        }
    }

    fn unregister(&self, oper: Operation) {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().unregister(oper),
        }
    }

    fn accept(&self, token: &mut Token, cx: &Context) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().accept(token, cx),
        }
    }

    fn is_ready(&self) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().is_ready(),
        }
    }

    fn watch(&self, oper: Operation, cx: &Context) -> bool {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().watch(oper, cx),
        }
    }

    fn unwatch(&self, oper: Operation) {
        match &self.flavor {
            SenderFlavor::Array(chan) => chan.sender().unwatch(oper),
        }
    }
}

impl<T> SelectHandle for Receiver<T> {
    fn try_select(&self, token: &mut Token) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().try_select(token),
        }
    }

    fn deadline(&self) -> Option<Instant> {
        match &self.flavor {
            ReceiverFlavor::Array(_) => None,
        }
    }

    fn register(&self, oper: Operation, cx: &Context) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().register(oper, cx),
        }
    }

    fn unregister(&self, oper: Operation) {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().unregister(oper),
        }
    }

    fn accept(&self, token: &mut Token, cx: &Context) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().accept(token, cx),
        }
    }

    fn is_ready(&self) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().is_ready(),
        }
    }

    fn watch(&self, oper: Operation, cx: &Context) -> bool {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().watch(oper, cx),
        }
    }

    fn unwatch(&self, oper: Operation) {
        match &self.flavor {
            ReceiverFlavor::Array(chan) => chan.receiver().unwatch(oper),
        }
    }
}

pub(crate) unsafe fn write<T>(s: &Sender<T>, token: &mut Token, msg: T) -> Result<(), T> {
    unsafe {
        match &s.flavor {
            SenderFlavor::Array(chan) => chan.write(token, msg),
        }
    }
}

pub(crate) unsafe fn read<T>(r: &Receiver<T>, token: &mut Token) -> Result<T, ()> {
    unsafe {
        match &r.flavor {
            ReceiverFlavor::Array(chan) => chan.read(token),
        }
    }
}
