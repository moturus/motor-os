//! AsyncBlockDevice and AsyncFs traits.
#![allow(async_fn_in_trait)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "file-dev")]
pub mod file_block_device;

pub mod block_cache;
mod block_device;
mod filesystem;

pub use block_device::*;
pub use filesystem::*;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(not(feature = "std"), not(feature = "moto-rt")))]
compile_error!("async-fs must have either 'std' or 'moto-rt' feature.");

pub const BLOCK_SIZE: usize = 4096;

/// A block of bytes.
#[derive(Clone, Copy)]
#[repr(C, align(4096))]
pub struct Block {
    bytes: [u8; 4096],
}

const _: () = assert!(core::mem::size_of::<Block>() == BLOCK_SIZE);

impl Block {
    pub const fn new_zeroed() -> Self {
        Self { bytes: [0; 4096] }
    }

    pub fn clear(&mut self) {
        *self = Self::new_zeroed()
    }

    pub async fn from_dev<Dev: AsyncBlockDevice>(dev: &mut Dev, block_no: u64) -> Result<Self> {
        // Safety: we never read from the uninit memory.
        unsafe {
            #[allow(invalid_value)]
            #[allow(clippy::uninit_assumed_init)]
            let mut block = core::mem::MaybeUninit::<Block>::uninit().assume_init();
            dev.read_block(block_no, &mut block).await?;
            Ok(block)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn get_at_offset<T: bytemuck::Pod>(&self, offset: usize) -> &T {
        assert!(core::mem::size_of::<T>() + offset <= BLOCK_SIZE);
        bytemuck::from_bytes(&self.bytes[offset..(offset + core::mem::size_of::<T>())])
    }

    pub fn get_mut_at_offset<T: bytemuck::Pod>(&mut self, offset: usize) -> &mut T {
        assert!(core::mem::size_of::<T>() + offset <= BLOCK_SIZE);
        bytemuck::from_bytes_mut(&mut self.bytes[offset..(offset + core::mem::size_of::<T>())])
    }
}

/*
pub struct WriteCompletion<'a, F>
where
    F: Future<Output = ()>,
{
    inner: F,
    _phantom_data: core::marker::PhantomData<&'a ()>,
}

impl<'a, F: Future<Output = ()>> Future for WriteCompletion<'a, F> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        // Safety: structured pinning.
        unsafe {
            let inner_future = self.map_unchecked_mut(|s| &mut s.inner);
            inner_future.poll(cx)
        }
    }
}

pub trait AsBlock {
    fn as_block(&self) -> &Block;
    fn as_block_mut(&mut self) -> &mut Block;
}

pub struct IoSlice<'a, B: AsBlock> {
    blocks: &'a [B],
}
*/
