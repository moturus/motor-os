//! AsyncBlockDevice and AsyncFs traits.
#![allow(async_fn_in_trait)]

#[cfg(feature = "file-dev")]
pub mod file_block_device;

mod block_device;
mod filesystem;

pub use block_device::*;
pub use filesystem::*;

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

    pub async fn from_dev<Dev: AsyncBlockDevice>(
        dev: &mut Dev,
        block_no: u64,
    ) -> std::io::Result<Self> {
        // Safety: we never read from the uninit memory.
        unsafe {
            #[allow(invalid_value)]
            #[allow(clippy::uninit_assumed_init)]
            let mut block = std::mem::MaybeUninit::<Block>::uninit().assume_init();
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

    pub fn get_at_offset<T: plain::Plain>(&self, offset: usize) -> &T {
        assert!(core::mem::size_of::<T>() + offset <= BLOCK_SIZE);
        plain::from_bytes(&self.bytes[offset..(offset + core::mem::size_of::<T>())])
            .expect("Bad alignment")
    }

    pub fn get_mut_at_offset<T: plain::Plain>(&mut self, offset: usize) -> &mut T {
        assert!(core::mem::size_of::<T>() + offset <= BLOCK_SIZE);
        plain::from_mut_bytes(&mut self.bytes[offset..(offset + core::mem::size_of::<T>())])
            .expect("Bad alignment")
    }
}
