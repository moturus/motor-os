//! Block cache for async block devices.

use std::{cell::RefCell, rc::Rc};

use crate::AsyncBlockDevice;

pub struct BlockCache<Dev: AsyncBlockDevice> {
    block_dev: Rc<RefCell<Dev>>,
}

impl<Dev: AsyncBlockDevice> BlockCache<Dev> {
    pub fn new(block_dev: Rc<RefCell<Dev>>) -> Self {
        Self { block_dev }
    }
}
