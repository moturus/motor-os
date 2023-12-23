//! Access to various system and model specific registers.

pub mod control;
pub mod model_specific;
pub mod mxcsr;
pub mod rflags;
pub mod segmentation;
pub mod xcontrol;

#[cfg(feature = "instructions")]
#[allow(deprecated)]
pub use crate::instructions::segmentation::{rdfsbase, rdgsbase, wrfsbase, wrgsbase};

#[cfg(feature = "instructions")]
pub use crate::instructions::read_rip;
