//! Information about Intel's performance events.
pub mod events;
// The types need to be in a spearate file so we don't get circular
// dependencies with build.rs include:
mod description;
pub use self::description::{Counter, EventDescription, MSRIndex, PebsType, Tuple};

use crate::cpuid;
use core::fmt::{Error, Result, Write};
use core::str;
use phf;

const MODEL_LEN: usize = 30;

#[derive(Default)]
struct ModelWriter {
    buffer: [u8; MODEL_LEN],
    index: usize,
}

impl ModelWriter {
    fn as_str(&self) -> &str {
        str::from_utf8(&self.buffer[..self.index]).unwrap()
    }
}

impl Write for ModelWriter {
    fn write_str(&mut self, s: &str) -> Result {
        // TODO: There exists probably a more efficient way of doing this:
        for c in s.chars() {
            if self.index >= self.buffer.len() {
                return Err(Error);
            }
            self.buffer[self.index] = c as u8;
            self.index += 1;
        }
        Ok(())
    }
}

// Format must be a string literal
macro_rules! get_events {
    ($format:expr) => {{
        let cpuid = cpuid::CpuId::new();

        cpuid.get_vendor_info().map_or(None, |vf| {
            cpuid.get_feature_info().map_or(None, |fi| {
                let vendor = vf.as_str();
                let (family, extended_model, model) = (
                    fi.base_family_id(),
                    fi.extended_model_id(),
                    fi.base_model_id(),
                );

                let mut writer: ModelWriter = Default::default();
                // Should work as long as it fits in MODEL_LEN bytes:
                write!(writer, $format, vendor, family, extended_model, model).unwrap();
                let key = writer.as_str();

                events::COUNTER_MAP.get(key)
            })
        })
    }};
}

/// Return all core performance events for the running micro-architecture.
pub fn events() -> Option<&'static phf::Map<&'static str, EventDescription<'static>>> {
    // Should be something like: GenuineIntel-6-2C
    get_events!("{}-{}-{:X}{:X}")
}

#[test]
fn events_test() {
    // Note: This will silently fail in case the counter is not available.
    events().map(|cc| {
        cc.get("INST_RETIRED.ANY").map(|p| {
            assert!(p.event_name == "INST_RETIRED.ANY");
        });
    });
}
