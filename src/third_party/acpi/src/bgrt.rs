use crate::{sdt::SdtHeader, AcpiTable};
use bit_field::BitField;

/// The BGRT table contains information about a boot graphic that was displayed
/// by firmware.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Bgrt {
    header: SdtHeader,
    pub version: u16,
    status: u8,
    image_type: u8,
    pub image_address: u64,
    image_offset_x: u32,
    image_offset_y: u32,
}

impl AcpiTable for Bgrt {
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

impl Bgrt {
    pub fn image_type(&self) -> ImageType {
        let img_type = self.image_type;
        match img_type {
            0 => ImageType::Bitmap,
            _ => ImageType::Reserved,
        }
    }

    /// Gets the orientation offset of the image.
    /// Degrees are clockwise from the images default orientation.
    pub fn orientation_offset(&self) -> u16 {
        let status = self.status;
        match status.get_bits(1..3) {
            0 => 0,
            1 => 90,
            2 => 180,
            3 => 270,
            _ => unreachable!(), // will never happen
        }
    }

    pub fn was_displayed(&self) -> bool {
        let status = self.status;
        status.get_bit(0)
    }

    pub fn image_offset(&self) -> (u32, u32) {
        let x = self.image_offset_x;
        let y = self.image_offset_y;
        (x, y)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ImageType {
    Bitmap,
    Reserved,
}
