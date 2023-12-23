use crate::TagType;
use core::fmt;

/// This tag contains VBE metadata, VBE controller information returned by the
/// VBE Function 00h and VBE mode information returned by the VBE Function 01h.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct VBEInfoTag {
    typ: TagType,
    length: u32,

    /// Indicates current video mode in the format specified in VBE 3.0.
    pub mode: u16,

    /// Contain the segment of the table of a protected mode interface defined in VBE 2.0+.
    ///
    /// If the information for a protected mode interface is not available
    /// this field is set to zero.
    pub interface_segment: u16,

    /// Contain the segment offset of the table of a protected mode interface defined in VBE 2.0+.
    ///
    /// If the information for a protected mode interface is not available
    /// this field is set to zero.
    pub interface_offset: u16,

    /// Contain the segment length of the table of a protected mode interface defined in VBE 2.0+.
    ///
    /// If the information for a protected mode interface is not available
    /// this field is set to zero.
    pub interface_length: u16,

    /// Contains VBE controller information returned by the VBE Function `00h`.
    pub control_info: VBEControlInfo,

    /// Contains VBE mode information returned by the VBE Function `01h`.
    pub mode_info: VBEModeInfo,
}

/// VBE controller information.
///
/// The capabilities of the display controller, the revision level of the
/// VBE implementation, and vendor specific information to assist in supporting all display
/// controllers in the field are listed here.
///
/// The purpose of this struct is to provide information to the kernel about the general
/// capabilities of the installed VBE software and hardware.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VBEControlInfo {
    /// VBE Signature aka "VESA".
    pub signature: [u8; 4],

    /// The VBE version.
    pub version: u16,

    /// A far pointer the the OEM String.
    pub oem_string_ptr: u32,

    /// Capabilities of the graphics controller.
    pub capabilities: VBECapabilities,

    /// Far pointer to the video mode list.
    pub mode_list_ptr: u32,

    /// Number of 64KiB memory blocks (Added for VBE 2.0+).
    pub total_memory: u16,

    /// VBE implementation software revision.
    pub oem_software_revision: u16,

    /// Far pointer to the vendor name string.
    pub oem_vendor_name_ptr: u32,

    /// Far pointer to the product name string.
    pub oem_product_name_ptr: u32,

    /// Far pointer to the product revision string.
    pub oem_product_revision_ptr: u32,

    /// Reserved for VBE implementation scratch area.
    reserved: [u8; 222],

    /// Data area for OEM strings.
    oem_data: [u8; 256],
}

impl fmt::Debug for VBEControlInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VBEControlInfo")
            .field("signature", &self.signature)
            .field("version", &{ self.version })
            .field("oem_string_ptr", &{ self.oem_string_ptr })
            .field("capabilities", &{ self.capabilities })
            .field("mode_list_ptr", &{ self.mode_list_ptr })
            .field("total_memory", &{ self.total_memory })
            .field("oem_software_revision", &{ self.oem_software_revision })
            .field("oem_vendor_name_ptr", &{ self.oem_vendor_name_ptr })
            .field("oem_product_name_ptr", &{ self.oem_product_name_ptr })
            .field("oem_product_revision_ptr", &{
                self.oem_product_revision_ptr
            })
            .finish()
    }
}

/// Extended information about a specific VBE display mode from the
/// mode list returned by `VBEControlInfo` (VBE Function `00h`).
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct VBEModeInfo {
    /// Mode attributes.
    pub mode_attributes: VBEModeAttributes,

    /// Window A attributes.
    pub window_a_attributes: VBEWindowAttributes,

    /// Window B attributes.
    pub window_b_attributes: VBEWindowAttributes,

    /// Window granularity (Measured in Kilobytes.)
    pub window_granularity: u16,

    /// Window size.
    pub window_size: u16,

    /// Window A start segment.
    pub window_a_segment: u16,

    /// Window B start segment.
    pub window_b_segment: u16,

    /// Real mode pointer to window function.
    pub window_function_ptr: u32,

    /// Bytes per scan line
    pub pitch: u16,

    /// Horizontal and vertical resolution in pixels or characters.
    pub resolution: (u16, u16),

    /// Character cell width and height in pixels.
    pub character_size: (u8, u8),

    /// Number of memory planes.
    pub number_of_planes: u8,

    /// Bits per pixel
    pub bpp: u8,

    /// Number of banks
    pub number_of_banks: u8,

    /// Memory model type
    pub memory_model: VBEMemoryModel,

    /// Bank size (Measured in Kilobytes.)
    pub bank_size: u8,

    /// Number of images.
    pub number_of_image_pages: u8,

    /// Reserved for page function.
    reserved0: u8,

    /// Red colour field.
    pub red_field: VBEField,

    /// Green colour field.
    pub green_field: VBEField,

    /// Blue colour field.
    pub blue_field: VBEField,

    /// Reserved colour field.
    pub reserved_field: VBEField,

    /// Direct colour mode attributes.
    pub direct_color_attributes: VBEDirectColorAttributes,

    /// Physical address for flat memory frame buffer
    pub framebuffer_base_ptr: u32,

    /// A pointer to the start of off screen memory.
    ///
    /// # Deprecated
    ///
    /// In VBE3.0 and above these fields are reserved and unused.
    pub offscreen_memory_offset: u32,

    /// The amount of off screen memory in 1k units.
    ///
    /// # Deprecated
    ///
    /// In VBE3.0 and above these fields are reserved and unused.
    pub offscreen_memory_size: u16,

    /// Remainder of mode info block
    reserved1: [u8; 206],
}

impl fmt::Debug for VBEModeInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VBEModeInfo")
            .field("mode_attributes", &{ self.mode_attributes })
            .field("window_a_attributes", &self.window_a_attributes)
            .field("window_b_attributes", &self.window_b_attributes)
            .field("window_granularity", &{ self.window_granularity })
            .field("window_size", &{ self.window_size })
            .field("window_a_segment", &{ self.window_a_segment })
            .field("window_b_segment", &{ self.window_b_segment })
            .field("window_function_ptr", &{ self.window_function_ptr })
            .field("pitch", &{ self.pitch })
            .field("resolution", &{ self.resolution })
            .field("character_size", &self.character_size)
            .field("number_of_planes", &self.number_of_planes)
            .field("bpp", &self.bpp)
            .field("number_of_banks", &self.number_of_banks)
            .field("memory_model", &self.memory_model)
            .field("bank_size", &self.bank_size)
            .field("number_of_image_pages", &self.number_of_image_pages)
            .field("red_field", &self.red_field)
            .field("green_field", &self.green_field)
            .field("blue_field", &self.blue_field)
            .field("reserved_field", &self.reserved_field)
            .field("direct_color_attributes", &self.direct_color_attributes)
            .field("framebuffer_base_ptr", &{ self.framebuffer_base_ptr })
            .field("offscreen_memory_offset", &{ self.offscreen_memory_offset })
            .field("offscreen_memory_size", &{ self.offscreen_memory_size })
            .finish()
    }
}

/// A VBE colour field.
///
/// Descirbes the size and position of some colour capability.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(C, packed)]
pub struct VBEField {
    /// The size, in bits, of the color components of a direct color pixel.
    pub size: u8,

    /// define the bit position within the direct color pixel or YUV pixel of
    /// the least significant bit of the respective color component.
    pub position: u8,
}

bitflags! {
    /// The Capabilities field indicates the support of specific features in the graphics environment.
    pub struct VBECapabilities: u32 {
        /// Can the DAC be switched between 6 and 8 bit modes.
        const SWITCHABLE_DAC = 0x1;

        /// Is the controller VGA compatible.
        const NOT_VGA_COMPATIBLE = 0x2;

        /// The operating behaviour of the RAMDAC.
        ///
        /// When writing lots of information to the RAMDAC, use the blank bit in Function `09h`.
        const RAMDAC_FIX = 0x4;
    }
}

bitflags! {
    /// A Mode attributes bitfield.
    pub struct VBEModeAttributes: u16 {
        /// Mode supported by hardware configuration.
        const SUPPORTED = 0x1;

        /// TTY Output functions supported by BIOS
        const TTY_SUPPORTED = 0x4;

        /// Color support.
        const COLOR = 0x8;

        /// Mode type (text or graphics).
        const GRAPHICS = 0x10;

        /// VGA compatibility.
        const NOT_VGA_COMPATIBLE = 0x20;

        /// VGA Window compatibility.
        ///
        /// If this is set, the window A and B fields of VBEModeInfo are invalid.
        const NO_VGA_WINDOW = 0x40;

        /// Linear framebuffer availability.
        ///
        /// Set if a linear framebuffer is available for this mode.
        const LINEAR_FRAMEBUFFER = 0x80;
    }
}

bitflags! {
    /// The WindowAttributes describe the characteristics of the CPU windowing
    /// scheme such as whether the windows exist and are read/writeable, as follows:
    pub struct VBEWindowAttributes: u8 {
        /// Relocatable window(s) supported?
        const RELOCATABLE = 0x1;

        /// Window is readable?
        const READABLE = 0x2;

        /// Window is writeable?
        const WRITEABLE = 0x4;
    }
}

bitflags! {

    /// The DirectColorModeInfo field describes important characteristics of direct color modes.
    ///
    /// Bit D0 specifies whether the color ramp of the DAC is fixed or
    /// programmable. If the color ramp is fixed, then it can not be changed.
    /// If the color ramp is programmable, it is assumed that the red, green,
    /// and blue lookup tables can be loaded by using VBE Function `09h`
    /// (it is assumed all color ramp data is 8 bits per primary).
    /// Bit D1 specifies whether the bits in the Rsvd field of the direct color
    /// pixel can be used by the application or are reserved, and thus unusable.
    pub struct VBEDirectColorAttributes: u8 {
        /// Color ramp is fixed when cleared and programmable when set.
        const PROGRAMMABLE = 0x1;

        /// Bits in Rsvd field when cleared are reserved and usable when set.
        const RESERVED_USABLE = 0x2;
    }
}

/// The MemoryModel field specifies the general type of memory organization used in modes.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum VBEMemoryModel {
    Text = 0x00,
    CGAGraphics = 0x01,
    HerculesGraphics = 0x02,
    Planar = 0x03,
    PackedPixel = 0x04,
    Unchained = 0x05,
    DirectColor = 0x06,
    YUV = 0x07,
}
