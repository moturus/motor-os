use crate::{
    platform::address::{AccessSize, AddressSpace, GenericAddress, RawGenericAddress},
    sdt::{ExtendedField, SdtHeader},
    AcpiError,
    AcpiTable,
};
use bit_field::BitField;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PowerProfile {
    Unspecified,
    Desktop,
    Mobile,
    Workstation,
    EnterpriseServer,
    SohoServer,
    AppliancePc,
    PerformanceServer,
    Tablet,
    Reserved(u8),
}

/// Represents the Fixed ACPI Description Table (FADT). This table contains various fixed hardware
/// details, such as the addresses of the hardware register blocks. It also contains a pointer to
/// the Differentiated Definition Block (DSDT).
///
/// In cases where the FADT contains both a 32-bit and 64-bit field for the same address, we should
/// always prefer the 64-bit one. Only if it's zero or the CPU will not allow us to access that
/// address should the 32-bit one be used.
#[repr(C, packed)]
pub struct Fadt {
    header: SdtHeader,

    firmware_ctrl: u32,
    dsdt_address: u32,

    // Used in acpi 1.0; compatibility only, should be zero
    _reserved: u8,

    preferred_pm_profile: u8,
    /// On systems with an i8259 PIC, this is the vector the System Control Interrupt (SCI) is wired to. On other systems, this is
    /// the Global System Interrupt (GSI) number of the SCI.
    ///
    /// The SCI should be treated as a sharable, level, active-low interrupt.
    pub sci_interrupt: u16,
    /// The system port address of the SMI Command Port. This port should only be accessed from the boot processor.
    /// A value of `0` indicates that System Management Mode is not supported.
    ///
    ///    - Writing the value in `acpi_enable` to this port will transfer control of the ACPI hardware registers
    ///      from the firmware to the OS. You must synchronously wait for the transfer to complete, indicated by the
    ///      setting of `SCI_EN`.
    ///    - Writing the value in `acpi_disable` will relinquish ownership of the hardware registers to the
    ///      firmware. This should only be done if you've previously acquired ownership. Before writing this value,
    ///      the OS should mask all SCI interrupts and clear the `SCI_EN` bit.
    ///    - Writing the value in `s4bios_req` requests that the firmware enter the S4 state through the S4BIOS
    ///      feature. This is only supported if the `S4BIOS_F` flag in the FACS is set.
    ///    - Writing the value in `pstate_control` yields control of the processor performance state to the OS.
    ///      If this field is `0`, this feature is not supported.
    ///    - Writing the value in `c_state_control` tells the firmware that the OS supports `_CST` AML objects and
    ///      notifications of C State changes.
    pub smi_cmd_port: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_control: u8,
    pm1a_event_block: u32,
    pm1b_event_block: u32,
    pm1a_control_block: u32,
    pm1b_control_block: u32,
    pm2_control_block: u32,
    pm_timer_block: u32,
    gpe0_block: u32,
    gpe1_block: u32,
    pm1_event_length: u8,
    pm1_control_length: u8,
    pm2_control_length: u8,
    pm_timer_length: u8,
    gpe0_block_length: u8,
    gpe1_block_length: u8,
    pub gpe1_base: u8,
    pub c_state_control: u8,
    /// The worst-case latency to enter and exit the C2 state, in microseconds. A value `>100` indicates that the
    /// system does not support the C2 state.
    pub worst_c2_latency: u16,
    /// The worst-case latency to enter and exit the C3 state, in microseconds. A value `>1000` indicates that the
    /// system does not support the C3 state.
    pub worst_c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub iapc_boot_arch: IaPcBootArchFlags,
    _reserved2: u8, // must be 0
    pub flags: FixedFeatureFlags,
    reset_reg: RawGenericAddress,
    pub reset_value: u8,
    pub arm_boot_arch: ArmBootArchFlags,
    fadt_minor_version: u8,
    x_firmware_ctrl: ExtendedField<u64, 2>,
    x_dsdt_address: ExtendedField<u64, 2>,
    x_pm1a_event_block: ExtendedField<RawGenericAddress, 2>,
    x_pm1b_event_block: ExtendedField<RawGenericAddress, 2>,
    x_pm1a_control_block: ExtendedField<RawGenericAddress, 2>,
    x_pm1b_control_block: ExtendedField<RawGenericAddress, 2>,
    x_pm2_control_block: ExtendedField<RawGenericAddress, 2>,
    x_pm_timer_block: ExtendedField<RawGenericAddress, 2>,
    x_gpe0_block: ExtendedField<RawGenericAddress, 2>,
    x_gpe1_block: ExtendedField<RawGenericAddress, 2>,
    sleep_control_reg: ExtendedField<RawGenericAddress, 2>,
    sleep_status_reg: ExtendedField<RawGenericAddress, 2>,
    hypervisor_vendor_id: ExtendedField<u64, 2>,
}

impl AcpiTable for Fadt {
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}

impl Fadt {
    pub fn validate(&self) -> Result<(), AcpiError> {
        self.header.validate(crate::sdt::Signature::FADT)
    }

    pub fn facs_address(&self) -> Result<usize, AcpiError> {
        unsafe {
            { self.x_firmware_ctrl }
                .access(self.header.revision)
                .filter(|&p| p != 0)
                .or(Some(self.firmware_ctrl as u64))
                .filter(|&p| p != 0)
                .map(|p| p as usize)
                .ok_or(AcpiError::InvalidFacsAddress)
        }
    }

    pub fn dsdt_address(&self) -> Result<usize, AcpiError> {
        unsafe {
            { self.x_dsdt_address }
                .access(self.header.revision)
                .filter(|&p| p != 0)
                .or(Some(self.dsdt_address as u64))
                .filter(|&p| p != 0)
                .map(|p| p as usize)
                .ok_or(AcpiError::InvalidDsdtAddress)
        }
    }

    pub fn power_profile(&self) -> PowerProfile {
        match self.preferred_pm_profile {
            0 => PowerProfile::Unspecified,
            1 => PowerProfile::Desktop,
            2 => PowerProfile::Mobile,
            3 => PowerProfile::Workstation,
            4 => PowerProfile::EnterpriseServer,
            5 => PowerProfile::SohoServer,
            6 => PowerProfile::AppliancePc,
            7 => PowerProfile::PerformanceServer,
            8 => PowerProfile::Tablet,
            other => PowerProfile::Reserved(other),
        }
    }

    pub fn pm1a_event_block(&self) -> Result<GenericAddress, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm1a_event_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return GenericAddress::from_raw(raw);
            }
        }

        Ok(GenericAddress {
            address_space: AddressSpace::SystemIo,
            bit_width: self.pm1_event_length * 8,
            bit_offset: 0,
            access_size: AccessSize::Undefined,
            address: self.pm1a_event_block.into(),
        })
    }

    pub fn pm1b_event_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm1b_event_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.pm1b_event_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.pm1_event_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.pm1b_event_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn pm1a_control_block(&self) -> Result<GenericAddress, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm1a_control_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return GenericAddress::from_raw(raw);
            }
        }

        Ok(GenericAddress {
            address_space: AddressSpace::SystemIo,
            bit_width: self.pm1_control_length * 8,
            bit_offset: 0,
            access_size: AccessSize::Undefined,
            address: self.pm1a_control_block.into(),
        })
    }

    pub fn pm1b_control_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm1b_control_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.pm1b_control_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.pm1_control_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.pm1b_control_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn pm2_control_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm2_control_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.pm2_control_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.pm2_control_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.pm2_control_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn pm_timer_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_pm_timer_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.pm_timer_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.pm_timer_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.pm_timer_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn gpe0_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_gpe0_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.gpe0_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.gpe0_block_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.gpe0_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn gpe1_block(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.x_gpe1_block.access(self.header().revision) } {
            if raw.address != 0x0 {
                return Ok(Some(GenericAddress::from_raw(raw)?));
            }
        }

        if self.gpe1_block != 0 {
            Ok(Some(GenericAddress {
                address_space: AddressSpace::SystemIo,
                bit_width: self.gpe1_block_length * 8,
                bit_offset: 0,
                access_size: AccessSize::Undefined,
                address: self.gpe1_block.into(),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn reset_register(&self) -> Result<GenericAddress, AcpiError> {
        GenericAddress::from_raw(self.reset_reg)
    }

    pub fn sleep_control_register(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.sleep_control_reg.access(self.header().revision) } {
            Ok(Some(GenericAddress::from_raw(raw)?))
        } else {
            Ok(None)
        }
    }

    pub fn sleep_status_register(&self) -> Result<Option<GenericAddress>, AcpiError> {
        if let Some(raw) = unsafe { self.sleep_status_reg.access(self.header().revision) } {
            Ok(Some(GenericAddress::from_raw(raw)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy)]
pub struct FixedFeatureFlags(u32);

impl FixedFeatureFlags {
    /// If true, an equivalent to the x86 [WBINVD](https://www.felixcloutier.com/x86/wbinvd) instruction is supported.
    /// All caches will be flushed and invalidated upon completion of this instruction,
    /// and memory coherency is properly maintained. The cache *SHALL* only contain what OSPM references or allows to be cached.
    pub fn supports_equivalent_to_wbinvd(&self) -> bool {
        self.0.get_bit(0)
    }

    /// If true, [WBINVD](https://www.felixcloutier.com/x86/wbinvd) properly flushes all caches and  memory coherency is maintained, but caches may not be invalidated.
    pub fn wbinvd_flushes_all_caches(&self) -> bool {
        self.0.get_bit(1)
    }

    /// If true, all processors implement the C1 power state.
    pub fn all_procs_support_c1_power_state(&self) -> bool {
        self.0.get_bit(2)
    }

    /// If true, the C2 power state is configured to work on a uniprocessor and multiprocessor system.
    pub fn c2_configured_for_mp_system(&self) -> bool {
        self.0.get_bit(3)
    }

    /// If true, the power button is handled as a control method device.
    /// If false, the power button is handled as a fixed-feature programming model.
    pub fn power_button_is_control_method(&self) -> bool {
        self.0.get_bit(4)
    }

    /// If true, the sleep button is handled as a control method device.
    /// If false, the sleep button is handled as a fixed-feature programming model.
    pub fn sleep_button_is_control_method(&self) -> bool {
        self.0.get_bit(5)
    }

    /// If true, the RTC wake status is not supported in fixed register space.
    pub fn no_rtc_wake_in_fixed_register_space(&self) -> bool {
        self.0.get_bit(6)
    }

    /// If true, the RTC alarm function can wake the system from an S4 sleep state.
    pub fn rtc_wakes_system_from_s4(&self) -> bool {
        self.0.get_bit(7)
    }

    /// If true, indicates that the PM timer is a 32-bit value.
    /// If false, the PM timer is a 24-bit value and the remaining 8 bits are clear.
    pub fn pm_timer_is_32_bit(&self) -> bool {
        self.0.get_bit(8)
    }

    /// If true, the system supports docking.
    pub fn supports_docking(&self) -> bool {
        self.0.get_bit(9)
    }

    /// If true, the system supports system reset via the reset_reg field of the FADT.
    pub fn supports_system_reset_via_fadt(&self) -> bool {
        self.0.get_bit(10)
    }

    /// If true, the system supports no expansion capabilities and the case is sealed.
    pub fn case_is_sealed(&self) -> bool {
        self.0.get_bit(11)
    }

    /// If true, the system cannot detect the monitor or keyboard/mouse devices.
    pub fn system_is_headless(&self) -> bool {
        self.0.get_bit(12)
    }

    /// If true, OSPM must use a processor instruction after writing to the SLP_TYPx register.
    pub fn use_instr_after_write_to_slp_typx(&self) -> bool {
        self.0.get_bit(13)
    }

    /// If set, the platform supports the `PCIEXP_WAKE_STS` and `PCIEXP_WAKE_EN` bits in the PM1 status and enable registers.
    pub fn supports_pciexp_wake_in_pm1(&self) -> bool {
        self.0.get_bit(14)
    }

    /// If true, OSPM should use the ACPI power management timer or HPET for monotonically-decreasing timers.
    pub fn use_pm_or_hpet_for_monotonically_decreasing_timers(&self) -> bool {
        self.0.get_bit(15)
    }

    /// If true, the contents of the `RTC_STS` register are valid after wakeup from S4.
    pub fn rtc_sts_is_valid_after_wakeup_from_s4(&self) -> bool {
        self.0.get_bit(16)
    }

    /// If true, the platform supports OSPM leaving GPE wake events armed prior to an S5 transition.
    pub fn ospm_may_leave_gpe_wake_events_armed_before_s5(&self) -> bool {
        self.0.get_bit(17)
    }

    /// If true, all LAPICs must be configured using the cluster destination model when delivering interrupts in logical mode.
    pub fn lapics_must_use_cluster_model_for_logical_mode(&self) -> bool {
        self.0.get_bit(18)
    }

    /// If true, all LXAPICs must be configured using physical destination mode.
    pub fn local_xapics_must_use_physical_destination_mode(&self) -> bool {
        self.0.get_bit(19)
    }

    /// If true, this system is a hardware-reduced ACPI platform, and software methods are used for fixed-feature functions defined in chapter 4 of the ACPI specification.
    pub fn system_is_hw_reduced_acpi(&self) -> bool {
        self.0.get_bit(20)
    }

    /// If true, the system can achieve equal or better power savings in an S0 power state, making an S3 transition useless.
    pub fn no_benefit_to_s3(&self) -> bool {
        self.0.get_bit(21)
    }
}

#[derive(Clone, Copy)]
pub struct IaPcBootArchFlags(u16);

impl IaPcBootArchFlags {
    /// If true, legacy user-accessible devices are available on the LPC and/or ISA buses.
    pub fn legacy_devices_are_accessible(&self) -> bool {
        self.0.get_bit(0)
    }

    /// If true, the motherboard exposes an IO port 60/64 keyboard controller, typically implemented as an 8042 microcontroller.
    pub fn motherboard_implements_8042(&self) -> bool {
        self.0.get_bit(1)
    }

    /// If true, OSPM *must not* blindly probe VGA hardware.
    /// VGA hardware is at MMIO addresses A0000h-BFFFFh and IO ports 3B0h-3BBh and 3C0h-3DFh.
    pub fn dont_probe_vga(&self) -> bool {
        self.0.get_bit(2)
    }

    /// If true, OSPM *must not* enable message-signaled interrupts.
    pub fn dont_enable_msi(&self) -> bool {
        self.0.get_bit(3)
    }

    /// If true, OSPM *must not* enable PCIe ASPM control.
    pub fn dont_enable_pcie_aspm(&self) -> bool {
        self.0.get_bit(4)
    }

    /// If true, OSPM *must not* use the RTC via its IO ports, either because it isn't implemented or is at other addresses;
    /// instead, OSPM *MUST* use the time and alarm namespace device control method.
    pub fn use_time_and_alarm_namespace_for_rtc(&self) -> bool {
        self.0.get_bit(5)
    }
}

#[derive(Clone, Copy)]
pub struct ArmBootArchFlags(u16);

impl ArmBootArchFlags {
    /// If true, the system implements PSCI.
    pub fn implements_psci(&self) -> bool {
        self.0.get_bit(0)
    }

    /// If true, OSPM must use HVC instead of SMC as the PSCI conduit.
    pub fn use_hvc_as_psci_conduit(&self) -> bool {
        self.0.get_bit(1)
    }
}
