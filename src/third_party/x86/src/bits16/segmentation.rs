use crate::segmentation::{
    DescriptorBuilder, DescriptorType, GateDescriptorBuilder, SegmentSelector,
    SystemDescriptorTypes32,
};

impl GateDescriptorBuilder<u16> for DescriptorBuilder {
    fn tss_descriptor(base: u64, limit: u64, available: bool) -> DescriptorBuilder {
        let typ = match available {
            true => DescriptorType::System32(SystemDescriptorTypes32::TSSAvailable16),
            false => DescriptorType::System32(SystemDescriptorTypes32::TSSBusy16),
        };

        DescriptorBuilder::with_base_limit(base, limit).set_type(typ)
    }

    fn call_gate_descriptor(selector: SegmentSelector, offset: u16) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::CallGate16),
        )
    }

    fn interrupt_descriptor(selector: SegmentSelector, offset: u16) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::InterruptGate16),
        )
    }

    fn trap_gate_descriptor(selector: SegmentSelector, offset: u16) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::TrapGate16),
        )
    }
}
