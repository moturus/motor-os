use crate::dap;

#[derive(Clone)]
pub struct DiskAccess {
    pub disk_number: u16,
    pub base_offset: u64,
}

impl DiskAccess {
    pub fn read_exact_into(&mut self, start_addr: usize, len: usize, buf: &mut dyn AlignedBuffer) {
        assert_eq!(len % 512, 0);
        let buf = &mut buf.slice_mut()[..len];
        let start_addr = start_addr as u64;

        let end_addr = self.base_offset + start_addr + u64::try_from(buf.len()).unwrap();
        let mut start_lba = (self.base_offset + start_addr) / 512;
        let end_lba = (end_addr - 1) / 512;

        let mut number_of_sectors = end_lba + 1 - start_lba;
        let mut target_addr = buf.as_ptr_range().start as u32;

        loop {
            let sectors = u64::min(number_of_sectors, 32) as u16;
            let dap = dap::DiskAddressPacket::from_lba(
                start_lba,
                sectors,
                (target_addr & 0b1111) as u16,
                (target_addr >> 4).try_into().unwrap(),
            );
            unsafe {
                dap.perform_load(self.disk_number);
            }

            start_lba += u64::from(sectors);
            number_of_sectors -= u64::from(sectors);
            target_addr += u32::from(sectors) * 512;

            if number_of_sectors == 0 {
                break;
            }
        }
    }
}

#[repr(align(2))]
pub struct AlignedArrayBuffer<const LEN: usize> {
    pub buffer: [u8; LEN],
}

pub trait AlignedBuffer {
    fn slice(&self) -> &[u8];
    fn slice_mut(&mut self) -> &mut [u8];
}

impl<const LEN: usize> AlignedBuffer for AlignedArrayBuffer<LEN> {
    fn slice(&self) -> &[u8] {
        &self.buffer[..]
    }
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..]
    }
}
