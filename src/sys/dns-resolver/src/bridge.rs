use moto_dns::{Address, AddressFamily, Status, MAX_ADDRESSES};

unsafe extern "C" {
    fn motor_dns_lookup(
        name: *const u8,
        name_len: usize,
        family: u8,
        out: *mut Address,
        out_capacity: usize,
        out_len: *mut usize,
        out_truncated: *mut u8,
    ) -> i32;
}

pub struct Result {
    pub status: Status,
    pub addresses: [Address; MAX_ADDRESSES],
    pub len: usize,
    pub truncated: bool,
}

pub fn lookup(name: &[u8], family: AddressFamily) -> Result {
    let mut addresses = [Address::zeroed(); MAX_ADDRESSES];
    let mut len = 0;
    let mut truncated = 0;
    let raw_status = unsafe {
        motor_dns_lookup(
            name.as_ptr(),
            name.len(),
            family as u8,
            addresses.as_mut_ptr(),
            addresses.len(),
            &mut len,
            &mut truncated,
        )
    };
    let status = Status::try_from(raw_status as u8).unwrap_or(Status::ResolverFailure);
    if len > MAX_ADDRESSES || (status != Status::Ok && len != 0) {
        return Result {
            status: Status::ResolverFailure,
            addresses: [Address::zeroed(); MAX_ADDRESSES],
            len: 0,
            truncated: false,
        };
    }
    Result {
        status,
        addresses,
        len,
        truncated: truncated != 0,
    }
}
