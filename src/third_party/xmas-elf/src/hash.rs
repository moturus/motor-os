use symbol_table::Entry;
use zero::Pod;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HashTable {
    bucket_count: u32,
    chain_count: u32,
    first_bucket: u32,
}

unsafe impl Pod for HashTable {}

pub fn hash(input: &str) -> u32 {
    let mut result = 0;
    for i in input.bytes() {
        result = (result << 4) + i as u32;
        let g = result & 0xf0000000;
        if g != 0 {
            result ^= g >> 24;
        }
        result &= !g
    }
    result
}

impl HashTable {
    pub fn get_bucket(&self, index: u32) -> u32 {
        assert!(index < self.bucket_count);
        unsafe {
            let ptr = (&self.first_bucket as *const u32).offset(index as isize);
            *ptr
        }
    }

    pub fn get_chain(&self, index: u32) -> u32 {
        assert!(index < self.chain_count);
        let index = self.bucket_count + index;
        unsafe {
            let ptr = (&self.first_bucket as *const u32).offset(index as isize);
            *ptr
        }
    }

    pub fn lookup<'a, F>(&'a self, _name: &str, _f: F) -> &'a dyn Entry
        where F: Fn(&'a dyn Entry) -> bool
    {
        // TODO
        unimplemented!();
    }
}
