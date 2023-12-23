use core::arch::asm;

#[derive(core::fmt::Debug)]
pub struct Leaf {
    pub leaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl Leaf {
    pub fn new(leaf: u32) -> Leaf {
        let mut eax: u32 = leaf;
        let mut ebx: u32;
        let mut ecx: u32;
        let mut edx: u32;

        // Basic validation
        unsafe {
            asm!(
                "mov {0:r}, rbx",
                "cpuid",
                "xchg {0:r}, rbx",
                lateout(reg) ebx,  // rbx is reserved by llvm
                inlateout("eax") eax,
                lateout("ecx") ecx,
                lateout("edx") edx,
                options(nomem, nostack)
            )
        }

        Leaf {
            leaf,
            eax,
            ebx,
            ecx,
            edx,
        }
    }
}

fn leaf(num: u32) -> Leaf {
    Leaf::new(num)
}

fn leaf_kvm() -> Leaf {
    Leaf::new(0x4000_0001)
}

pub fn has_msr() -> bool {
    leaf(1).edx & (1 << 5) != 0
}

pub fn has_tsc() -> bool {
    leaf(1).edx & (1 << 4) != 0
}

pub fn has_tsc_deadline() -> bool {
    leaf(1).edx & (1 << 24) != 0
}

pub fn has_rdtscp() -> bool {
    leaf(0x8000_0001).edx & (1 << 27) != 0
}

pub fn has_pdpe1gb() -> bool {
    leaf(0x8000_0001).edx & (1 << 26) != 0 // 1G pages
}

// num_cpus() below works in QEMU but does not work in cloud-hypervisor.
/*
pub fn num_cpus() -> u8 {
    let leaf = leaf(1);
    if leaf.edx & (1 << 28) != 0 {
        ((leaf.ebx & 0x00FF0000) >> 16) as u8
    } else {
        1
    }
}
*/

pub fn has_kvm_clockshource2() -> bool {
    // see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
    // see https://www.kernel.org/doc/html/latest/virt/kvm/cpuid.html
    leaf_kvm().eax & (1 << 3) != 0
}

pub fn has_kvm_clockshource_stable_bit() -> bool {
    // see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
    // see https://www.kernel.org/doc/html/latest/virt/kvm/cpuid.html
    leaf_kvm().eax & (1 << 24) != 0
}

pub fn apic_id_32() -> u32 {
    use x86::apic::ApicControl;

    let mut x2apic = x86::apic::x2apic::X2APIC::new();
    x2apic.attach();
    x2apic.id()
}
