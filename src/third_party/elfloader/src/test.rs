#[cfg(test)]
mod test {
    use crate::*;
    use log::{info, trace};
    use std::fs;
    use std::vec::Vec;

    #[derive(Eq, Clone, PartialEq, Copy, Debug)]
    enum LoaderAction {
        Allocate(VAddr, usize, Flags),
        Load(VAddr, usize),
        Relocate(VAddr, u64),
        Tls(VAddr, u64, u64, u64),
    }
    struct TestLoader {
        vbase: VAddr,
        actions: Vec<LoaderAction>,
    }

    impl TestLoader {
        fn new(offset: VAddr) -> TestLoader {
            TestLoader {
                vbase: offset,
                actions: Vec::with_capacity(12),
            }
        }
    }

    impl ElfLoader for TestLoader {
        fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
            for header in load_headers {
                info!(
                    "allocate base = {:#x} size = {:#x} flags = {}",
                    header.virtual_addr(),
                    header.mem_size(),
                    header.flags()
                );

                self.actions.push(LoaderAction::Allocate(
                    header.virtual_addr(),
                    header.mem_size() as usize,
                    header.flags(),
                ));
            }
            Ok(())
        }

        fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
            use crate::arch::x86::RelocationTypes::*;
            use crate::arch::x86_64::RelocationTypes::*;
            use RelocationType::{x86, x86_64};

            // Get the pointer to where the relocation happens in the
            // memory where we loaded the headers
            //
            // vbase is the new base where we locate the binary
            //
            // get_offset(): For an executable or shared object, the value indicates
            // the virtual address of the storage unit affected by the relocation.
            // This information makes the relocation entries more useful for the runtime linker.
            let addr: *mut u64 = (self.vbase + entry.offset) as *mut u64;

            match entry.rtype {
                // x86
                x86(R_386_32) => Ok(()),
                x86(R_386_RELATIVE) => {
                    info!("R_RELATIVE {:p} ", addr);
                    self.actions
                        .push(LoaderAction::Relocate(addr as u64, self.vbase));
                    Ok(())
                }
                x86(R_386_GLOB_DAT) => {
                    trace!("R_386_GLOB_DAT: Can't handle that.");
                    Ok(())
                }
                x86(R_386_NONE) => Ok(()),

                // x86_64
                x86_64(R_AMD64_64) => {
                    trace!("R_64");
                    Ok(())
                }
                x86_64(R_AMD64_RELATIVE) => {
                    // This type requires addend to be present
                    let addend = entry
                        .addend
                        .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                    // This is a relative relocation, add the offset (where we put our
                    // binary in the vspace) to the addend and we're done.
                    self.actions
                        .push(LoaderAction::Relocate(addr as u64, self.vbase + addend));
                    trace!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);
                    Ok(())
                }
                x86_64(R_AMD64_GLOB_DAT) => {
                    trace!("R_AMD64_GLOB_DAT: Can't handle that.");
                    Ok(())
                }
                x86_64(R_AMD64_NONE) => Ok(()),
                _ => Err(ElfLoaderErr::UnsupportedRelocationEntry),
            }
        }

        fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
            info!("load base = {:#x} size = {:#x} region", base, region.len());
            self.actions.push(LoaderAction::Load(base, region.len()));
            Ok(())
        }

        fn tls(
            &mut self,
            tdata_start: VAddr,
            tdata_length: u64,
            total_size: u64,
            alignment: u64,
        ) -> Result<(), ElfLoaderErr> {
            info!(
                "tdata_start = {:#x} tdata_length = {:#x} total_size = {:#x} alignment = {:#}",
                tdata_start, tdata_length, total_size, alignment
            );
            self.actions.push(LoaderAction::Tls(
                tdata_start,
                tdata_length,
                total_size,
                alignment,
            ));
            Ok(())
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn load_pie_elf() {
        init();
        let binary_blob = fs::read("test/test").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(binary.is_pie());

        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");

        for action in loader.actions.iter() {
            println!("{:?}", action);
        }

        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x0u64), 0x888, Flags(1 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x200db8u64), 0x260, Flags(2 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x0u64), 0x888))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x200db8u64), 0x258))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x200db8, 0x1000_0000 + 0x000640))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x200dc0, 0x1000_0000 + 0x000600))
            .is_some());
    }

    #[test]
    fn load_pie_elf_32() {
        init();
        let binary_blob = fs::read("test/test32").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(binary.is_pie());

        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");

        for action in loader.actions.iter() {
            println!("{:?}", action);
        }

        // View allocate/load actions with readelf -l [binary]
        // Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
        // LOAD           0x000000 0x00000000 0x00000000 0x003bc 0x003bc R   0x1000
        // LOAD           0x001000 0x00001000 0x00001000 0x00288 0x00288 R E 0x1000
        // LOAD           0x002000 0x00002000 0x00002000 0x0016c 0x0016c R   0x1000
        // LOAD           0x002ef4 0x00003ef4 0x00003ef4 0x00128 0x0012c RW  0x1000
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x0u64), 0x003bc, Flags(4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x1000u64), 0x288, Flags(1 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x002000u64), 0x0016c, Flags(4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x3ef4u64), 0x12c, Flags(2 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x0u64), 0x003bc))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x001000u64), 0x00288))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x002000u64), 0x0016c))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x00003ef4u64), 0x00128))
            .is_some());

        // View relocation actions with readelf -r [binary]
        // Offset     Info    Type            Sym.Value  Sym. Name
        // 00003ef4  00000008 R_386_RELATIVE
        // 00003ef8  00000008 R_386_RELATIVE
        // 00003ff8  00000008 R_386_RELATIVE
        // 00004018  00000008 R_386_RELATIVE
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x00003ef4, 0x1000_0000))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x00003ef8, 0x1000_0000))
            .is_some());
    }

    #[test]
    fn check_nopie() {
        init();
        let binary_blob = fs::read("test/test_nopie").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(!binary.is_pie());
    }

    #[test]
    fn check_nopie_32() {
        init();
        let binary_blob = fs::read("test/test32_nopie").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(!binary.is_pie());
    }

    #[test]
    fn check_tls() {
        init();

        let binary_blob = fs::read("test/tls").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");
        /*
        TLS produces entries of this form:
        pheader = Program header:
        type:             Ok(Tls)
        flags:              R
        offset:           0xdb4
        virtual address:  0x200db4
        physical address: 0x200db4
        file size:        0x4
        memory size:      0x8
        align:            0x4

        File size is 0x4 because we have one tdata entry; memory size
        is 8 because we also have one bss entry that needs to be written with zeroes.
        So to initialize TLS: we allocate zeroed memory of size `memory size`, then copy
        file size starting at virtual address in the beginning.
        */
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x200db4u64), 0x4, 0x8, 0x4))
            .is_some());
    }

    #[test]
    fn check_tls_32() {
        init();

        let binary_blob = fs::read("test/tls32").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");
        /*
        TLS produces entries of this form:
        pheader = Program header:
        type:             Ok(Tls)
        flags:              R
        offset:           0x2ef0
        virtual address:  0x3ef0
        physical address: 0x3ef0
        file size:        0x4
        memory size:      0x8
        align:            0x4

        File size is 0x4 because we have one tdata entry; memory size
        is 8 because we also have one bss entry that needs to be written with zeroes.
        So to initialize TLS: we allocate zeroed memory of size `memory size`, then copy
        file size starting at virtual address in the beginning.
        */
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x3ef0u64), 0x4, 0x8, 0x4))
            .is_some());
    }
}

#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
