![Build](https://github.com/gz/rust-elfloader/actions/workflows/standard.yml/badge.svg) [![cargo-badge][]][cargo-link] [![docs-badge][]][docs-link]

# elfloader

A library to load and relocate ELF files in memory. This library depends only on
libcore so it can be used in kernel level code, for example to
load user-space programs.

## How-to use

Clients will have to implement the ElfLoader trait:

```rust
use elfloader::*;
use log::info;

/// A simple ExampleLoader, that implements ElfLoader
/// but does nothing but logging
struct ExampleLoader {
    vbase: u64,
}

impl ElfLoader for ExampleLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        for header in load_headers {
            info!(
                "allocate base = {:#x} size = {:#x} flags = {}",
                header.virtual_addr(),
                header.mem_size(),
                header.flags()
            );
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use RelocationType::x86_64;
        use crate::arch::x86_64::RelocationTypes::*;

        let addr: *mut u64 = (self.vbase + entry.offset) as *mut u64;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {

                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                info!(
                    "R_RELATIVE *{:p} = {:#x}",
                    addr,
                    self.vbase + addend
                );
                Ok(())
            }
            _ => Ok((/* not implemented */)),
        }
    }

    fn load(&mut self, flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        let start = self.vbase + base;
        let end = self.vbase + base + region.len() as u64;
        info!("load region into = {:#x} -- {:#x}", start, end);
        Ok(())
    }

    fn tls(
        &mut self,
        tdata_start: VAddr,
        _tdata_length: u64,
        total_size: u64,
        _align: u64
    ) -> Result<(), ElfLoaderErr> {
        let tls_end = tdata_start +  total_size;
        info!("Initial TLS region is at = {:#x} -- {:#x}", tdata_start, tls_end);
        Ok(())
    }

}

// Then, with ElfBinary, a ELF file is loaded using `load`:
fn main() {
    use std::fs;

    let binary_blob = fs::read("test/test").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
    let mut loader = ExampleLoader { vbase: 0x1000_0000 };
    binary.load(&mut loader).expect("Can't load the binary?");
}
```

[//]: # (badges/links)
[cargo-badge]: https://img.shields.io/crates/v/elfloader.svg?label=crates.io
[cargo-link]: https://crates.io/crates/elfloader
[docs-badge]: https://docs.rs/elfloader/badge.svg?label=docs.rs
[docs-link]: https://docs.rs/elfloader
