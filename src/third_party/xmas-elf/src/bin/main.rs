extern crate xmas_elf;

use std::path::Path;
use std::env;
use std::process;
use xmas_elf::{ElfFile, header, program};
use xmas_elf::sections;

// Note if running on a 32bit system, then reading Elf64 files probably will not
// work (maybe if the size of the file in bytes is < u32::Max).

// Helper function to open a file and read it into a buffer.
// Allocates the buffer.
fn open_file<P: AsRef<Path>>(name: P) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut f = File::open(name).unwrap();
    let mut buf = Vec::new();
    assert!(f.read_to_end(&mut buf).unwrap() > 0);
    buf
}

fn display_binary_information<P: AsRef<Path>>(binary_path: P) {
    let buf = open_file(binary_path);
    let elf_file = ElfFile::new(&buf).unwrap();
    println!("{}", elf_file.header);
    header::sanity_check(&elf_file).unwrap();

    let mut sect_iter = elf_file.section_iter();
    // Skip the first (dummy) section
    sect_iter.next();
    println!("sections");
    for sect in sect_iter {
        println!("{}", sect.get_name(&elf_file).unwrap());
        println!("{:?}", sect.get_type());
        // println!("{}", sect);
        sections::sanity_check(sect, &elf_file).unwrap();

        // if sect.get_type() == ShType::StrTab {
        //     println!("{:?}", sect.get_data(&elf_file).to_strings().unwrap());
        // }

        // if sect.get_type() == ShType::SymTab {
        //     if let sections::SectionData::SymbolTable64(data) = sect.get_data(&elf_file) {
        //         for datum in data {
        //             println!("{}", datum.get_name(&elf_file));
        //         }
        //     } else {
        //         unreachable!();
        //     }
        // }
    }
    let ph_iter = elf_file.program_iter();
    println!("\nprogram headers");
    for sect in ph_iter {
        println!("{:?}", sect.get_type());
        program::sanity_check(sect, &elf_file).unwrap();
    }

    match elf_file.program_header(5) {
        Ok(sect) => {
            println!("{}", sect);
            match sect.get_data(&elf_file) {
                Ok(program::SegmentData::Note64(header, ptr)) => {
                    println!("{}: {:?}", header.name(ptr), header.desc(ptr))
                }
                Ok(_) => (),
                Err(err) => println!("Error: {}", err),
            }
        }
        Err(err) => println!("Error: {}", err),
    }

    // let sect = elf_file.find_section_by_name(".rodata.const2794").unwrap();
    // println!("{}", sect);
}

// TODO make this whole thing more library-like
fn main() {
    let mut args = env::args();
    let program_name = args.next();

    if let Some(binary_path) = args.next() {
        display_binary_information(binary_path);
    } else {
        println!("usage: {} <binary_path>", program_name.unwrap());
        process::exit(1);
    }
}
