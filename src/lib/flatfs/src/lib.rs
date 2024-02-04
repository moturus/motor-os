#![no_std]
extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub const PARTITION_ID: u8 = 0x2c;

pub struct Writer {
    files: BTreeMap<String, Vec<u8>>,
}

#[repr(C, align(8))]
struct FlatFsHeader {
    magic: u64,
    version: u64,
    len: u64,
    num_files: u64,
}

#[repr(C, align(8))]
struct EntryHeader {
    name_start: u64,
    name_len: u64,
    bytes_start: u64,
    bytes_len: u64,
    next_header: u64,
}

const MAGIC_V1: u64 = 0xf1a1_f1a1_f1a1_f1a1;

impl Writer {
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, filename: &str, bytes: &[u8]) {
        self.files.insert(filename.to_owned(), Vec::from(bytes));
    }

    pub fn pack(self) -> Vec<u8> {
        let mut result_size = core::mem::size_of::<FlatFsHeader>();
        for (key, value) in &self.files {
            result_size += core::mem::size_of::<EntryHeader>();
            result_size += key.len();
            result_size += value.len();

            result_size = (result_size + 7) & !7; // Align up.
        }

        let mut result = Vec::with_capacity(result_size);
        let result_size = result_size as u64;

        let fs_header = FlatFsHeader {
            magic: MAGIC_V1,
            version: 1,
            len: result_size,
            num_files: self.files.len() as u64,
        };

        let buf: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &fs_header as *const _ as usize as *const u8,
                core::mem::size_of::<FlatFsHeader>(),
            )
        };

        result.extend_from_slice(buf);

        for (key, value) in self.files {
            let curr_pos = result.len() as u64;
            let name_start = curr_pos + core::mem::size_of::<EntryHeader>() as u64;
            let name_len = key.len() as u64;
            let bytes_start = name_start + name_len;
            let bytes_len = value.len() as u64;

            let mut next_header = (bytes_start + bytes_len + 7) & !7;
            if next_header == result_size {
                next_header = 0;
            }
            assert!(next_header < result_size);

            let header = EntryHeader {
                name_start,
                name_len,
                bytes_start,
                bytes_len,
                next_header,
            };

            let buf: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    &header as *const _ as usize as *const u8,
                    core::mem::size_of::<EntryHeader>(),
                )
            };

            result.extend_from_slice(buf);
            result.extend_from_slice(key.as_bytes());
            result.extend_from_slice(&value);

            // align up
            while (result.len() & 7) != 0 {
                result.push(0);
            }
        }

        assert_eq!(result.len(), result_size as usize);

        result
    }
}

pub struct Dir<'a> {
    pub filename: &'a str, // The leaf filename.
    pub path: String,      // The full path.
    pub subdirs: BTreeMap<&'a str, Dir<'a>>,
    pub files: BTreeMap<&'a str, &'a [u8]>,
}

fn add_file<'a>(dir: &'_ mut Dir<'a>, name: &'a str, bytes: &'a [u8]) -> Result<(), ()> {
    let left_right = name.split_once('/');
    if left_right.is_none() {
        dir.files.insert(name, bytes);
        return Ok(());
    }

    let (left, right) = left_right.unwrap();
    if left.is_empty() {
        return add_file(dir, right, bytes);
    }

    if right.is_empty() {
        return Err(()); // We don't support empty directories.
    }

    let child: &mut Dir<'a> = if let Some(d) = dir.subdirs.get_mut(left) {
        d
    } else {
        let mut new_path = dir.path.clone();
        new_path.push('/');
        new_path.push_str(left);
        dir.subdirs.insert(
            left,
            Dir {
                filename: left,
                path: new_path,
                subdirs: BTreeMap::new(),
                files: BTreeMap::new(),
            },
        );
        dir.subdirs.get_mut(left).unwrap()
    };

    add_file(child, right, bytes)
}

/// Unpacks buf into a directory tree. buf MUST be aligned at 8 bytes.
pub fn unpack<'a>(buf: &'a [u8]) -> Result<Dir<'a>, ()> {
    if buf.len() < core::mem::size_of::<FlatFsHeader>() {
        return Err(());
    }

    if ((&buf[0] as *const _ as usize) & 7) != 0 {
        return Err(());
    }

    let fs_header: &FlatFsHeader = unsafe {
        (&buf[0] as *const _ as usize as *const FlatFsHeader)
            .as_ref()
            .unwrap()
    };

    if fs_header.magic != MAGIC_V1 {
        return Err(());
    }

    if fs_header.version != 1 {
        return Err(());
    }

    if (fs_header.len as usize) > buf.len() {
        return Err(());
    }

    let mut files: BTreeMap<&str, &[u8]> = BTreeMap::new();
    let mut num_files: u64 = 0;
    let mut curr_pos = core::mem::size_of::<FlatFsHeader>();

    while num_files < fs_header.num_files {
        assert_eq!(curr_pos & 7, 0);
        if curr_pos + core::mem::size_of::<EntryHeader>() > fs_header.len as usize {
            return Err(());
        }

        let header: &EntryHeader = unsafe {
            (&buf[curr_pos] as *const _ as usize as *const EntryHeader)
                .as_ref()
                .unwrap()
        };

        if (header.name_start + header.name_len) > fs_header.len {
            return Err(());
        }
        if (header.bytes_start + header.bytes_len) > fs_header.len {
            return Err(());
        }
        let name: &[u8] = unsafe {
            core::slice::from_raw_parts(&buf[header.name_start as usize], header.name_len as usize)
        };
        let name: &str = match core::str::from_utf8(name) {
            Ok(s) => s,
            Err(_) => return Err(()),
        };

        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &buf[header.bytes_start as usize],
                header.bytes_len as usize,
            )
        };

        files.insert(name, bytes);
        curr_pos = header.next_header as usize;

        num_files += 1;
    }
    assert_eq!(curr_pos, 0);

    if files.len() != fs_header.num_files as usize {
        return Err(()); // Duplicate files.
    }

    // Now parse files into a directory tree.
    let mut root_dir = Dir {
        filename: "",
        path: "".to_owned(),
        subdirs: BTreeMap::new(),
        files: BTreeMap::new(),
    };

    for (name, bytes) in &files {
        add_file(&mut root_dir, name, bytes)?;
    }

    Ok(root_dir)
}

#[test]
fn test() {
    let mut writer = Writer::new();

    writer.add("/foo", b"foo");
    writer.add("/foo/bar", b"bar");
    writer.add("/baz/baz", b"baz");

    let flat_fs = writer.pack();

    let root_dir = unpack(&flat_fs).unwrap();
    assert_eq!(root_dir.name, "/");

    assert_eq!(root_dir.files.len(), 1);
    assert_eq!(root_dir.files.get("foo").unwrap(), b"foo");

    let baz_dir = root_dir.subdirs.get("baz").unwrap();
    assert_eq!(baz_dir.files.get("baz").unwrap(), b"baz");
}
