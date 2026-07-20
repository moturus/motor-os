#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use flate2::bufread::GzDecoder;
use semver::Version;

use crate::atomic::AtomicDirectory;
use crate::config::PolicyLimits;
use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex};
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};

const BLOCK_BYTES: usize = 512;
const TAR_OVERHEAD_BYTES: u64 = 1024 * 1024;
const TAR_BYTES_PER_FILE: u64 = 4096;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_compressed_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_files: u64,
    pub max_path_bytes: usize,
    pub max_file_bytes: u64,
}

impl Limits {
    pub fn from_policy(policy: &PolicyLimits) -> Self {
        Self {
            max_compressed_bytes: policy.max_package_bytes,
            max_expanded_bytes: policy.max_extracted_package_bytes,
            max_files: policy.max_package_files,
            max_path_bytes: crate::source_tree::DEFAULT_LIMITS.max_path_bytes,
            max_file_bytes: policy.max_extracted_package_bytes,
        }
    }

    fn tree(self) -> Result<TreeLimits> {
        let max_entries = self
            .max_files
            .checked_mul(2)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| Error::failure("archive entry limit does not fit this platform"))?;
        Ok(TreeLimits {
            max_entries,
            max_path_bytes: self.max_path_bytes,
            max_file_bytes: self.max_file_bytes,
            max_tree_bytes: self.max_expanded_bytes,
        })
    }

    fn max_tar_bytes(self) -> Result<u64> {
        self.max_expanded_bytes
            .checked_add(
                self.max_files
                    .checked_mul(TAR_BYTES_PER_FILE)
                    .ok_or_else(|| Error::failure("archive stream limit overflowed"))?,
            )
            .and_then(|value| value.checked_add(TAR_OVERHEAD_BYTES))
            .ok_or_else(|| Error::failure("archive stream limit overflowed"))
    }
}

#[derive(Debug)]
pub struct ExtractedArchive {
    staging: AtomicDirectory,
    archive_root: String,
    tree: Tree,
}

impl ExtractedArchive {
    pub fn path(&self) -> &Path {
        self.staging.path()
    }

    pub fn archive_root(&self) -> &str {
        &self.archive_root
    }

    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    pub fn commit(self, destination: &Path) -> Result<Tree> {
        let Self { staging, tree, .. } = self;
        staging.commit(destination)?;
        Ok(tree)
    }
}

pub fn extract_crate(
    archive: &Path,
    expected_checksum: [u8; 32],
    staging_parent: &Path,
    name: &str,
    version: &Version,
    limits: Limits,
) -> Result<ExtractedArchive> {
    validate_root_component(name, "package name")?;
    let archive_root = format!("{name}-{version}");
    validate_root_component(&archive_root, "archive root")?;
    if archive_root.len() > limits.max_path_bytes {
        return Err(Error::failure(format!(
            "archive root `{archive_root}` exceeds the path-length limit"
        )));
    }

    let staging = AtomicDirectory::new(staging_parent, name)?;
    extract_gzip_tar(
        archive,
        expected_checksum,
        staging.path(),
        &archive_root,
        limits,
    )?;
    let tree = Tree::scan(staging.path(), limits.tree()?, Exclusions::None)?;
    Ok(ExtractedArchive {
        staging,
        archive_root,
        tree,
    })
}

fn extract_gzip_tar(
    archive: &Path,
    expected_checksum: [u8; 32],
    destination: &Path,
    archive_root: &str,
    limits: Limits,
) -> Result<()> {
    let metadata = fs::symlink_metadata(archive).map_err(|error| {
        Error::failure(format!(
            "failed to inspect crate archive `{}`: {error}",
            archive.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::failure(format!(
            "crate archive `{}` is not a real regular file",
            archive.display()
        )));
    }
    if metadata.len() > limits.max_compressed_bytes {
        return Err(Error::failure(format!(
            "crate archive `{}` exceeds the compressed-byte limit of {}",
            archive.display(),
            limits.max_compressed_bytes
        )));
    }

    let file = File::open(archive).map_err(|error| {
        Error::failure(format!(
            "failed to open crate archive `{}`: {error}",
            archive.display()
        ))
    })?;
    let opened = file.metadata().map_err(|error| {
        Error::failure(format!(
            "failed to inspect open crate archive `{}`: {error}",
            archive.display()
        ))
    })?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(Error::failure(format!(
            "crate archive `{}` changed while being opened",
            archive.display()
        )));
    }

    let limited = CompressedReader::new(file, limits.max_compressed_bytes);
    let mut compressed = BufReader::new(limited);
    {
        let decoder = GzDecoder::new(&mut compressed);
        let expanded = ExpandedReader::new(decoder, limits.max_tar_bytes()?);
        let mut reader = TarReader::new(expanded, destination, archive_root, limits);
        reader.extract().map_err(|error| {
            Error::failure(format!(
                "invalid crate archive `{}`: {error}",
                archive.display()
            ))
        })?;
        let mut expanded = reader.into_inner();
        let mut byte = [0_u8; 1];
        match expanded.read(&mut byte) {
            Ok(0) => {}
            Ok(_) => {
                return Err(Error::failure(format!(
                    "crate archive `{}` has nonzero tar data after its trailer",
                    archive.display()
                )));
            }
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to finish gzip stream `{}`: {error}",
                    archive.display()
                )));
            }
        }
    }

    let mut trailing = [0_u8; 1];
    match compressed.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(Error::failure(format!(
                "crate archive `{}` has trailing data or multiple gzip members",
                archive.display()
            )));
        }
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to finish compressed archive `{}`: {error}",
                archive.display()
            )));
        }
    }
    let compressed = compressed.into_inner();
    let (archive_bytes, checksum) = compressed.finish();
    if archive_bytes != opened.len() {
        return Err(Error::failure(format!(
            "crate archive `{}` changed while being read",
            archive.display()
        )));
    }
    if checksum != expected_checksum {
        return Err(Error::failure(format!(
            "crate archive `{}` checksum mismatch: expected {}, got {}",
            archive.display(),
            hex(&expected_checksum),
            hex(&checksum)
        )));
    }
    Ok(())
}

struct CompressedReader<R> {
    inner: R,
    remaining: u64,
    bytes_read: u64,
    hasher: Sha256,
}

impl<R> CompressedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
            bytes_read: 0,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> (u64, [u8; 32]) {
        (self.bytes_read, self.hasher.finish())
    }
}

impl<R: Read> Read for CompressedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut byte = [0_u8; 1];
            return match self.inner.read(&mut byte)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed-byte limit exceeded",
                )),
            };
        }
        let length = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..length])?;
        self.remaining -= read as u64;
        self.bytes_read += read as u64;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct ExpandedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> ExpandedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for ExpandedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut byte = [0_u8; 1];
            return match self.inner.read(&mut byte)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expanded tar stream exceeds its limit",
                )),
            };
        }
        let length = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..length])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Directory,
    File,
}

#[derive(Default)]
struct PendingExtensions {
    long_name: Option<String>,
    pax_path: Option<String>,
    pax_size: Option<u64>,
}

impl PendingExtensions {
    fn is_empty(&self) -> bool {
        self.long_name.is_none() && self.pax_path.is_none() && self.pax_size.is_none()
    }

    fn path(&self, header_path: String) -> Result<String> {
        if self.long_name.is_some() && self.pax_path.is_some() {
            return Err(Error::failure(
                "archive entry has conflicting GNU and PAX path records",
            ));
        }
        Ok(self
            .pax_path
            .clone()
            .or_else(|| self.long_name.clone())
            .unwrap_or(header_path))
    }
}

struct TarReader<'a, R> {
    input: R,
    destination: &'a Path,
    archive_root: &'a str,
    limits: Limits,
    entries: BTreeMap<String, EntryKind>,
    archive_entry_seen: bool,
    root_entry_seen: bool,
    file_count: u64,
    total_bytes: u64,
    pending: PendingExtensions,
}

impl<'a, R: Read> TarReader<'a, R> {
    fn new(input: R, destination: &'a Path, archive_root: &'a str, limits: Limits) -> Self {
        Self {
            input,
            destination,
            archive_root,
            limits,
            entries: BTreeMap::new(),
            archive_entry_seen: false,
            root_entry_seen: false,
            file_count: 0,
            total_bytes: 0,
            pending: PendingExtensions::default(),
        }
    }

    fn into_inner(self) -> R {
        self.input
    }

    fn extract(&mut self) -> Result<()> {
        loop {
            let header = self.read_block("tar header")?;
            if is_zero_block(&header) {
                let second = self.read_block("second tar trailer block")?;
                if !is_zero_block(&second) {
                    return Err(Error::failure("tar trailer contains only one zero block"));
                }
                self.consume_zero_trailer()?;
                break;
            }

            let header = Header::parse(&header)?;
            match header.type_flag {
                b'L' => self.read_long_name(header.size)?,
                b'x' => self.read_pax(header.size)?,
                b'g' => return Err(Error::failure("global PAX headers are unsupported")),
                b'\0' | b'0' | b'5' => self.extract_entry(header)?,
                b'1' | b'2' => {
                    return Err(Error::failure("archive links are unsupported and unsafe"));
                }
                b'3' | b'4' | b'6' | b'7' | b'S' => {
                    return Err(Error::failure(
                        "archive special or sparse entries are unsupported",
                    ));
                }
                flag => {
                    return Err(Error::failure(format!(
                        "unsupported tar type flag 0x{flag:02x}"
                    )));
                }
            }
        }

        if !self.pending.is_empty() {
            return Err(Error::failure(
                "archive ends before an extension record's entry",
            ));
        }
        if !self.archive_entry_seen {
            return Err(Error::failure(format!(
                "archive contains no entries beneath its `{}/` root",
                self.archive_root
            )));
        }
        Ok(())
    }

    fn extract_entry(&mut self, header: Header) -> Result<()> {
        let path = self.pending.path(header.path)?;
        let size = self.pending.pax_size.unwrap_or(header.size);
        self.pending = PendingExtensions::default();
        let relative = validate_archive_path(&path, self.archive_root, self.limits.max_path_bytes)?;
        let kind = if header.type_flag == b'5' {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        self.archive_entry_seen = true;

        if relative.is_empty() {
            if kind != EntryKind::Directory || size != 0 {
                return Err(Error::failure("archive root is not an empty directory"));
            }
            if self.root_entry_seen {
                return Err(Error::failure("archive contains a duplicate root entry"));
            }
            self.root_entry_seen = true;
            return Ok(());
        }
        if self.entries.insert(relative.clone(), kind).is_some() {
            return Err(Error::failure(format!(
                "duplicate archive entry `{relative}`"
            )));
        }
        let max_entries = self
            .limits
            .max_files
            .checked_mul(2)
            .ok_or_else(|| Error::failure("archive entry limit overflowed"))?;
        if self.entries.len() as u64 > max_entries {
            return Err(Error::failure("archive exceeds the entry-count limit"));
        }

        let parent = relative.rsplit_once('/').map_or("", |(parent, _)| parent);
        ensure_real_directories(self.destination, parent)?;
        let output = join_portable(self.destination, &relative);
        match kind {
            EntryKind::Directory => {
                if size != 0 {
                    return Err(Error::failure(format!(
                        "archive directory `{relative}` has nonzero contents"
                    )));
                }
                create_or_validate_directory(&output, &relative)?;
            }
            EntryKind::File => self.extract_file(&output, &relative, size, header.mode)?,
        }
        Ok(())
    }

    fn extract_file(&mut self, output: &Path, relative: &str, size: u64, mode: u64) -> Result<()> {
        if size > self.limits.max_file_bytes {
            return Err(Error::failure(format!(
                "archive file `{relative}` exceeds the per-file limit"
            )));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(size)
            .ok_or_else(|| Error::failure("archive extracted-byte count overflowed"))?;
        if self.total_bytes > self.limits.max_expanded_bytes {
            return Err(Error::failure("archive exceeds the extracted-byte limit"));
        }
        self.file_count += 1;
        if self.file_count > self.limits.max_files {
            return Err(Error::failure("archive exceeds the file-count limit"));
        }

        revalidate_parent_chain(self.destination, relative)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to create extracted file `{}` exclusively: {error}",
                    output.display()
                ))
            })?;
        copy_exact(&mut self.input, &mut file, size, relative)?;
        file.flush()
            .and_then(|()| file.sync_all())
            .map_err(|error| {
                Error::failure(format!(
                    "failed to persist extracted file `{}`: {error}",
                    output.display()
                ))
        })?;
        set_file_mode(&file, output, mode & 0o111 != 0)?;
        file.sync_all().map_err(|error| {
            Error::failure(format!(
                "failed to persist extracted file permissions `{}`: {error}",
                output.display()
            ))
        })?;
        revalidate_parent_chain(self.destination, relative)?;
        let metadata = fs::symlink_metadata(output).map_err(|error| {
            Error::failure(format!(
                "failed to revalidate extracted file `{}`: {error}",
                output.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != size {
            return Err(Error::failure(format!(
                "extracted file `{}` changed during extraction",
                output.display()
            )));
        }
        self.consume_padding(size, relative)
    }

    fn read_long_name(&mut self, size: u64) -> Result<()> {
        if !self.pending.is_empty() {
            return Err(Error::failure(
                "GNU long-name record conflicts with another extension record",
            ));
        }
        let maximum = self
            .limits
            .max_path_bytes
            .checked_add(self.archive_root.len())
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| Error::failure("archive path limit overflowed"))?;
        let data = self.read_extension(size, maximum, "GNU long-name")?;
        let nul = data.iter().position(|byte| *byte == 0).ok_or_else(|| {
            Error::failure("GNU long-name record is not terminated by a NUL byte")
        })?;
        if data[nul + 1..].iter().any(|byte| *byte != 0) {
            return Err(Error::failure(
                "GNU long-name record has nonzero bytes after its terminator",
            ));
        }
        let name = std::str::from_utf8(&data[..nul])
            .map_err(|_| Error::failure("GNU long-name record is not UTF-8"))?;
        if name.is_empty() {
            return Err(Error::failure("GNU long-name record is empty"));
        }
        self.pending.long_name = Some(name.to_owned());
        Ok(())
    }

    fn read_pax(&mut self, size: u64) -> Result<()> {
        if !self.pending.is_empty() {
            return Err(Error::failure(
                "PAX record conflicts with another extension record",
            ));
        }
        let maximum = self
            .limits
            .max_path_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(4096))
            .ok_or_else(|| Error::failure("PAX record limit overflowed"))?;
        let data = self.read_extension(size, maximum, "PAX")?;
        self.pending = parse_pax(&data)?;
        Ok(())
    }

    fn read_extension(&mut self, size: u64, maximum: usize, context: &str) -> Result<Vec<u8>> {
        let size = usize::try_from(size)
            .map_err(|_| Error::failure(format!("{context} record is too large")))?;
        if size == 0 || size > maximum {
            return Err(Error::failure(format!(
                "{context} record exceeds its size limit"
            )));
        }
        let mut data = vec![0_u8; size];
        read_exact_context(&mut self.input, &mut data, context)?;
        self.consume_padding(size as u64, context)?;
        Ok(data)
    }

    fn consume_padding(&mut self, size: u64, context: &str) -> Result<()> {
        let padding = (BLOCK_BYTES as u64 - size % BLOCK_BYTES as u64) % BLOCK_BYTES as u64;
        if padding == 0 {
            return Ok(());
        }
        let mut bytes = [0_u8; BLOCK_BYTES];
        read_exact_context(
            &mut self.input,
            &mut bytes[..padding as usize],
            "tar entry padding",
        )?;
        if bytes[..padding as usize].iter().any(|byte| *byte != 0) {
            return Err(Error::failure(format!(
                "archive entry `{context}` has nonzero padding"
            )));
        }
        Ok(())
    }

    fn read_block(&mut self, context: &str) -> Result<[u8; BLOCK_BYTES]> {
        let mut block = [0_u8; BLOCK_BYTES];
        read_exact_context(&mut self.input, &mut block, context)?;
        Ok(block)
    }

    fn consume_zero_trailer(&mut self) -> Result<()> {
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            let read = self
                .input
                .read(&mut buffer)
                .map_err(|error| Error::failure(format!("failed to read tar trailer: {error}")))?;
            if read == 0 {
                return Ok(());
            }
            if buffer[..read].iter().any(|byte| *byte != 0) {
                return Err(Error::failure("tar archive has nonzero trailing data"));
            }
        }
    }
}

struct Header {
    path: String,
    mode: u64,
    size: u64,
    type_flag: u8,
}

impl Header {
    fn parse(block: &[u8; BLOCK_BYTES]) -> Result<Self> {
        validate_checksum(block)?;
        let mode = parse_octal(&block[100..108], "mode", false)?;
        parse_octal(&block[108..116], "owner", true)?;
        parse_octal(&block[116..124], "group", true)?;
        let size = parse_octal(&block[124..136], "size", true)?;
        parse_octal(&block[136..148], "modification time", true)?;

        let magic = &block[257..263];
        let v7 = magic.iter().all(|byte| *byte == 0);
        let ustar = magic == b"ustar\0" || magic == b"ustar ";
        if !v7 && !ustar {
            return Err(Error::failure("unsupported tar header magic"));
        }
        if ustar {
            parse_octal(&block[329..337], "device major", true)?;
            parse_octal(&block[337..345], "device minor", true)?;
        }

        let name = parse_tar_string(&block[..100], "entry name")?;
        let prefix = if ustar {
            parse_tar_string(&block[345..500], "ustar prefix")?
        } else {
            String::new()
        };
        let path = match (prefix.is_empty(), name.is_empty()) {
            (true, false) => name,
            (false, false) => format!("{prefix}/{name}"),
            (false, true) => prefix,
            (true, true) => return Err(Error::failure("tar header has an empty path")),
        };
        Ok(Self {
            path,
            mode,
            size,
            type_flag: block[156],
        })
    }
}

fn validate_checksum(block: &[u8; BLOCK_BYTES]) -> Result<()> {
    let expected = parse_octal(&block[148..156], "checksum", false)?;
    let actual = block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as u64
            } else {
                *byte as u64
            }
        })
        .sum::<u64>();
    if expected != actual {
        return Err(Error::failure(format!(
            "tar header checksum mismatch: expected {expected}, computed {actual}"
        )));
    }
    Ok(())
}

fn parse_octal(field: &[u8], name: &str, empty_is_zero: bool) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(Error::failure(format!(
            "base-256 tar {name} is unsupported"
        )));
    }
    let mut start = 0;
    while start < field.len() && matches!(field[start], 0 | b' ') {
        start += 1;
    }
    let mut end = start;
    while end < field.len() && (b'0'..=b'7').contains(&field[end]) {
        end += 1;
    }
    if start == end {
        if empty_is_zero && field.iter().all(|byte| matches!(*byte, 0 | b' ')) {
            return Ok(0);
        }
        return Err(Error::failure(format!("tar {name} is not octal")));
    }
    if field[end..].iter().any(|byte| !matches!(*byte, 0 | b' ')) {
        return Err(Error::failure(format!(
            "tar {name} has invalid trailing bytes"
        )));
    }
    field[start..end].iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add((byte - b'0') as u64))
            .ok_or_else(|| Error::failure(format!("tar {name} overflowed")))
    })
}

fn parse_tar_string(field: &[u8], name: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if end < field.len() && field[end + 1..].iter().any(|byte| *byte != 0) {
        return Err(Error::failure(format!(
            "tar {name} has nonzero bytes after its terminator"
        )));
    }
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .map_err(|_| Error::failure(format!("tar {name} is not UTF-8")))
}

fn parse_pax(data: &[u8]) -> Result<PendingExtensions> {
    let mut pending = PendingExtensions::default();
    let mut offset = 0;
    while offset < data.len() {
        let space = data[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|relative| offset + relative)
            .ok_or_else(|| Error::failure("malformed PAX record length"))?;
        let length_text = std::str::from_utf8(&data[offset..space])
            .map_err(|_| Error::failure("PAX record length is not ASCII"))?;
        if length_text.is_empty()
            || (length_text.len() > 1 && length_text.starts_with('0'))
            || !length_text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Error::failure("PAX record has a non-canonical length"));
        }
        let length = length_text
            .parse::<usize>()
            .map_err(|_| Error::failure("PAX record length overflowed"))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| Error::failure("truncated PAX record"))?;
        if space + 1 >= end || data[end - 1] != b'\n' {
            return Err(Error::failure("malformed PAX record framing"));
        }
        let record = &data[space + 1..end - 1];
        let equals = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| Error::failure("PAX record has no value separator"))?;
        let key = std::str::from_utf8(&record[..equals])
            .map_err(|_| Error::failure("PAX key is not UTF-8"))?;
        let value = std::str::from_utf8(&record[equals + 1..])
            .map_err(|_| Error::failure("PAX value is not UTF-8"))?;
        match key {
            "path" => {
                if pending.pax_path.replace(value.to_owned()).is_some() {
                    return Err(Error::failure("duplicate PAX path key"));
                }
            }
            "size" => {
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(Error::failure("PAX size is not canonical decimal"));
                }
                let size = value
                    .parse::<u64>()
                    .map_err(|_| Error::failure("PAX size overflowed"))?;
                if pending.pax_size.replace(size).is_some() {
                    return Err(Error::failure("duplicate PAX size key"));
                }
            }
            _ => {
                return Err(Error::failure(format!("unsupported PAX key `{key}`")));
            }
        }
        offset = end;
    }
    if pending.is_empty() {
        return Err(Error::failure("PAX record contains no supported keys"));
    }
    Ok(pending)
}

fn validate_archive_path(path: &str, root: &str, max_path_bytes: usize) -> Result<String> {
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.as_bytes().contains(&b'\\')
        || path.as_bytes().contains(&0)
        || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(Error::failure(format!("unsafe archive path `{path}`")));
    }
    let mut components = path.split('/');
    if components
        .clone()
        .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(Error::failure(format!("unsafe archive path `{path}`")));
    }
    if components.next() != Some(root) {
        return Err(Error::failure(format!(
            "archive entry `{path}` is outside the required `{root}/` root"
        )));
    }
    let relative = components.collect::<Vec<_>>().join("/");
    if relative.len() > max_path_bytes {
        return Err(Error::failure(format!(
            "extracted path `{relative}` exceeds the path-length limit"
        )));
    }
    Ok(relative)
}

fn validate_root_component(value: &str, context: &str) -> Result<()> {
    if value.is_empty()
        || value.as_bytes().contains(&b'/')
        || value.as_bytes().contains(&b'\\')
        || value.as_bytes().contains(&0)
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || matches!(value, "." | "..")
    {
        return Err(Error::failure(format!("invalid {context} `{value}`")));
    }
    Ok(())
}

fn join_portable(root: &Path, relative: &str) -> PathBuf {
    let mut result = root.to_owned();
    for component in relative.split('/') {
        result.push(component);
    }
    result
}

fn ensure_real_directories(root: &Path, relative: &str) -> Result<()> {
    let mut current = root.to_owned();
    require_real_directory(&current)?;
    if relative.is_empty() {
        return Ok(());
    }
    for component in relative.split('/') {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => set_directory_private(&current)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                require_real_directory(&current)?;
            }
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to create archive directory `{}`: {error}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn create_or_validate_directory(path: &Path, relative: &str) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_directory_private(path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => require_real_directory(path)
            .map_err(|_| Error::failure(format!("conflicting archive entry `{relative}`"))),
        Err(error) => Err(Error::failure(format!(
            "failed to create archive directory `{}`: {error}",
            path.display()
        ))),
    }
}

fn revalidate_parent_chain(root: &Path, relative: &str) -> Result<()> {
    require_real_directory(root)?;
    let mut current = root.to_owned();
    if let Some((parent, _)) = relative.rsplit_once('/') {
        for component in parent.split('/') {
            current.push(component);
            require_real_directory(&current)?;
        }
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect archive directory `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "archive parent `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn copy_exact(input: &mut impl Read, output: &mut File, size: u64, path: &str) -> Result<()> {
    let mut remaining = size;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining != 0 {
        let wanted = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = input.read(&mut buffer[..wanted]).map_err(|error| {
            Error::failure(format!("failed to read archive file `{path}`: {error}"))
        })?;
        if read == 0 {
            return Err(Error::failure(format!(
                "archive file `{path}` is truncated"
            )));
        }
        output.write_all(&buffer[..read]).map_err(|error| {
            Error::failure(format!("failed to write extracted file `{path}`: {error}"))
        })?;
        remaining -= read as u64;
    }
    Ok(())
}

fn read_exact_context(input: &mut impl Read, buffer: &mut [u8], context: &str) -> Result<()> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::failure(format!("truncated {context}"))
        } else {
            Error::failure(format!("failed to read {context}: {error}"))
        }
    })
}

fn is_zero_block(block: &[u8; BLOCK_BYTES]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn set_directory_private(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Error::failure(format!(
                "failed to set archive directory permissions `{}`: {error}",
                _path.display()
            ))
        })?;
    }
    #[cfg(target_os = "motor")]
    {
        let path = _path.to_str().ok_or_else(|| {
            Error::failure(format!(
                "archive directory path is not UTF-8: `{}`",
                _path.display()
            ))
        })?;
        moto_rt::fs::set_perm(
            path,
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC,
        )
        .map_err(|error| {
            Error::failure(format!(
                "failed to set archive directory permissions `{}`: {error}",
                _path.display()
            ))
        })?;
    }
    Ok(())
}

fn set_file_mode(_file: &File, _path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o700 } else { 0o600 };
        _file
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| {
                Error::failure(format!(
                    "failed to set extracted file permissions `{}`: {error}",
                    _path.display()
                ))
            })?;
    }
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;
        let mut permissions = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE;
        if executable {
            permissions |= moto_rt::fs::PERM_EXEC;
        }
        moto_rt::fs::set_file_perm(_file.as_raw_fd(), permissions).map_err(|error| {
            Error::failure(format!(
                "failed to set extracted file permissions `{}`: {error}",
                _path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lorry-archive-{label}-{}-{time:x}-{sequence:x}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy)]
    enum Format {
        V7,
        Ustar,
        Gnu,
    }

    fn test_limits() -> Limits {
        Limits {
            max_compressed_bytes: 1024 * 1024,
            max_expanded_bytes: 1024 * 1024,
            max_files: 100,
            max_path_bytes: 256,
            max_file_bytes: 1024 * 1024,
        }
    }

    fn put_string(field: &mut [u8], value: &str) {
        assert!(value.len() <= field.len());
        field[..value.len()].copy_from_slice(value.as_bytes());
    }

    fn put_octal(field: &mut [u8], value: u64) {
        let text = format!("{value:0width$o}", width = field.len() - 1);
        assert_eq!(text.len(), field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
        field[text.len()] = 0;
    }

    fn header(
        name: &str,
        prefix: &str,
        type_flag: u8,
        size: u64,
        mode: u64,
        format: Format,
    ) -> [u8; BLOCK_BYTES] {
        let mut block = [0_u8; BLOCK_BYTES];
        put_string(&mut block[..100], name);
        put_octal(&mut block[100..108], mode);
        put_octal(&mut block[108..116], 0);
        put_octal(&mut block[116..124], 0);
        put_octal(&mut block[124..136], size);
        put_octal(&mut block[136..148], 0);
        block[148..156].fill(b' ');
        block[156] = type_flag;
        match format {
            Format::V7 => {}
            Format::Ustar => {
                block[257..263].copy_from_slice(b"ustar\0");
                block[263..265].copy_from_slice(b"00");
                put_string(&mut block[345..500], prefix);
            }
            Format::Gnu => {
                block[257..263].copy_from_slice(b"ustar ");
                block[263..265].copy_from_slice(b" \0");
                put_string(&mut block[345..500], prefix);
            }
        }
        let checksum = block.iter().map(|byte| *byte as u64).sum::<u64>();
        let checksum = format!("{checksum:06o}\0 ");
        block[148..156].copy_from_slice(checksum.as_bytes());
        block
    }

    #[allow(clippy::too_many_arguments)]
    fn append_entry(
        tar: &mut Vec<u8>,
        name: &str,
        prefix: &str,
        type_flag: u8,
        declared_size: u64,
        contents: &[u8],
        mode: u64,
        format: Format,
    ) {
        tar.extend_from_slice(&header(
            name,
            prefix,
            type_flag,
            declared_size,
            mode,
            format,
        ));
        tar.extend_from_slice(contents);
        tar.resize(
            tar.len() + (BLOCK_BYTES - contents.len() % BLOCK_BYTES) % BLOCK_BYTES,
            0,
        );
    }

    fn append_file(tar: &mut Vec<u8>, path: &str, contents: &[u8], mode: u64) {
        append_entry(
            tar,
            path,
            "",
            b'0',
            contents.len() as u64,
            contents,
            mode,
            Format::Ustar,
        );
    }

    fn finish_tar(tar: &mut Vec<u8>) {
        tar.resize(tar.len() + BLOCK_BYTES * 2, 0);
    }

    fn minimal_tar() -> Vec<u8> {
        let mut tar = Vec::new();
        append_entry(
            &mut tar,
            "demo-1.2.3/",
            "",
            b'5',
            0,
            b"",
            0o755,
            Format::Ustar,
        );
        append_file(&mut tar, "demo-1.2.3/Cargo.toml", b"[package]\n", 0o644);
        finish_tar(&mut tar);
        tar
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn write_gzip(root: &Path, label: &str, tar: &[u8]) -> PathBuf {
        let path = root.join(format!("{label}.crate"));
        fs::write(&path, gzip(tar)).unwrap();
        path
    }

    fn extract_test(
        archive: &Path,
        staging_parent: &Path,
        name: &str,
        version: &Version,
        limits: Limits,
    ) -> Result<ExtractedArchive> {
        let bytes = fs::read(archive).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        extract_crate(
            archive,
            hasher.finish(),
            staging_parent,
            name,
            version,
            limits,
        )
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!("{key}={value}\n");
        let mut digits = 1;
        loop {
            let length = digits + 1 + body.len();
            let actual_digits = length.to_string().len();
            if actual_digits == digits {
                return format!("{length} {body}").into_bytes();
            }
            digits = actual_digits;
        }
    }

    #[test]
    fn extracts_v7_ustar_gnu_and_pax_entries() {
        let root = TempRoot::new("formats");
        let mut tar = Vec::new();
        append_entry(
            &mut tar,
            "demo-1.2.3/",
            "",
            b'5',
            0,
            b"",
            0o755,
            Format::Ustar,
        );
        append_entry(
            &mut tar,
            "Cargo.toml",
            "demo-1.2.3",
            b'0',
            10,
            b"[package]\n",
            0o644,
            Format::Ustar,
        );
        append_entry(
            &mut tar,
            "demo-1.2.3/src/",
            "",
            b'5',
            0,
            b"",
            0o755,
            Format::V7,
        );
        append_entry(
            &mut tar,
            "main.rs",
            "demo-1.2.3/src",
            b'0',
            13,
            b"fn main() {}\n",
            0o755,
            Format::Ustar,
        );

        let long_leaf = format!("{}.txt", "long".repeat(28));
        let long_path = format!("demo-1.2.3/src/{long_leaf}");
        let mut long_record = long_path.as_bytes().to_vec();
        long_record.push(0);
        append_entry(
            &mut tar,
            "././@LongLink",
            "",
            b'L',
            long_record.len() as u64,
            &long_record,
            0,
            Format::Gnu,
        );
        append_entry(
            &mut tar,
            "ignored",
            "",
            b'0',
            4,
            b"long",
            0o644,
            Format::Gnu,
        );

        let pax_path = format!("demo-1.2.3/src/{}.txt", "pax".repeat(35));
        let mut pax = pax_record("path", &pax_path);
        pax.extend_from_slice(&pax_record("size", "3"));
        append_entry(
            &mut tar,
            "PaxHeader",
            "",
            b'x',
            pax.len() as u64,
            &pax,
            0,
            Format::Ustar,
        );
        append_entry(
            &mut tar,
            "placeholder",
            "",
            b'0',
            0,
            b"pax",
            0o644,
            Format::Ustar,
        );
        finish_tar(&mut tar);

        let archive = write_gzip(&root.0, "formats", &tar);
        let extracted = extract_test(
            &archive,
            &root.0,
            "demo",
            &Version::parse("1.2.3").unwrap(),
            test_limits(),
        )
        .unwrap();
        assert_eq!(
            fs::read(extracted.path().join("Cargo.toml")).unwrap(),
            b"[package]\n"
        );
        assert_eq!(
            fs::read(extracted.path().join("src/main.rs")).unwrap(),
            b"fn main() {}\n"
        );
        assert_eq!(
            fs::read(extracted.path().join("src").join(long_leaf)).unwrap(),
            b"long"
        );
        assert_eq!(
            fs::read(
                extracted
                    .path()
                    .join(pax_path.strip_prefix("demo-1.2.3/").unwrap())
            )
            .unwrap(),
            b"pax"
        );
        let executable = extracted
            .tree()
            .entries
            .iter()
            .find(|entry| entry.path == "src/main.rs")
            .unwrap();
        assert!(executable.executable);
        assert_eq!(extracted.archive_root(), "demo-1.2.3");
    }

    #[test]
    fn accepts_an_implied_single_archive_root() {
        let root = TempRoot::new("implied-root");
        let mut tar = Vec::new();
        append_file(&mut tar, "demo-1.2.3/Cargo.toml", b"[package]\n", 0o644);
        finish_tar(&mut tar);
        let archive = write_gzip(&root.0, "implied-root", &tar);
        let extracted = extract_test(
            &archive,
            &root.0,
            "demo",
            &Version::parse("1.2.3").unwrap(),
            test_limits(),
        )
        .unwrap();
        assert_eq!(
            fs::read(extracted.path().join("Cargo.toml")).unwrap(),
            b"[package]\n"
        );
    }

    #[test]
    fn rejects_bad_checksum_truncation_and_nonzero_padding_or_trailer() {
        let root = TempRoot::new("framing");
        let version = Version::parse("1.2.3").unwrap();

        let mut bad_checksum = minimal_tar();
        bad_checksum[0] ^= 1;
        let path = write_gzip(&root.0, "checksum", &bad_checksum);
        assert!(
            extract_test(&path, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("checksum")
        );

        let mut truncated = minimal_tar();
        truncated.truncate(truncated.len() - BLOCK_BYTES - 1);
        let path = write_gzip(&root.0, "truncated", &truncated);
        assert!(extract_test(&path, &root.0, "demo", &version, test_limits()).is_err());

        let mut padding = Vec::new();
        append_entry(
            &mut padding,
            "demo-1.2.3/",
            "",
            b'5',
            0,
            b"",
            0o755,
            Format::Ustar,
        );
        append_file(&mut padding, "demo-1.2.3/x", b"x", 0o644);
        let padding_offset = BLOCK_BYTES * 2 + 1;
        padding[padding_offset] = 1;
        finish_tar(&mut padding);
        let path = write_gzip(&root.0, "padding", &padding);
        assert!(
            extract_test(&path, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("padding")
        );

        let mut trailer = minimal_tar();
        trailer.push(1);
        let path = write_gzip(&root.0, "trailer", &trailer);
        assert!(
            extract_test(&path, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("trailing")
        );
    }

    #[test]
    fn accepts_exactly_one_complete_gzip_member() {
        let root = TempRoot::new("gzip");
        let version = Version::parse("1.2.3").unwrap();
        let tar = minimal_tar();

        let valid = write_gzip(&root.0, "valid", &tar);
        extract_test(&valid, &root.0, "demo", &version, test_limits()).unwrap();
        assert!(
            extract_crate(&valid, [0_u8; 32], &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("checksum mismatch")
        );

        let mut trailing = gzip(&tar);
        trailing.extend_from_slice(b"junk");
        let trailing_path = root.0.join("trailing.crate");
        fs::write(&trailing_path, trailing).unwrap();
        assert!(
            extract_test(&trailing_path, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("trailing data")
        );

        let mut concatenated = gzip(&tar);
        concatenated.extend_from_slice(&gzip(&tar));
        let concatenated_path = root.0.join("concatenated.crate");
        fs::write(&concatenated_path, concatenated).unwrap();
        assert!(
            extract_test(&concatenated_path, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("multiple gzip members")
        );

        let mut damaged = gzip(&tar);
        damaged.pop();
        let damaged_path = root.0.join("damaged.crate");
        fs::write(&damaged_path, damaged).unwrap();
        assert!(extract_test(&damaged_path, &root.0, "demo", &version, test_limits()).is_err());
    }

    #[test]
    fn rejects_traversal_links_duplicates_and_unknown_pax() {
        type MaliciousCase = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);

        let version = Version::parse("1.2.3").unwrap();
        let cases: [MaliciousCase; 5] = [
            (
                "unsafe archive path",
                Box::new(|tar| append_file(tar, "demo-1.2.3/../escape", b"x", 0o644)),
            ),
            (
                "links",
                Box::new(|tar| {
                    append_entry(
                        tar,
                        "demo-1.2.3/link",
                        "",
                        b'2',
                        0,
                        b"",
                        0o777,
                        Format::Ustar,
                    )
                }),
            ),
            (
                "duplicate archive entry",
                Box::new(|tar| append_file(tar, "demo-1.2.3/Cargo.toml", b"x", 0o644)),
            ),
            (
                "unsupported PAX key",
                Box::new(|tar| {
                    let pax = pax_record("mtime", "1");
                    append_entry(
                        tar,
                        "PaxHeader",
                        "",
                        b'x',
                        pax.len() as u64,
                        &pax,
                        0,
                        Format::Ustar,
                    )
                }),
            ),
            (
                "global PAX",
                Box::new(|tar| append_entry(tar, "GlobalHead", "", b'g', 0, b"", 0, Format::Ustar)),
            ),
        ];

        for (expected, add_malicious) in cases {
            let root = TempRoot::new("unsafe");
            let mut tar = minimal_tar();
            tar.truncate(tar.len() - BLOCK_BYTES * 2);
            add_malicious(&mut tar);
            finish_tar(&mut tar);
            let archive = write_gzip(&root.0, "unsafe", &tar);
            let error = extract_test(&archive, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
            assert!(!root.0.join("escape").exists());
        }
    }

    #[test]
    fn rejects_malformed_extensions_special_entries_and_path_conflicts() {
        type MaliciousCase = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);

        let version = Version::parse("1.2.3").unwrap();
        let cases: [MaliciousCase; 6] = [
            (
                "not terminated",
                Box::new(|tar| {
                    append_entry(
                        tar,
                        "././@LongLink",
                        "",
                        b'L',
                        12,
                        b"unterminated",
                        0,
                        Format::Gnu,
                    )
                }),
            ),
            (
                "truncated PAX",
                Box::new(|tar| {
                    append_entry(
                        tar,
                        "PaxHeader",
                        "",
                        b'x',
                        10,
                        b"99 path=x\n",
                        0,
                        Format::Ustar,
                    )
                }),
            ),
            (
                "special or sparse",
                Box::new(|tar| {
                    append_entry(tar, "demo-1.2.3/sparse", "", b'S', 0, b"", 0, Format::Gnu)
                }),
            ),
            (
                "unsupported tar type",
                Box::new(|tar| {
                    append_entry(
                        tar,
                        "demo-1.2.3/unknown",
                        "",
                        b'Z',
                        0,
                        b"",
                        0,
                        Format::Ustar,
                    )
                }),
            ),
            (
                "unsafe archive path",
                Box::new(|tar| append_file(tar, "/demo-1.2.3/absolute", b"x", 0o644)),
            ),
            (
                "not a real directory",
                Box::new(|tar| {
                    append_file(tar, "demo-1.2.3/parent", b"x", 0o644);
                    append_file(tar, "demo-1.2.3/parent/child", b"x", 0o644);
                }),
            ),
        ];

        for (expected, add_malicious) in cases {
            let root = TempRoot::new("malformed");
            let mut tar = minimal_tar();
            tar.truncate(tar.len() - BLOCK_BYTES * 2);
            add_malicious(&mut tar);
            finish_tar(&mut tar);
            let archive = write_gzip(&root.0, "malformed", &tar);
            let error = extract_test(&archive, &root.0, "demo", &version, test_limits())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn enforces_root_path_file_count_and_byte_limits() {
        let version = Version::parse("1.2.3").unwrap();
        let root = TempRoot::new("limits");
        let archive = write_gzip(&root.0, "limits", &minimal_tar());

        for limits in [
            Limits {
                max_compressed_bytes: 1,
                ..test_limits()
            },
            Limits {
                max_expanded_bytes: 1,
                ..test_limits()
            },
            Limits {
                max_file_bytes: 1,
                ..test_limits()
            },
            Limits {
                max_files: 0,
                ..test_limits()
            },
            Limits {
                max_path_bytes: 2,
                ..test_limits()
            },
        ] {
            assert!(extract_test(&archive, &root.0, "demo", &version, limits).is_err());
        }

        assert!(
            extract_test(&archive, &root.0, "different", &version, test_limits())
                .unwrap_err()
                .to_string()
                .contains("outside the required")
        );

        let mut reader = ExpandedReader::new(Cursor::new(vec![0_u8; 5]), 4);
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parent_revalidation_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = TempRoot::new("race");
        let destination = root.0.join("destination");
        let outside = root.0.join("outside");
        fs::create_dir(&destination).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, destination.join("redirect")).unwrap();
        let error = ensure_real_directories(&destination, "redirect/child")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a real directory"));
        assert!(!outside.join("child").exists());
    }

    #[test]
    fn extracts_every_retained_stage_two_archive_when_requested() {
        let Some(repository) = std::env::var_os("LORRY_TEST_SEEDED_REPOSITORY") else {
            return;
        };
        let repository = PathBuf::from(repository);
        let objects = repository.join("objects/crates-io/sha256");
        let output = TempRoot::new("real-seed");
        let mut checked = 0;

        for prefix in fs::read_dir(objects).unwrap() {
            for object in fs::read_dir(prefix.unwrap().path()).unwrap() {
                let object = object.unwrap().path();
                let document = fs::read_to_string(object.join("package.toml"))
                    .unwrap()
                    .parse::<toml_edit::DocumentMut>()
                    .unwrap();
                if document["retained-archive"].as_bool() != Some(true)
                    || document["retained-source"].as_bool() != Some(true)
                {
                    continue;
                }
                let name = document["name"].as_str().unwrap();
                let version = Version::parse(document["version"].as_str().unwrap()).unwrap();
                let checksum =
                    crate::hash::decode_hex(document["checksum"].as_str().unwrap()).unwrap();
                let extracted = extract_crate(
                    &object.join("package.crate"),
                    checksum,
                    &output.0,
                    name,
                    &version,
                    Limits {
                        max_compressed_bytes: 16 * 1024 * 1024,
                        max_expanded_bytes: 128 * 1024 * 1024,
                        max_files: 20_000,
                        max_path_bytes: 4096,
                        max_file_bytes: 128 * 1024 * 1024,
                    },
                )
                .unwrap_or_else(|error| panic!("failed to extract {}: {error}", object.display()));
                let retained = Tree::scan(
                    &object.join("source"),
                    Limits {
                        max_compressed_bytes: 16 * 1024 * 1024,
                        max_expanded_bytes: 128 * 1024 * 1024,
                        max_files: 20_000,
                        max_path_bytes: 4096,
                        max_file_bytes: 128 * 1024 * 1024,
                    }
                    .tree()
                    .unwrap(),
                    Exclusions::None,
                );
                let retained = retained.unwrap_or_else(|error| {
                    panic!(
                        "failed to scan retained source {}: {error}",
                        object.display()
                    )
                });
                assert_eq!(extracted.tree(), &retained, "{}", object.display());
                checked += 1;
            }
        }
        assert!(checked > 0);
    }
}
