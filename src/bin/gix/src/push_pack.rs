use std::{
    fs::File,
    io::{self, BufWriter, Read, Seek, Write},
    path::Path,
};

use crate::{cancellation::Cancellation, object_database::Reader, push_objects::Selection};

const MAX_PACK_BYTES: u64 = 128 * 1024 * 1024;
const WRITER_BUFFER_BYTES: usize = 64 * 1024;
const SHA1_BYTES: usize = 20;

type Tempfile = gix::tempfile::Handle<gix::tempfile::handle::Writable>;

/// A complete, verified pack whose owned tempfile is removed on drop.
pub struct FinishedPack {
    file: Tempfile,
    length: u64,
    object_count: u32,
}

/// A read-only view that retains cleanup ownership of a finished pack.
pub struct PackReader {
    reader: File,
    _guard: Tempfile,
}

impl Read for PackReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reader.read(bytes)
    }
}

impl FinishedPack {
    /// Consume this pack into its sole read-only descriptor and cleanup guard.
    pub fn into_reader(mut self) -> io::Result<(PackReader, u64)> {
        let mut reader = self.file.with_mut(|file| file.as_file().try_clone())??;
        reader.seek(io::SeekFrom::Start(0))?;
        let actual = reader.metadata()?.len();
        if actual != self.length {
            return Err(invalid(format!(
                "finished push pack changed size from {} to {actual} bytes",
                self.length
            )));
        }
        let length = self.length;
        Ok((
            PackReader {
                reader,
                _guard: self.file,
            },
            length,
        ))
    }

    /// The exact object count encoded in the pack header.
    pub fn object_count(&self) -> u32 {
        self.object_count
    }
}

/// Encode selected full objects into a bounded, non-thin V2 pack.
pub fn write(
    repo: &gix::Repository,
    selection: &Selection,
    staging: &Path,
    cancellation: &Cancellation,
) -> crate::Result<FinishedPack> {
    let pack = write_ids(repo, selection.ids(), staging, cancellation)
        .map_err(|error| cancellation.normalize_error(error))?;
    cancellation.check()?;
    Ok(pack)
}

fn write_ids(
    repo: &gix::Repository,
    ids: &[gix::ObjectId],
    staging: &Path,
    cancellation: &Cancellation,
) -> crate::Result<FinishedPack> {
    cancellation.check()?;
    let object_count = u32::try_from(ids.len())?;
    let file = gix::tempfile::new(
        staging,
        gix::tempfile::ContainingDirectory::Exists,
        gix::tempfile::AutoRemove::Tempfile,
    )?;
    let output = BufWriter::with_capacity(
        WRITER_BUFFER_BYTES,
        ExtentWriter {
            inner: file,
            written: 0,
        },
    );
    let objects = Reader::new(repo, cancellation);
    let input = ids.iter().copied().map(|id| encode_object(&objects, id));
    let mut encoder = gix_pack::data::output::bytes::FromEntriesIter::new(
        input,
        output,
        object_count,
        gix_pack::data::Version::V2,
        gix::hash::Kind::Sha1,
    );
    for written in encoder.by_ref() {
        written?;
        cancellation.check()?;
    }
    let digest = encoder
        .digest()
        .ok_or_else(|| invalid("push pack encoder did not produce a trailer"))?;
    let output = encoder
        .into_write()
        .into_inner()
        .map_err(|error| error.into_error())?;
    let length = output.written;
    let mut file = output.inner;
    let actual =
        file.with_mut(|file| file.as_file().metadata().map(|metadata| metadata.len()))??;
    if actual != length {
        return Err(invalid(format!(
            "push pack writer recorded {length} bytes but the tempfile has {actual}"
        ))
        .into());
    }
    verify_pack(&mut file, length, digest, cancellation)?;
    Ok(FinishedPack {
        file,
        length,
        object_count,
    })
}

fn encode_object(
    objects: &Reader<'_>,
    id: gix::ObjectId,
) -> io::Result<Vec<gix_pack::data::output::Entry>> {
    let object = objects.load(id).map_err(io::Error::other)?;
    let data = gix::objs::Data {
        kind: object.kind,
        object_hash: id.kind(),
        data: &object.data,
    };
    let count = gix_pack::data::output::Count::from_data(id, None);
    let entry =
        gix_pack::data::output::Entry::from_data(&count, &data, gix::zlib::Compression::DEFAULT)
            .map_err(io::Error::other)?;
    objects.cancellation().check().map_err(io::Error::other)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(1).map_err(io::Error::other)?;
    entries.push(entry);
    Ok(entries)
}

fn verify_pack(
    file: &mut Tempfile,
    length: u64,
    expected: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result {
    let payload = length
        .checked_sub(SHA1_BYTES as u64)
        .ok_or_else(|| invalid("push pack is shorter than its SHA-1 trailer"))?;
    let mut reader = file.with_mut(|file| file.as_file().try_clone())??;
    reader.seek(io::SeekFrom::Start(0))?;
    let actual = gix::hash::bytes(
        &mut reader,
        payload,
        gix::hash::Kind::Sha1,
        &mut gix::progress::Discard,
        cancellation.flag(),
    )?;
    let mut trailer = [0u8; SHA1_BYTES];
    reader.read_exact(&mut trailer)?;
    if reader.read(&mut [0u8; 1])? != 0 {
        return Err(invalid("push pack has bytes after its SHA-1 trailer").into());
    }
    let stored = gix::ObjectId::try_from(trailer.as_slice())?;
    if actual != expected || stored != expected {
        return Err(invalid("push pack SHA-1 trailer does not match its contents").into());
    }
    cancellation.check()?;
    Ok(())
}

struct ExtentWriter<W> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for ExtentWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested = self
            .written
            .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
            .filter(|length| *length <= MAX_PACK_BYTES)
            .ok_or_else(|| invalid("push pack exceeds the 128 MiB byte limit"))?;
        let written = self.inner.write(bytes)?;
        debug_assert!(self.written + written as u64 <= requested);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use super::*;

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn empty_pack_is_valid_and_missing_objects_remove_the_tempfile() -> crate::Result {
        let root = std::env::temp_dir().join(format!(
            "motor-gix-push-pack-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _cleanup = Cleanup(root.clone());
        fs::create_dir(&root)?;
        let repo = gix::init_bare(root.join("repo"))?;
        let staging = root.join("staging");
        fs::create_dir(&staging)?;
        let cancellation = Cancellation::new();

        let pack = write_ids(&repo, &[], &staging, &cancellation)?;
        assert_eq!(pack.object_count(), 0);
        let (mut reader, length) = pack.into_reader()?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        assert_eq!(length, 12 + SHA1_BYTES as u64);
        assert_eq!(&bytes[..4], b"PACK");
        assert_eq!(u32::from_be_bytes(bytes[8..12].try_into()?), 0);
        drop(reader);
        assert!(fs::read_dir(&staging)?.next().is_none());

        let missing = gix::ObjectId::from_bytes_or_panic(&[1; SHA1_BYTES]);
        assert!(write_ids(&repo, &[missing], &staging, &cancellation).is_err());
        assert!(fs::read_dir(&staging)?.next().is_none());

        let mut extent = ExtentWriter {
            inner: Vec::new(),
            written: MAX_PACK_BYTES - 1,
        };
        assert_eq!(extent.write(&[1])?, 1);
        assert_eq!(extent.inner, vec![1]);
        assert!(extent.write(&[2]).is_err());
        assert_eq!(extent.inner, vec![1], "rejected bytes reached the sink");
        Ok(())
    }
}
