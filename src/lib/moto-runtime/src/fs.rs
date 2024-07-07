use super::rt_api::fs::*;
use alloc::borrow::ToOwned;
use alloc::string::String;
use core::sync::atomic::*;
use moto_sys::SysMem;

#[derive(Debug)]
pub enum SeekFrom {
    Start(u64),
    End(i64),
    Current(i64),
}

#[derive(Clone, Debug)]
pub struct FileAttr {
    size: u64,
    file_perm: u16,
    file_type: u8,
    modified: u64,
    accessed: u64,
    created: u64,
}

impl FileAttr {
    pub fn new(raw_data: &FileAttrData) -> Self {
        Self {
            size: raw_data.size,
            file_type: raw_data.file_type,
            file_perm: raw_data.file_perm,
            modified: raw_data.modified,
            accessed: raw_data.accessed,
            created: raw_data.created,
        }
    }

    pub fn validate(&self) -> Result<(), ErrorCode> {
        FileType::from_u8(self.file_type).validate()?;
        FilePermissions::from_u16(self.file_perm).validate()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions::from_u16(self.file_perm)
    }

    pub fn file_type(&self) -> FileType {
        FileType::from_u8(self.file_type)
    }

    pub fn modified(&self) -> Result<u64, ErrorCode> {
        Ok(self.modified)
    }

    pub fn accessed(&self) -> Result<u64, ErrorCode> {
        Ok(self.accessed)
    }

    pub fn created(&self) -> Result<u64, ErrorCode> {
        Ok(self.created)
    }
}

#[derive(Debug)]
pub struct ReadDir {
    path: String,
    fd: u64,
}

impl Drop for ReadDir {
    fn drop(&mut self) {
        FsClient::close_fd(self.fd, CloseFdRequest::F_READDIR).ok();
    }
}

impl ReadDir {
    fn from(path: String, resp: &ReadDirResponse) -> Result<ReadDir, ErrorCode> {
        Ok(ReadDir { path, fd: resp.fd })
    }
}

impl Iterator for ReadDir {
    type Item = Result<DirEntry, ErrorCode>;

    fn next(&mut self) -> Option<Self::Item> {
        match FsClient::readdir_next(self) {
            Ok(result) => match result {
                Some(entry) => Some(Ok(entry)),
                None => None,
            },
            Err(err) => Some(Err(err)),
        }
    }
}

pub struct DirEntry {
    fname_offset: u16, // "" => root.
    abs_path: String,  // "/" => root.
    file_attr: FileAttr,
}

impl DirEntry {
    pub fn path(&self) -> &str {
        self.abs_path.as_str()
    }

    pub fn file_name(&self) -> &str {
        &self.abs_path.as_str()[(self.fname_offset as usize)..]
    }

    pub fn metadata(&self) -> Result<FileAttr, ErrorCode> {
        Ok(self.file_attr.clone())
    }

    pub fn file_type(&self) -> Result<FileType, ErrorCode> {
        Ok(self.file_attr.file_type())
    }

    fn from(
        readdir: &ReadDir,
        raw_channel: &moto_ipc::sync::RawChannel,
        data: &DirEntryData,
    ) -> Result<Self, ErrorCode> {
        assert_eq!(0, data.version);
        assert_eq!(
            core::mem::size_of::<DirEntryData>(),
            data.self_size as usize
        );
        let file_attr = FileAttr::new(&data.attr);
        file_attr.validate()?;

        let fname_bytes = unsafe { raw_channel.get_bytes(&data.fname, data.fname_size as usize)? };
        let fname = core::str::from_utf8(fname_bytes).map_err(|_| ErrorCode::InternalError)?;

        let mut abs_path = readdir.path.clone();
        if abs_path != "/" {
            abs_path.push('/');
        }
        abs_path.push_str(fname);
        Ok(DirEntry {
            fname_offset: (abs_path.len() - fname.len()) as u16,
            abs_path,
            file_attr,
        })
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FileTimes {}

impl FileTimes {
    pub fn set_accessed(&mut self, _unix_ts: u64) {
        todo!()
    }

    pub fn set_modified(&mut self, _unix_ts: u64) {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilePermissions {
    file_perm: u16,
}

impl FilePermissions {
    pub fn from_u16(val: u16) -> Self {
        FilePermissions { file_perm: val }
    }

    fn validate(&self) -> Result<(), ErrorCode> {
        if self.file_perm & !0x3 != 0 {
            return Err(ErrorCode::InternalError);
        }
        Ok(())
    }

    pub fn readonly(&self) -> bool {
        self.file_perm & FILE_PERM_WRITE == 0
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            self.file_perm &= !FILE_PERM_WRITE
        } else {
            self.file_perm |= FILE_PERM_WRITE
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq)]
pub struct FileType {
    file_type: u8,
}

impl FileType {
    pub fn from_u8(val: u8) -> Self {
        Self { file_type: val }
    }

    pub fn validate(&self) -> Result<(), ErrorCode> {
        if (self.file_type & !0x7) != 0 {
            return Err(ErrorCode::InternalError);
        }

        if (self.file_type & 3) == 3 {
            return Err(ErrorCode::InternalError);
        }

        Ok(())
    }

    pub fn is_dir(&self) -> bool {
        (self.file_type & FILE_TYPE_DIR) != 0
    }

    pub fn is_file(&self) -> bool {
        (self.file_type & FILE_TYPE_FILE) != 0
    }

    pub fn is_symlink(&self) -> bool {
        (self.file_type & FILE_TYPE_SYMLINK) != 0
    }
}

#[derive(Debug)]
pub struct DirBuilder {}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        Self {}
    }

    pub fn mkdir(&self, path: &str) -> Result<(), ErrorCode> {
        FsClient::mkdir(path)
    }
}

#[derive(Clone, Debug)]
pub struct OpenOptions {
    flags: u32,
}

impl OpenOptions {
    const F_READ: u32 = FileOpenRequest::F_READ;
    const F_WRITE: u32 = FileOpenRequest::F_WRITE;
    const F_APPEND: u32 = FileOpenRequest::F_APPEND;
    const F_TRUNCATE: u32 = FileOpenRequest::F_TRUNCATE;
    const F_CREATE: u32 = FileOpenRequest::F_CREATE;
    const F_CREATE_NEW: u32 = FileOpenRequest::F_CREATE_NEW;

    pub const fn new() -> OpenOptions {
        Self { flags: 0 }
    }

    fn set_flag(&mut self, flag: u32, val: bool) {
        if val {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    pub fn read(&mut self, read: bool) {
        self.set_flag(Self::F_READ, read);
    }

    pub fn write(&mut self, write: bool) {
        self.set_flag(Self::F_WRITE, write);
    }

    pub fn append(&mut self, append: bool) {
        self.set_flag(Self::F_APPEND, append);
    }

    pub fn truncate(&mut self, truncate: bool) {
        self.set_flag(Self::F_TRUNCATE, truncate);
    }

    pub fn create(&mut self, create: bool) {
        self.set_flag(Self::F_CREATE, create);
    }

    pub fn create_new(&mut self, create_new: bool) {
        self.set_flag(Self::F_CREATE_NEW, create_new);
    }
}

pub struct File {
    path: String, // Absolute.
    fd: u64,
    pos: AtomicU64, // Atomic because read operations take &File, but change pos.
    size: u64,
}

impl Drop for File {
    fn drop(&mut self) {
        FsClient::close_fd(self.fd, CloseFdRequest::F_FILE).ok();
    }
}

impl File {
    pub fn open(path: &str, opts: &OpenOptions) -> Result<File, ErrorCode> {
        FsClient::file_open(path, opts)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn seek(&self, pos: SeekFrom) -> Result<u64, ErrorCode> {
        FsClient::seek(self, pos)
    }

    pub fn file_attr(&self) -> Result<FileAttr, ErrorCode> {
        FsClient::stat(self.path.as_str())
    }

    pub fn fsync(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    pub fn datasync(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    pub fn truncate(&self, _size: u64) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        FsClient::read(self, buf)
    }

    pub fn read_all(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        if buf.len() < self.size as usize {
            return Err(ErrorCode::InvalidArgument);
        }
        self.pos.store(0, Ordering::Relaxed);

        let mut done = 0_usize;
        while done < self.size as usize {
            let dst = &mut buf[done..];
            let sz = FsClient::read(self, dst)?;
            if sz == 0 {
                break;
            }
            done += sz;
        }

        Ok(done)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let mut written = 0;
        loop {
            if written == buf.len() {
                return Ok(written);
            }

            let res = FsClient::write(self, &buf[written..]);
            if let Ok(sz) = res {
                written += sz;
            } else {
                if written > 0 {
                    return Ok(written);
                } else {
                    return res;
                }
            }
        }
    }
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(core::format_args!("File: '{}'", self.path))
    }
}

pub fn readdir(dir: &str) -> Result<ReadDir, ErrorCode> {
    FsClient::readdir(dir)
}

pub fn rename(old: &str, new: &str) -> Result<(), ErrorCode> {
    FsClient::rename(old, new)
}

pub fn set_perm(_pathname: &str, _perm: FilePermissions) -> Result<(), ErrorCode> {
    todo!()
}

pub fn stat(path: &str) -> Result<FileAttr, ErrorCode> {
    FsClient::stat(path)
}

pub fn lstat(path: &str) -> Result<FileAttr, ErrorCode> {
    SysMem::log(alloc::format!("fs.rs: lstat: {}", path).as_str()).ok();
    todo!()
}

pub fn canonicalize(path: &str) -> Result<String, ErrorCode> {
    let c_path = CanonicalPath::parse(path)?;
    FsClient::stat(c_path.abs_path.as_str()).map(|_| c_path.abs_path)
}

pub fn getcwd() -> Result<String, ErrorCode> {
    FsClient::getcwd()
}

pub fn chdir(path: &str) -> Result<(), ErrorCode> {
    FsClient::chdir(path)
}

pub fn unlink(path: &str) -> Result<(), ErrorCode> {
    FsClient::unlink(path, F_UNLINK_FILE)
}

pub fn rmdir(path: &str) -> Result<(), ErrorCode> {
    FsClient::unlink(path, F_UNLINK_DIR)
}

pub fn rmdir_all(path: &str) -> Result<(), ErrorCode> {
    FsClient::unlink(path, F_UNLINK_DIR_ALL)
}

// ---------------------- implementation details below ------------------------ //

// Given a path str from the user, figure out the absolute path, filename, etc.
#[derive(Clone)]
struct CanonicalPath {
    abs_path: String,
    fname_offset: u16, // The last component.
}

impl CanonicalPath {
    fn _filename(&self) -> &str {
        &self.abs_path.as_str()[(self.fname_offset as usize)..]
    }

    fn normalize(abs_path: &str) -> Result<Self, ErrorCode> {
        if (abs_path.len() == 0) || (abs_path.len() >= MAX_PATH) {
            return Err(ErrorCode::InvalidFilename);
        }
        if &abs_path[0..1] != "/" {
            return Err(ErrorCode::InvalidFilename);
        }

        if abs_path == "/" {
            return Ok(CanonicalPath {
                abs_path: abs_path.to_owned(),
                fname_offset: 1,
            });
        }

        let mut components = alloc::vec![];
        for entry in abs_path.split('/') {
            if entry.is_empty() {
                continue;
            }
            if entry == "." {
                continue;
            }
            if entry.len() != entry.trim().len() {
                return Err(ErrorCode::InvalidFilename);
            }

            if entry == ".." {
                if components.len() == 0 {
                    return Err(ErrorCode::InvalidFilename);
                }
                components.pop();
            } else {
                components.push(entry);
            }
        }

        if components.len() == 0 {
            return Ok(CanonicalPath {
                abs_path: "/".to_owned(),
                fname_offset: 1,
            });
        }

        let mut result = String::new();
        for entry in &components {
            result.push('/');
            result.push_str(entry);
        }

        let fname_offset = result.len() - components[components.len() - 1].len();

        Ok(CanonicalPath {
            abs_path: result,
            fname_offset: fname_offset as u16,
        })
    }

    fn parse(path: &str) -> Result<Self, ErrorCode> {
        if (path.len() == 0) || (path.len() >= MAX_PATH) || (path.len() != path.trim().len()) {
            return Err(ErrorCode::InvalidFilename);
        }

        if path == "/" {
            return Ok(CanonicalPath {
                abs_path: path.to_owned(),
                fname_offset: 1, // Empty filename.
            });
        }

        if path.trim_end_matches('/').len() != path.len() {
            return Err(ErrorCode::InvalidFilename);
        }

        if path.starts_with('/') {
            return Self::normalize(path);
        }

        let mut abs_path = {
            match getcwd() {
                Ok(cwd) => cwd,
                Err(_) => {
                    // Can't work with rel paths without cwd.
                    return Err(ErrorCode::InvalidFilename);
                }
            }
        };

        if abs_path != "/" {
            abs_path.push('/');
        }
        abs_path.push_str(path);

        Self::normalize(abs_path.as_str())
    }
}

struct FsClient {
    _driver_url: String,
    conn: super::mutex::Mutex<moto_ipc::sync::ClientConnection>,
    cwd: super::mutex::Mutex<Option<DirEntry>>,
}

static FS_CLIENT: AtomicUsize = AtomicUsize::new(0);

impl FsClient {
    fn new(url: String) -> Result<(), ErrorCode> {
        use alloc::boxed::Box;

        let mut conn = moto_ipc::sync::ClientConnection::new(moto_ipc::sync::ChannelSize::Small)?;
        if let Err(err) = conn.connect(url.as_str()) {
            SysMem::log("Failed to connect to FS driver.").ok();
            return Err(err.into());
        }

        let fs_client = Box::leak(Box::new(FsClient {
            _driver_url: url,
            conn: super::mutex::Mutex::new(conn),
            cwd: super::mutex::Mutex::new(None),
        }));
        assert_eq!(
            0,
            FS_CLIENT.swap(fs_client as *const _ as usize, Ordering::AcqRel)
        );

        Ok(())
    }

    fn get() -> Result<&'static FsClient, ErrorCode> {
        let addr = FS_CLIENT.load(Ordering::Relaxed);
        if addr == 0 {
            return Err(ErrorCode::InternalError);
        }

        unsafe { Ok((addr as *const FsClient).as_ref().unwrap_unchecked()) }
    }

    fn getcwd() -> Result<String, ErrorCode> {
        let cwd = Self::get()?.cwd.lock();
        match cwd.as_ref() {
            Some(dir_entry) => Ok(dir_entry.abs_path.clone()),
            None => super::env::getenv("PWD").ok_or(ErrorCode::NotFound),
        }
    }

    fn chdir(path: &str) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let self_ = Self::get()?;

        let cwd = {
            let mut conn = self_.conn.lock();
            let raw_channel = conn.raw_channel();
            unsafe {
                let req = raw_channel.get_mut::<StatRequest>();
                req.header.cmd = CMD_STAT;
                req.header.ver = 0;
                req.header.flags = 0;
                req.parent_fd = 0;

                req.fname_size = c_path.abs_path.as_bytes().len() as u16;
                raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
            }

            conn.do_rpc(None)?;

            let resp = unsafe { raw_channel.get::<StatResponse>() };
            if resp.header.result != 0 {
                return Err(ErrorCode::from(resp.header.result));
            }

            let file_attr = FileAttr::new(&resp.attr);
            file_attr.validate()?;

            if !file_attr.file_type().is_dir() {
                return Err(ErrorCode::NotADirectory);
            }

            DirEntry {
                fname_offset: c_path.fname_offset,
                abs_path: c_path.abs_path.clone(),
                file_attr,
            }
        };

        *self_.cwd.lock() = Some(cwd);
        Ok(())
    }

    fn rename(old: &str, new: &str) -> Result<(), ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<RenameRequest>();
            let old_path = CanonicalPath::parse(old)?;
            let new_path = CanonicalPath::parse(new)?;

            req.build(
                old_path.abs_path.as_str(),
                new_path.abs_path.as_str(),
                &raw_channel,
            )?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<RenameResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        Ok(())
    }

    fn unlink(path: &str, flags: u32) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<UnlinkRequest>();
            req.header.cmd = CMD_UNLINK;
            req.header.ver = 0;
            req.header.flags = flags;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<UnlinkResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        Ok(())
    }

    fn file_open(path: &str, opts: &OpenOptions) -> Result<File, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<FileOpenRequest>();
            req.header.cmd = CMD_FILE_OPEN;
            req.header.ver = 0;
            req.header.flags = opts.flags;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileOpenResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        if resp.fd == 0 {
            return Err(ErrorCode::InternalError);
        }

        Ok(File {
            path: c_path.abs_path,
            fd: resp.fd,
            pos: AtomicU64::new(0),
            size: resp.size,
        })
    }

    fn seek(file: &File, pos: SeekFrom) -> Result<u64, ErrorCode> {
        match pos {
            SeekFrom::Current(n) => {
                if n == 0 {
                    return Ok(file.pos.load(Ordering::Relaxed));
                }

                loop {
                    let curr = file.pos.load(Ordering::Relaxed) as i64;
                    let new = curr + n;
                    if (new > (file.size as i64)) || (new < 0) {
                        return Err(ErrorCode::InvalidArgument);
                    }

                    if file
                        .pos
                        .compare_exchange_weak(
                            curr as u64,
                            new as u64,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        return Ok(new as u64);
                    }
                }
            }
            SeekFrom::Start(n) => {
                if n > file.size {
                    return Err(ErrorCode::InvalidArgument);
                }
                file.pos.store(n, Ordering::Relaxed);
                Ok(n)
            }
            SeekFrom::End(n) => {
                if (n < 0) && ((-n as u64) > file.size) {
                    return Err(ErrorCode::InvalidArgument);
                }
                if n > 0 {
                    SysMem::log(
                        alloc::format!(
                            "fs.rs: File::seek: '{:?}' => {:?}: Not Implemented",
                            file,
                            pos
                        )
                        .as_str(),
                    )
                    .ok();
                    return Err(ErrorCode::from(ErrorCode::NotImplemented));
                }
                let new_pos = file.size - ((-n) as u64);
                file.pos.store(new_pos, Ordering::Relaxed);
                Ok(new_pos)
            }
        }
    }

    fn read(file: &File, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<FileReadRequest>();
            req.header.cmd = CMD_FILE_READ;
            req.header.ver = 0;
            req.fd = file.fd;
            req.offset = file.pos.load(Ordering::Relaxed);
            req.max_bytes = {
                if buf.len() > raw_channel.size() {
                    raw_channel.size()
                } else {
                    buf.len()
                }
            } as u32;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileReadResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        // resp.size may be BLOCK_SIZE if buf is too small.
        let result_sz = buf.len().min(resp.size as usize);

        unsafe {
            let bytes = raw_channel.get_bytes(&resp.data, result_sz)?;
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr(), result_sz);
            file.pos.fetch_add(result_sz as u64, Ordering::Relaxed);
            Ok(result_sz)
        }
    }

    fn write(file: &File, buf: &[u8]) -> Result<usize, ErrorCode> {
        if buf.len() == 0 {
            SysMem::log("FS: write request with empty buf").ok();
            return Err(ErrorCode::InvalidArgument);
        }
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<FileWriteRequest>();
            req.header.cmd = CMD_FILE_WRITE;
            req.header.ver = 0;
            req.header.flags = 0;
            req.fd = file.fd;
            req.offset = file.pos.load(Ordering::Relaxed);

            let size =
                (raw_channel.size() - core::mem::size_of::<FileWriteRequest>()).min(buf.len());
            req.size = size as u32;

            raw_channel.put_bytes(&buf[0..size], &mut req.data).unwrap();
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<FileWriteResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from_u16(resp.header.result));
        }

        file.pos.fetch_add(resp.written as u64, Ordering::Relaxed);

        Ok(resp.written as usize)
    }

    fn readdir(path: &str) -> Result<ReadDir, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<ReadDirRequest>();
            req.header.cmd = CMD_READDIR;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<ReadDirResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        ReadDir::from(c_path.abs_path, &resp)
    }

    fn readdir_next(readdir: &ReadDir) -> Result<Option<DirEntry>, ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<ReadDirNextRequest>();
            req.header.cmd = CMD_READDIR_NEXT;
            req.header.ver = 0;
            req.header.flags = 0;
            req.readdir_fd = readdir.fd;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<ReadDirNextResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from(resp.header.result));
        }

        if resp.entries == 0 {
            return Ok(None);
        }

        if resp.entries != 1 {
            panic!("Batched entries not supported yet.");
        }

        let dentry = unsafe { raw_channel.get_at(&resp.dir_entries, 1)? };
        Ok(Some(DirEntry::from(readdir, &raw_channel, &dentry[0])?))
    }

    fn close_fd(fd: u64, flags: u32) -> Result<(), ErrorCode> {
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();
        unsafe {
            let req = raw_channel.get_mut::<CloseFdRequest>();
            req.header.cmd = CMD_CLOSE_FD;
            req.header.ver = 0;
            req.header.flags = flags;
            req.fd = fd;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<CloseFdResponse>() };
        if resp.header.result != 0 {
            SysMem::log("close_fd: RPC failed.").ok();
        }

        Ok(())
    }

    fn stat(path: &str) -> Result<FileAttr, ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<StatRequest>();
            req.header.cmd = CMD_STAT;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<StatResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from_u16(resp.header.result));
        }

        let file_attr = FileAttr::new(&resp.attr);
        file_attr.validate()?;
        Ok(file_attr)
    }

    fn mkdir(path: &str) -> Result<(), ErrorCode> {
        let c_path = CanonicalPath::parse(path)?;
        let mut conn = Self::get()?.conn.lock();
        let raw_channel = conn.raw_channel();

        unsafe {
            let req = raw_channel.get_mut::<MkdirRequest>();
            req.header.cmd = CMD_MKDIR;
            req.header.ver = 0;
            req.header.flags = 0;
            req.parent_fd = 0;

            req.fname_size = c_path.abs_path.as_bytes().len() as u16;
            raw_channel.put_bytes(c_path.abs_path.as_bytes(), &mut req.fname)?;
        }

        conn.do_rpc(None)?;

        let resp = unsafe { raw_channel.get::<MkdirResponse>() };
        if resp.header.result != 0 {
            return Err(ErrorCode::from_u16(resp.header.result));
        }

        Ok(())
    }
}

fn get_fileserver_url() -> Result<String, ErrorCode> {
    let mut conn = moto_ipc::sync::ClientConnection::new(moto_ipc::sync::ChannelSize::Small)?;
    conn.connect(FS_URL)?;

    let req = conn.req::<GetServerUrlRequest>();
    req.header.cmd = 1;
    req.header.ver = 0;
    req.header.flags = 0;
    conn.do_rpc(Some(
        moto_sys::time::Instant::now() + core::time::Duration::from_millis(1000),
    ))?;

    let resp = conn.resp::<GetServerUrlResponse>();
    if resp.header.result != 0 || resp.header.ver != 0 {
        SysMem::log("get_fileserver_url() failed.").ok();
        return Err(ErrorCode::InternalError);
    }

    Ok(unsafe { resp.url() }?.to_owned())
}

pub(super) fn init() -> Result<(), ErrorCode> {
    let driver_url = get_fileserver_url()?;
    FsClient::new(driver_url)
}
