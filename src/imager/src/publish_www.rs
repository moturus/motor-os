//! `imager publish-www`: one staged update that turns a stopped image into a web host.

use crate::chmod;
use crate::permissions::{FileClass, PermissionPolicy};
use crate::set::credentials::{self, Credentials};
use crate::set::image::{self, Fs};
use crate::set::{invalid, Input};
use async_fs::{
    AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions, BLOCK_SIZE,
};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const WWW_HOME: &str = "/user/www-home";
const WWW_SCRIPT: &str = "/user/bin/www";
const HTTPD: &str = "/user/bin/httpd-axum";
const SCRIPT: &str = "#!/system/bin/rush\n\
/user/bin/httpd-axum -a 0.0.0.0:443 -d /user/www-home \
--ssl-cert /system/cfg/ssl/ssl-cert.pem --ssl-key /system/cfg/ssl/ssl-key.pem\n";

struct Args<'a> {
    www: &'a Path,
    password: &'a str,
    login_key: &'a Path,
    tls: &'a Path,
    image: &'a Path,
}

fn usage() -> io::Error {
    invalid("expected WWW_DIR --ssh-password PWD --ssh-key PUBLIC_KEY_FILE --ssl-keys DIR -i IMAGE")
}

fn parse<'a>(args: &'a [&'a str]) -> io::Result<Args<'a>> {
    let [www, options @ ..] = args else {
        return Err(usage());
    };
    if www.starts_with('-') {
        return Err(usage());
    }
    let (mut password, mut login_key, mut tls, mut image) = (None, None, None, None);
    for pair in options.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        let slot = match *option {
            "--ssh-password" => &mut password,
            "--ssh-key" => &mut login_key,
            "--ssl-keys" => &mut tls,
            "-i" => &mut image,
            _ => return Err(usage()),
        };
        if slot.replace(*value).is_some() {
            return Err(usage());
        }
    }
    let (Some(password), Some(login_key), Some(tls), Some(image)) =
        (password, login_key, tls, image)
    else {
        return Err(usage());
    };
    credentials::validate_password(password)?;
    Ok(Args {
        www: Path::new(www),
        password,
        login_key: Path::new(login_key),
        tls: Path::new(tls),
        image: Path::new(image),
    })
}

/// A host entry under WWW_DIR; `host` is set for regular files only.
struct Node {
    guest: PathBuf,
    host: Option<PathBuf>,
}

/// Lists WWW_DIR parents-first; anything but directories and regular files is rejected.
fn walk(root: &Path) -> io::Result<Vec<Node>> {
    if !fs::metadata(root)?.is_dir() {
        return Err(invalid("WWW_DIR must be a directory"));
    }
    let mut nodes = Vec::new();
    let mut pending = vec![(root.to_owned(), PathBuf::from(WWW_HOME))];
    while let Some((host_dir, guest_dir)) = pending.pop() {
        let mut entries = fs::read_dir(&host_dir)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("WWW_DIR entry names must be UTF-8"))?;
            let (host, guest) = (entry.path(), guest_dir.join(name));
            let kind = entry.file_type()?;
            if kind.is_dir() {
                nodes.push(Node {
                    guest: guest.clone(),
                    host: None,
                });
                pending.push((host, guest));
            } else if kind.is_file() {
                nodes.push(Node {
                    guest,
                    host: Some(host),
                });
            } else {
                return Err(invalid(
                    "WWW_DIR may contain only directories and regular files",
                ));
            }
        }
    }
    Ok(nodes)
}

fn open_host_file(path: &Path) -> io::Result<File> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid(
            "WWW_DIR may contain only directories and regular files",
        ));
    }
    Ok(file)
}

/// Fills `buf` from `source` unless EOF comes first; returns the byte count.
fn read_chunk(source: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut len = 0;
    while len < buf.len() {
        match source.read(&mut buf[len..])? {
            0 => break,
            size => len += size,
        }
    }
    Ok(len)
}

fn split(path: &Path) -> (&Path, &str) {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap();
    (path.parent().unwrap(), name)
}

async fn writable_by_system(fs: &mut Fs, id: EntryId) -> io::Result<()> {
    let mut permissions = fs.metadata(Role::System, id).await?.permissions()?;
    if !permissions.system.can_write() {
        permissions.system = AccessPermissions::Rwx;
        fs.set_all_permissions_image_admin(Role::System, id, permissions)
            .await?;
    }
    Ok(())
}

async fn children(fs: &Fs, dir: EntryId) -> io::Result<Vec<EntryId>> {
    let mut result = Vec::new();
    let mut next = fs.get_first_entry(Role::System, dir).await?;
    while let Some(id) = next {
        result.push(id);
        next = fs.get_next_entry(Role::System, id).await?;
    }
    Ok(result)
}

async fn delete_tree(fs: &mut Fs, root: EntryId) -> io::Result<()> {
    let mut stack = vec![(root, false)];
    while let Some((id, emptied)) = stack.pop() {
        if emptied || fs.metadata(Role::System, id).await?.try_kind()? == EntryKind::File {
            fs.delete_entry(Role::System, id).await?;
            continue;
        }
        writable_by_system(fs, id).await?;
        stack.push((id, true));
        stack.extend(children(fs, id).await?.into_iter().map(|id| (id, false)));
    }
    Ok(())
}

/// Creates `path` (whose parent must exist) as `kind`, replacing a same-kind entry.
async fn recreate(
    fs: &mut Fs,
    path: &Path,
    kind: EntryKind,
    permissions: RolePermissions,
) -> io::Result<EntryId> {
    let (parent, name) = split(path);
    let parent = chmod::resolve_path(fs, parent).await?;
    if let Some((old, _)) = fs.stat(Role::System, parent, name).await? {
        if fs.metadata(Role::System, old).await?.try_kind()? != kind {
            return Err(invalid(
                "publish-www destination exists with the wrong entry kind",
            ));
        }
        delete_tree(fs, old).await?;
    }
    let initial = if permissions.system.can_write() {
        permissions
    } else {
        RolePermissions::new(
            AccessPermissions::Rw,
            AccessPermissions::None,
            AccessPermissions::None,
        )
    };
    fs.create_entry(Role::System, parent, kind, name, initial)
        .await
}

async fn write_file(
    fs: &mut Fs,
    path: &Path,
    permissions: RolePermissions,
    mut source: impl Read,
) -> io::Result<()> {
    let id = recreate(fs, path, EntryKind::File, permissions).await?;
    let mut buf = vec![0; BLOCK_SIZE];
    let mut offset = 0;
    loop {
        let len = read_chunk(&mut source, &mut buf)?;
        let mut written = 0;
        while written < len {
            let size = fs
                .write(Role::System, id, offset, &buf[written..len])
                .await?;
            if size == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            written += size;
            offset += size as u64;
        }
        if len < buf.len() {
            break;
        }
    }
    if !permissions.system.can_write() {
        fs.set_all_permissions_image_admin(Role::System, id, permissions)
            .await?;
    }
    Ok(())
}

async fn publish(fs: &mut Fs, policy: &PermissionPolicy, nodes: &[Node]) -> io::Result<()> {
    let no_httpd = || invalid("image has no /user/bin/httpd-axum");
    let httpd = match chmod::resolve_path(fs, Path::new(HTTPD)).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(no_httpd()),
        result => result?,
    };
    if fs.metadata(Role::System, httpd).await?.try_kind()? != EntryKind::File {
        return Err(no_httpd());
    }
    let home = Path::new(WWW_HOME);
    recreate(
        fs,
        home,
        EntryKind::Directory,
        policy.directory_permissions(home),
    )
    .await?;
    for node in nodes {
        match &node.host {
            None => {
                let permissions = policy.directory_permissions(&node.guest);
                recreate(fs, &node.guest, EntryKind::Directory, permissions).await?;
            }
            Some(host) => {
                let permissions = policy.file_permissions(&node.guest, FileClass::Regular);
                write_file(fs, &node.guest, permissions, open_host_file(host)?).await?;
            }
        }
    }
    let script = Path::new(WWW_SCRIPT);
    let permissions = policy.file_permissions(script, FileClass::Script);
    write_file(fs, script, permissions, SCRIPT.as_bytes()).await
}

async fn verify_file(
    fs: &Fs,
    path: &Path,
    permissions: RolePermissions,
    mut source: impl Read,
) -> io::Result<()> {
    let mismatch = || io::Error::other("published web content verification failed");
    let id = chmod::resolve_path(fs, path).await?;
    let metadata = fs.metadata(Role::System, id).await?;
    if metadata.try_kind()? != EntryKind::File || metadata.permissions()? != permissions {
        return Err(mismatch());
    }
    let (mut expected, mut actual) = (vec![0; BLOCK_SIZE], vec![0; BLOCK_SIZE]);
    let mut offset = 0;
    loop {
        let len = read_chunk(&mut source, &mut expected)?;
        let mut read = 0;
        while read < len {
            let size = fs
                .read(Role::System, id, offset, &mut actual[read..len])
                .await?;
            if size == 0 {
                return Err(mismatch());
            }
            read += size;
            offset += size as u64;
        }
        if expected[..len] != actual[..len] {
            return Err(mismatch());
        }
        if len < expected.len() {
            break;
        }
    }
    if offset != metadata.size {
        return Err(mismatch());
    }
    Ok(())
}

async fn verify(fs: &Fs, policy: &PermissionPolicy, nodes: &[Node]) -> io::Result<()> {
    let mismatch = || io::Error::other("published web content verification failed");
    let mut dirs = vec![PathBuf::from(WWW_HOME)];
    for node in nodes {
        match &node.host {
            None => dirs.push(node.guest.clone()),
            Some(host) => {
                let permissions = policy.file_permissions(&node.guest, FileClass::Regular);
                verify_file(fs, &node.guest, permissions, open_host_file(host)?).await?;
            }
        }
    }
    for dir in dirs {
        let id = chmod::resolve_path(fs, &dir).await?;
        let metadata = fs.metadata(Role::System, id).await?;
        let expected = nodes
            .iter()
            .filter(|node| node.guest.parent() == Some(dir.as_path()));
        if metadata.try_kind()? != EntryKind::Directory
            || metadata.permissions()? != policy.directory_permissions(&dir)
            || children(fs, id).await?.len() != expected.count()
        {
            return Err(mismatch());
        }
    }
    let script = Path::new(WWW_SCRIPT);
    let permissions = policy.file_permissions(script, FileClass::Script);
    verify_file(fs, script, permissions, SCRIPT.as_bytes()).await
}

pub(super) fn run(args: &[OsString]) -> io::Result<()> {
    let args = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .ok_or_else(|| invalid("publish-www arguments must be UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let args = parse(&args)?;
    let policy = PermissionPolicy::parse(
        include_str!("../motor-os-permissions.yaml"),
        PathBuf::from("motor-os-permissions.yaml"),
    )
    .map_err(io::Error::other)?;
    let nodes = walk(args.www)?;
    let host_key = Credentials::generate_host_key()?;
    let credentials = [
        Credentials::read(Input::Password(args.password))?,
        Credentials::read(Input::LoginKey(args.login_key))?,
        host_key.credentials,
        Credentials::read(Input::Tls(args.tls))?,
    ];
    image::update_with(
        args.image,
        &credentials,
        async |fs| publish(fs, &policy, &nodes).await,
        async |fs| verify(fs, &policy, &nodes).await,
    )?;
    println!("SSH host key: {}", host_key.public_key);
    println!("SSH host key fingerprint: {}", host_key.fingerprint);
    Ok(())
}
