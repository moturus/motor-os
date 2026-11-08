# Imager command reference

`imager` is the host tool in `src/imager` for creating Motor OS disk images
and data filesystems, adding guest directories and files, changing guest
permissions, resizing the data partition, and replacing SSH or TLS
credentials. It operates on image files while the VM is stopped.

## Invocation

```text
imager <REPO ROOT> debug|release <CONFIG YAML>
imager <REPO ROOT> debug|release <CONFIG YAML> --raw-output <FILENAME>
imager chmod <MODE> <IMAGE> <GUEST PATH>
imager mkdir [--mode <MODE>] <IMAGE> <GUEST PATH>
imager put [--mode <MODE>] <IMAGE> <HOST FILE> <GUEST PATH>
imager mkfs --size <SIZE> [--mode <MODE>] <OUTPUT IMAGE>
imager resize -i <INPUT IMAGE> -o <OUTPUT IMAGE> --size <SIZE>
imager set [--ssh-user <NAME> | --ssh-new-user <NAME>] --ssh-password <PASSWORD> -i <IMAGE>
imager set [--ssh-user <NAME> | --ssh-new-user <NAME>] --ssh-key <PUBLIC KEY FILE> -i <IMAGE>
imager set --ssh-server-key <PRIVATE KEY FILE> -i <IMAGE>
imager set --ssl-keys <DIRECTORY> -i <IMAGE>
imager publish-www <SITE DIRECTORY> --ssh-password <PASSWORD> \
    --ssh-key <PUBLIC KEY FILE> --ssl-keys <DIRECTORY> -i <IMAGE>
```

Examples below use `imager` for the host executable. Every image target in
the Makefile installs a statically linked copy as `vm_images/PROFILE/tools/imager`,
whose editing commands need neither the Motor OS toolchain nor a checkout. To invoke it through
Cargo, use the repository-selected toolchain, change to `src/imager`, and
run `cargo run --release -- <arguments>`. That directory's Cargo configuration
supplies the required build flags. Cargo's `--release` selects the host tool's
build profile; the separate `debug|release` argument selects guest build inputs.

Host paths are relative to the current working directory unless absolute;
quote arguments containing spaces. Guest paths name entries inside the image.
Editing commands detect raw versus qcow2 input by its contents, not its suffix.
`qemu-img` must be on `PATH` for operations involving qcow2. No VM, mount, or
guest service needs to run. Stop the VM and prevent concurrent image writers
before using these commands.

Successful commands exit with status 0; errors exit nonzero and report a
diagnostic. Running without arguments prints usage and exits nonzero.
`imager --help` prints the same usage to standard output and exits 0.

## Create an image

```sh
imager /path/to/motor-os release /path/to/motor-os/src/imager/motor-os-base.yaml
imager /path/to/motor-os release /path/to/motor-os/src/imager/motor-os-base.yaml \
  --raw-output custom-base.img
```

`REPO ROOT` is the Motor OS checkout containing `build/bin/`, `img_files/`,
and `vm_images/`. The built-in usage calls this argument `$MOTORH`; it is the
checkout itself, whereas the build scripts normally use the `MOTORH`
environment variable for the checkout's parent development directory.

Creation packages already-built binaries from `REPO ROOT/build/bin/PROFILE/`
and the configured file trees. It assembles the MBR, boot loader, initrd,
and Motor OS filesystem data partition. It does not compile the guest binaries.
`REPO ROOT/vm_images/PROFILE/` must already exist. The image is written there
under `img_name`, alongside `initrd` and `kloader` boot artifacts. An existing
output can be replaced. Scratch files under
`REPO ROOT/build/vm_images/PROFILE/` are cleared; direct image builds using
the same profile must not run concurrently.

`--raw-output` overrides both `img_name` and `image_format`. Its argument
must be a filename ending in `.img` or `.raw`, with no directory components.
It still writes into `vm_images/PROFILE/`. Place this option after the YAML
argument, exactly as shown.

For ordinary builds, use the [build workflow](build-motor-os.md) and Make
targets, which prepare binaries, output directories, assembly inputs, and
serialize image construction:

```sh
make base.img BUILD=release
make main.img BUILD=release
make raw.img BUILD=release
make dev.img BUILD=release
```

These produce `motor-os-base.img`, `motor-os.qcow2`, `motor-os.img` (the raw
standard image), and `motor-os-dev.qcow2`, respectively. Later rebuilding an
image replaces any customizations made directly to that output file.

### Image configuration

The YAML file is read from the supplied host path. Start from the image
descriptions in [`src/imager`](../src/imager), such as `motor-os-base.yaml`,
`motor-os.yaml`, and `motor-os-dev.yaml`.

| Field | Meaning |
| --- | --- |
| `permission_policy` | Required permission-policy file, resolved relative to the YAML file. |
| `input_files` | Required list of absolute guest destinations. Each source is `build/bin/PROFILE/` plus the destination's basename. |
| `directories` | Required list of guest directories, using normalized absolute paths. Parent directories are created as needed. |
| `static_dirs` | Required list of host trees to overlay at guest `/`. Relative source paths are resolved against `REPO ROOT`. Later overlays replace earlier files at the same destination. |
| `filesystem` | Required; currently `motor-fs`. |
| `data_partition_size_mb` | Required data-partition size in MiB (1,048,576 bytes), excluding the preceding boot partitions. |
| `img_name` | Required output path, resolved against `vm_images/PROFILE/`; normally a filename. |
| `image_format` | Required; `raw` or `qcow2`, independent of the image name's suffix. |
| `required_executables` | Optional list of host files that must exist and have an execute bit. Relative paths use `REPO ROOT`. Defaults to an empty list. |
| `assembly_dirs` | Optional list of overlay directories relative to `MOTOR_ASSEMBLY_IMAGE_ROOT`. Appended after `static_dirs`. Defaults to empty. |
| `assembly_required_executables` | Optional executable checks relative to the same assembly root. Defaults to empty. |
| `source_dirs` | Optional list of `{source, destination}` mappings. Relative host sources use `REPO ROOT`; destinations are absolute guest directories. Defaults to empty. |
| `ca_bundle` | Optional host PEM file installed as `/system/cfg/ssl/ca-certificates.crt`. Relative paths use `REPO ROOT`. The build fails unless it exists and contains only certificates; text outside PEM blocks is allowed. |

Source snapshots are added after static overlays and exclude `.git`, `.lorry`,
`__pycache__`, and `target` directories. Static overlays omit `devtools`
directories unless the configuration declares `/devtools` or a directory
below it. File modes come from the
[permission policy](fs-permissions.md#imager-enforcement), not host ownership
or host read/write permissions.

The CA bundle is added last and replaces any overlay file at its destination.
Every image configuration names the build host's
`/etc/ssl/certs/ca-certificates.crt`, so the guest trust store holds exactly
the roots the host trusted at build time: hosts with different bundles build
different images, and a rebuild picks up host CA updates. The imager prints
the bundle's certificate count and SHA-256.

Configurations with assembly inputs require `MOTOR_ASSEMBLY_IMAGE_ROOT` to
name a normalized absolute host directory. Assembly paths in YAML must be
normalized relative paths. The Make recipes pass `build/assembly/images`,
which holds the overlays of the native toolchain and of the external sources;
see [toolchain.md](toolchain.md#4-the-assembly) for the build workflow.

## Change guest permissions

```sh
imager chmod rw-r----- image.img /system/cfg/sshd.toml
imager chmod r-xr-xr-x image.qcow2 /user/bin/program
```

`chmod` changes the permissions of one existing file or directory. It is not
recursive. `GUEST PATH` must be normalized and absolute: no `.` or `..`
components, repeated slashes, or trailing slash except for `/` itself.

`MODE` is exactly nine characters: three permission triplets in **System,
Interactive, None** role order. These are Motor OS roles, not Unix
owner/group/other classes. Each triplet must be one of:

| Triplet | Access |
| --- | --- |
| `rwx` | Read, write, execute/traverse |
| `rw-` | Read and write |
| `r-x` | Read and execute/traverse |
| `r--` | Read only |
| `---` | No access |

Interactive access must be a subset of System access, and None access a
subset of Interactive access. Thus `rw-r-----` grants System read/write,
Interactive read, and None no access. Octal modes and expressions such as
`u+x` are not accepted. For directories, execute means traversal.

This offline command can change sealed entries through the image
administration API. Raw images are edited directly. Qcow2 images are
converted to a temporary raw image, edited, converted back, and replaced at
the original path. The qcow2 result retains the host file's permission mode.
`IMAGE` holds an MBR with one Motor OS filesystem partition, or a bare
filesystem made by `mkfs`.
See [filesystem permissions](fs-permissions.md) for runtime permission rules.

## Add directories and files

```sh
imager mkdir image.qcow2 /user/data
imager put image.qcow2 sys-fs.toml /system/cfg/sys-fs.toml
imager put --mode rwx------ image.qcow2 setup.sh /user/bin/setup.sh
```

`mkdir` creates one directory whose parent exists and fails if the entry
exists. `put` creates `GUEST PATH` with the contents of the regular host file,
replacing an existing file but never a directory; its parent must exist.
Guest paths follow the `chmod` rules and cannot be `/`.

Without `--mode`, the entry gets the mode the shipped
[permission policy](fs-permissions.md#imager-enforcement) gives its path, as
image creation would; for `put` the policy also uses the host file's kind:
regular, `#!` script, or ELF executable. A replaced file does not keep its
old mode. `--mode` takes a `chmod` mode that obeys the policy's rules:
directories grant System `rwx`, only System may execute a regular file, and
an ELF is executable and writable by no role.

Both commands accept the images `chmod` accepts, raw or qcow2, and update them
as `set` does: they edit a raw copy next to the image and rename the result
over the original. Raw copies stay sparse.

## Create a data filesystem

```sh
imager mkfs --size 10G data.qcow2
imager mkfs --size 512M --mode rwxr-xr-x data.img
```

`mkfs` creates an image holding one empty Motor OS filesystem of `SIZE`
(as for `resize`) without a partition table, for a
`/system/cfg/sys-fs.toml` mount that omits `partition`
([fs-permissions.md](fs-permissions.md)). The output suffix chooses qcow2 or
raw, as for `resize`, and an existing file is never replaced. The
filesystem root gets `--mode`, or `rwxrwxr-x`, which lets Interactive users
write; a mount keeps that mode. The image is sparse and readable only by its
owner; a qcow2 output's raw scratch uses the host temporary directory.
`mkdir`, `put`, and `chmod` can populate it.

To mount a new 10 GiB disk at `/user/data` in a copy of the standard image
(`tools/imager` in `vm_images/PROFILE/` is the installed copy):

```sh
cd vm_images/release
tools/imager mkfs --size 10G data.qcow2
cp motor-os.qcow2 my-os.qcow2
tools/imager mkdir my-os.qcow2 /user/data
cp ../../img_files/motor-os-base/system/cfg/sys-fs.toml .
printf '\n[[mount]]\npath = "/user/data"\ntype = "motor-fs"\ndevice = 1\n' >> sys-fs.toml
tools/imager put my-os.qcow2 sys-fs.toml /system/cfg/sys-fs.toml
MOTO_IMAGE=my-os.qcow2 ./run-chv.sh --extra-disk data.qcow2
```

## Resize the data partition

```sh
imager resize -i original.qcow2 -o larger.qcow2 --size 4G
imager resize -i original.qcow2 -o smaller.img --size 512M
```

`resize` copies the input into an output whose **Motor OS filesystem data partition**
has the requested size. `SIZE` is a positive decimal integer followed by
uppercase `M` or `G`: `M` means MiB and `G` means GiB. This is not the total
image size or its allocated host disk space. Fractions, lowercase suffixes,
and a bare number are not accepted. `-i`, `-o`, and `--size` may appear in
any order, exactly once each.

The output suffix chooses its format: `.qcow2` for qcow2; `.img` or `.raw`
for raw. Format conversion can accompany resizing. Input and output must
refer to different files, including through hard links or symlinks. An
existing output is replaced only after the new image is complete.

The input must contain exactly one Motor OS filesystem partition, and that partition
must be last. Both growth and shrinking are supported; shrinking fails if
the contents and filesystem metadata do not fit. Guest files and their
metadata are copied to a newly formatted filesystem. Earlier boot contents
are preserved, and the MBR data-partition size is updated. The input is only
read; the output inherits the input file's host permission mode.

Raw intermediates use the host temporary directory; the final staged image
is created beside the output. Allow space in both locations. Qcow2 conversion
does not preserve container snapshots.

## Replace credentials

All `set` commands replace the supplied image at the same path, preserving
its raw/qcow2 format, virtual disk size, unrelated guest permissions, and host
permission mode. They edit a private staged copy and publish it only after the
update and content checks succeed. A failure before publication leaves the original
image unchanged, including a failure during the second TLS file write.
Allow space beside the image for a copy and, with qcow2, its raw intermediate.

The image must be a regular file, not a symlink. Destination files other than
a login name's key file must already exist, and their contents and each input
artifact are limited to 1 MiB. Artifact input files must be nonempty regular
files. Secret destinations (`sshd.toml` and `ssl-key.pem`) must have permissions
no broader than `rw-r-----`; use `chmod` to correct a permissive image before
installing secrets. All command arguments must be UTF-8.

Login credentials live in `/user/cfg/russhd/users.toml` and
`/user/cfg/ssh/authorized_keys.NAME` (see
[SSH client](ssh-client.md#log-in-to-a-motor-os-server)). Imager writes both with
mode `rwxrw----`, the mode SFTP gives a new file, even when the contents stay the
same. It refuses them, before changing anything, unless each is a regular file
and None can neither write it nor replace any directory up to `/user`, and None
cannot read `users.toml`. A file that an update only consults keeps its mode.

SSH edits require version 2 `/system/cfg/sshd.toml` with the standard
`users_file` and `authorized_keys_dir` values and no user credentials, and a
`users.toml` in the shipped layout, with bare `[users.NAME]` tables. Credential
paths read from inside an image are never followed. Unsupported layouts, such
as inline tables or dotted assignments, duplicate fields, and unknown fields are
rejected. Other fields and comments are preserved. Key strings are escaped when
inserted into TOML. Imager does not validate SSH keys, parse TLS certificates,
or check that a TLS key matches its certificate; the caller supplies artifacts
that the guest services can use. Nor does it check the salts and hashes it leaves
in place, so it can report success on a registry that `russhd` refuses.

### Select a login name

`--ssh-password` and `--ssh-key` apply to the name `motor` unless a selector says
otherwise. `--ssh-user NAME` selects a name that has a record.
`--ssh-new-user NAME` creates one, and requires that neither the record nor its
key file exists, so orphaned keys are not reactivated. `--ssh-server-key` and
`--ssl-keys` take no selector.

```sh
imager set --ssh-new-user alice --ssh-password 'new-password' -i image.qcow2
imager set --ssh-user alice --ssh-key alice.pub -i image.qcow2
```

A name is 1 to 64 ASCII letters, digits, `_`, or `-`. Imager refuses a 1,025th
name, and any edit of a registry already past that limit, because `russhd`
denies every login with such a registry.

### Set the login password

```sh
imager set --ssh-password 'your-new-password' -i image.qcow2
```

The password is one literal argument for the selected name. It must be
nonempty, at most 1 MiB, and contain no CR, LF, or U+FEFF byte-order
mark. Spaces and other Unicode characters are preserved. It is never read
as a filename. The argument may appear in shell history or process listings.

Imager generates a fresh 32-byte salt from the host's `/dev/urandom` and sets
that name's `salt` and `password_hash` in `users.toml` to hexadecimal values for
`SHA-256(salt_bytes || password_utf8_bytes)`, matching russhd's login check,
adding the fields to a record that lacks them. The plaintext password is not
stored in the image.

### Set the login public key

```sh
imager set --ssh-key /path/to/id_ed25519.pub -i image.qcow2
```

Reads one UTF-8 public-key line, strips its final LF/CRLF line ending if
present, and replaces the selected name's whole key file, creating it if
missing. An optional key comment is retained. Multiple lines, and a line over
16 KiB or containing NUL, are rejected. To add a key to a list, use
[`ssh-copy-id`](ssh-client.md#log-in-to-a-motor-os-server) on a running system.
The user's private login key stays on the client.

### Set the SSH server private key

```sh
imager set --ssh-server-key /path/to/ssh_host_ed25519_key -i image.qcow2
```

Reads the private-key file as UTF-8 and replaces `host_key` in `sshd.toml`.
Supply an unencrypted OpenSSH private key that russhd can load. No separate
public-key file is needed: the private-key object contains the server's
public identity. Existing clients must verify and trust the replacement
host identity when connecting again.

### Set the TLS certificate and private key

```sh
imager set --ssl-keys /path/to/tls -i image.qcow2
```

| Host input | Guest destination |
| --- | --- |
| `DIRECTORY/ssl-cert.pem` | `/system/cfg/ssl/ssl-cert.pem` |
| `DIRECTORY/ssl-key.pem` | `/system/cfg/ssl/ssl-key.pem` |

Both files are required and copied byte-for-byte in one image update. Supply
a PEM certificate chain (leaf first) and its matching unencrypted private
key. Extra files are ignored; `ca-certificates.crt` is not replaced.

Each setter changes only its selected credentials. Changing a password
leaves the login's keys, every other name, and the server host key unchanged.
To replace all bundled credentials, set the password, login key, server key,
and TLS pair. These operations do not erase old secrets from freed filesystem
blocks, snapshots, or backups, and do not change other names or disable unused
authentication methods.

## Publish a website

```sh
imager publish-www /path/to/site --ssh-password 'your-new-password' \
    --ssh-key /path/to/id_ed25519.pub --ssl-keys /path/to/tls -i image.qcow2
```

All options are required, each exactly once, in any order after the site
directory. They mean the same as for `imager set`, for the name `motor`. In one
staged update, the command:

- replaces `/user/www-home` with a copy of the site directory;
- writes `/user/bin/www`, a rush script that runs `httpd-axum` on
  `0.0.0.0:443`, serving `/user/www-home` with the TLS pair in
  `/system/cfg/ssl`;
- sets the login password, login public key, and TLS certificate and key;
- installs a newly generated Ed25519 SSH server key.

The image must contain `/user/bin/httpd-axum`: the standard and developer
images do, the base image does not. The site directory may contain only
directories and regular files. Symlinks and special files are rejected, and
hidden files are copied. Copied entries get the shared permission policy's
`/user` modes (`rwxrwxr-x` for directories, `rw-rw-r--` for files); host
execute bits are not carried over. An existing `/user/www-home` is removed
first, and an existing `/user/bin/www` is overwritten.

The server private key is generated in memory from the host's `/dev/urandom`
and written only to the image. The command prints the matching public key
and its SHA-256 fingerprint:

```text
SSH host key: ssh-ed25519 AAAA...
SSH host key fingerprint: SHA256:...
```

Add the key to the client's `known_hosts` as `[ADDRESS]:2222 ssh-ed25519 AAAA...`,
or compare the fingerprint on first connect. In the VM, run `/user/bin/www`
to start serving.
