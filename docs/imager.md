# Imager command reference

`imager` is the host tool in `src/imager` for creating Motor OS disk images,
changing guest permissions, resizing the data partition, and replacing SSH
or TLS credentials. It operates on image files while the VM is stopped.

## Invocation

```text
imager <REPO ROOT> debug|release <CONFIG YAML>
imager <REPO ROOT> debug|release <CONFIG YAML> --raw-output <FILENAME>
imager chmod <MODE> <IMAGE> <GUEST PATH>
imager resize -i <INPUT IMAGE> -o <OUTPUT IMAGE> --size <SIZE>
imager set ssh-password <PASSWORD> <IMAGE>
imager set ssh-key <PUBLIC KEY FILE> <IMAGE>
imager set ssh-server-key <PRIVATE KEY FILE> <IMAGE>
imager set ssl keys <DIRECTORY> <IMAGE>
```

Examples below use `imager` for the host executable. To invoke it through
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
and Motor FS data partition. It does not compile the guest binaries.
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

Source snapshots are added after static overlays and exclude `.git`, `.lorry`,
`__pycache__`, and `target` directories. Static overlays omit `devtools`
directories unless the configuration declares `/devtools` or a directory
below it. File modes come from the
[permission policy](fs-permissions.md#imager-enforcement), not host ownership
or host read/write permissions.

Configurations with assembly inputs require `MOTOR_ASSEMBLY_IMAGE_ROOT` to
name a normalized absolute host directory. Assembly paths in YAML must be
normalized relative paths. The Make recipes obtain the root from
`src/resolve-toolchain-assembly.sh --resolve`; see
[assembly resolution](assembly-resolution.md) for the build workflow.

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
See [filesystem permissions](fs-permissions.md) for runtime permission rules.

## Resize the data partition

```sh
imager resize -i original.qcow2 -o larger.qcow2 --size 4G
imager resize -i original.qcow2 -o smaller.img --size 512M
```

`resize` copies the input into an output whose **Motor FS data partition**
has the requested size. `SIZE` is a positive decimal integer followed by
uppercase `M` or `G`: `M` means MiB and `G` means GiB. This is not the total
image size or its allocated host disk space. Fractions, lowercase suffixes,
and a bare number are not accepted. `-i`, `-o`, and `--size` may appear in
any order, exactly once each.

The output suffix chooses its format: `.qcow2` for qcow2; `.img` or `.raw`
for raw. Format conversion can accompany resizing. Input and output must
refer to different files, including through hard links or symlinks. An
existing output is replaced only after the new image is complete.

The input must contain exactly one Motor FS partition, and that partition
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
its raw/qcow2 format, virtual disk size, guest permissions, and host permission
mode. They edit a private staged copy and publish it only after the update
and content checks succeed. A failure before publication leaves the original
image unchanged, including a failure during the second TLS file write.
Allow space beside the image for a copy and, with qcow2, its raw intermediate.

The image must be a regular file, not a symlink. Destination files must
already exist, and their contents and each input artifact are limited to
1 MiB. Artifact input files must be nonempty regular files. Secret destinations
(`sshd.toml` and `ssl-key.pem`) must have permissions no broader than
`rw-r-----`; use `chmod` to correct a permissive image before installing
secrets. All command arguments must be UTF-8.

SSH edits require version 1 `/system/cfg/sshd.toml`, using the shipped layout
with bare table names and existing scalar fields. Unsupported layouts,
such as inline tables or dotted assignments, duplicate fields, and missing
targets are rejected. Other fields and comments are preserved. Key strings
are escaped when inserted into TOML. Imager does not validate SSH keys,
parse TLS certificates, or check that a TLS key matches its certificate;
the caller supplies artifacts that the guest services can use.

### Set the login password

```sh
imager set ssh-password 'your-new-password' image.qcow2
```

The password is one literal argument for the existing `motor` account.
It must be nonempty, at most 1 MiB, and contain no CR, LF, or U+FEFF byte-order
mark. Spaces and other Unicode characters are preserved. It is never read
as a filename. The argument may appear in shell history or process listings.

Imager generates a fresh 32-byte salt from the host's `/dev/urandom` and sets
`users.motor.salt` and `users.motor.password_hash` to hexadecimal values for
`SHA-256(salt_bytes || password_utf8_bytes)`, matching russhd's login check.
The plaintext password is not stored in the image.

### Set the login public key

```sh
imager set ssh-key /path/to/id_ed25519.pub image.qcow2
```

Reads one UTF-8 public-key line, strips its final LF/CRLF line ending if
present, and replaces `users.motor.authorized_key`. An optional key comment
is retained. Multiple lines are rejected. The field contains a single key;
the command does not append to an `authorized_keys` file. The user's private
login key stays on the client.

### Set the SSH server private key

```sh
imager set ssh-server-key /path/to/ssh_host_ed25519_key image.qcow2
```

Reads the private-key file as UTF-8 and replaces `host_key` in `sshd.toml`.
Supply an unencrypted OpenSSH private key that russhd can load. No separate
public-key file is needed: the private-key object contains the server's
public identity. Existing clients must verify and trust the replacement
host identity when connecting again.

### Set the TLS certificate and private key

```sh
imager set ssl keys /path/to/tls image.qcow2
```

| Host input | Guest destination |
| --- | --- |
| `DIRECTORY/ssl-cert.pem` | `/system/cfg/ssl/ssl-cert.pem` |
| `DIRECTORY/ssl-key.pem` | `/system/cfg/ssl/ssl-key.pem` |

Both files are required and copied byte-for-byte in one image update. Supply
a PEM certificate chain (leaf first) and its matching unencrypted private
key. Extra files are ignored; `ca-certificates.crt` is not replaced.

Each setter changes only its selected credentials. Changing the password
leaves the login public key and server host key unchanged. To replace all
bundled credentials, set the password, login key, server key, and TLS pair.
These operations do not erase old secrets from freed filesystem blocks,
snapshots, or backups, and do not change other accounts or disable unused
authentication methods.
