# Exact Motor FS permissions with `chmod`

## Goal

Add a Motor-native `chmod` command to sysbox that sets the permissions for all
three process roles in one atomic filesystem operation. The command uses the
nine permission characters printed by `ls -l`; it does not implement Unix
owner/group/other or special permission bits. Also provide an offline host
command for editing permissions in VM images and a configurable System-role
serial-console session for administration and automated tests.

## Command syntax

```text
chmod MODE PATH...
```

`MODE` is exactly nine ASCII characters, split into three triplets in the same
order as `ls -l`: **System, Interactive, None**. For example:

```text
ls -l app
-rwxr-xr-- 123 app

chmod rwxr-xr-- app
```

The leading file-type character from `ls -l` (`-` or `d`) is not part of the
mode. Each triplet must be one of:

```text
rwx  rw-  r-x  r--  ---
```

These are the only Motor FS permission values: `r` gates `w` and `x`, so forms
such as `-w-` and `--x` are invalid. The complete mode must also satisfy
Motor FS monotonicity:

```text
None ⊆ Interactive ⊆ System
```

There are no symbolic updates (`+x`, `-w`, or `=`), numeric modes, role names,
or recursive `-R` mode in the initial command. Each invocation describes the
exact final state and is independent of the entry's previous permissions.

The command accepts one or more paths. Each path is changed atomically, but an
invocation covering multiple paths is not atomic as a group. It attempts every
path, reports each failure, and exits nonzero if any path failed. `--help`
prints the syntax and role order. The mode is always the first positional
operand, including the all-empty mode `---------`; it is not parsed as an
option.

## Host image syntax

The host imager accepts the same mode and changes entries in an offline VM
image:

```text
imager chmod MODE VM_IMAGE FILE_PATH
imager chmod rwxr-xr-- vm_images/debug/motor-os.qcow2 /system/bin/app
```

`VM_IMAGE` is explicit because imager has no implicit image target. `FILE_PATH`
is a normalized absolute path inside the image. The initial command
supports both raw MBR images and qcow2 images containing one Motor FS data
partition, and rejects an absent or ambiguous Motor FS partition.

Imager opens Motor FS as `Role::System`, as it already does for filesystem
operations while building an image. It resolves paths through the normal
System-authorized filesystem API, but changes the mode through an explicit
host-only administrative setter. That setter requires `caller == Role::System`
and validates the complete mode and cross-role monotonicity, but permits the
System value to widen. This lets an offline image editor temporarily make an
`r-x` System file or directory writable, edit or add entries through ordinary
System calls, and restore the intended mode afterward.

The administrative setter is an inherent `MotorFs` API behind an opt-in Cargo
feature (called `image-admin` below) and `cfg(target_os = "linux")`. Imager
enables the feature; Motor OS builds do not, and the method is not part of the
`FileSystem` trait or any IPC protocol. Enabling `image-admin` for a Motor OS
target is a compile error. There is no administrative path resolver: if System
cannot traverse the path, imager cannot reach it through this command. The
image must not be running while it is edited.

For a raw image, imager locates the Motor FS partition from the MBR and opens a
bounded block-device view of that partition. Both parts are new code: today
imager only writes a fresh MBR while building an image, and the data partition
starts on a 512-byte sector boundary that is not 4 KiB-aligned, so the view
must apply a byte offset. Extend `AsyncFileBlockDevice` with a validated
`open_region(path, offset, length)` constructor and a base-offset field rather
than adding another file-backed block-device implementation. For qcow2, imager
invokes the `qemu-img` host binary that image builds already require: it
converts to a temporary raw image, edits that image, converts back to a
temporary qcow2 image, and renames over the original only after all steps
succeed. Temporaries are staged in the image's own directory so the final
rename cannot cross filesystems.

## Authority and atomicity

The filesystem continues to derive the caller's role from the authenticated
connection. For every field whose requested value differs from its old value,
the existing authority rules apply:

- A caller may change a lower role's permissions in either direction.
- A caller may only narrow its own role's permissions.
- A caller may not change a higher role's permissions.

Unchanged higher-role fields are allowed in the full request; this matters
because `may_set` rejects even a no-op write to a higher role, so the
implementation must diff before authorizing (`create_entry` documents and
works around the same property). After authority checks, the filesystem
validates monotonicity against the complete requested state. It then writes
all three values in one transaction or writes none of them. This exact setter
does not silently cascade or clamp fields; an invalid requested state is
rejected. That is a deliberate divergence from the existing single-role
setter, which rejects a requested value above the next-higher role's ceiling
and narrows lower roles to preserve monotonicity; both setters coexist.

The existing single-role permission API remains available for current users
such as the POSIX compatibility and SFTP paths. Adding a separate exact setter
keeps this patch focused and avoids changing their semantics. Note that the
existing IPC message carries no target role — sys-io hardcodes the caller as
the target — so the cross-role branch of the authority rules is unreachable
over IPC today; the new message exposes it for the first time.

Runtime exact changes always follow the authority rules above, including the
rule that System cannot widen its own value. The Linux-only image-admin method
is the sole exception: after requiring a System caller, it may install any
valid monotonic `RolePermissions` value. Runtime System processes therefore
cannot undo System sealing.

Represent a complete permission state with a named value rather than a bare
array:

```rust
RolePermissions {
    system,
    interactive,
    none,
}
```

Use it in the full-state filesystem APIs, IPC helpers, and entry creation, then
convert to Metadata's role-indexed bytes at the storage boundary. This keeps
the displayed System/Interactive/None order from being confused with the
internal None/Interactive/System discriminant order.

## System serial-console sessions

This is not possible through the current `tty:` configuration alone. sys-init
hard-codes an Interactive capability mask for sys-tty, and sys-tty then
hard-codes an Interactive mask for the rush process it starts.

Extend the sys-init configuration with an optional role name on the tty line:

```text
tty:/system/services/sys-tty
tty:system:/system/services/sys-tty
```

The first form remains backward compatible and uses the current Interactive
role. The second selects System; the accepted explicit values are `system`,
`interactive`, and `none`. sys-init continues to own sys-tty's fixed
operational capability set (`CAP_IO_MANAGER`, `CAP_SPAWN`, `CAP_LOG`, and
`CAP_SPAWN_DETACHED`) and adds only the capability bit for the selected role.
This avoids exposing a brittle numeric mask or allowing the tty configuration
to omit required capabilities.

sys-tty must propagate its own derived role to the console command: a System
sys-tty grants `CAP_SYS`, an Interactive sys-tty grants `CAP_INTERACTIVE`, and
a None-role sys-tty grants neither. It does not grant the console command
`CAP_IO_MANAGER`. Thus the explicit System tty configuration produces an
interactive serial shell with System filesystem authority, while existing
images keep their current Interactive console unless their configuration is
changed.

Motor's global default child capabilities continue not to propagate System
authority. Rush is the explicit session boundary: when rush itself has the
System role, its Motor spawn path explicitly grants System to ordinary external
commands. An explicit per-command `MOTOR_OS_CAPS` assignment may still request
a narrower child. Rush's `spawn-detached` grant must preserve the shell's
System role as well as adding `CAP_SPAWN_DETACHED`. This shell-specific policy
makes commands and scripts in a System serial session consistently System
without changing the safe default for other System services.

Rush-compatible shebang shims such as `/system/bin/chmod` run in-process in
rush, so they do not introduce an intermediate default-role spawn. Both
`chmod` and `sysbox chmod` therefore work with the session role.

Hardening `/system/cfg/sys-init.cfg`, `/system/cfg/sys-tty.cfg`, or other
configuration files is explicitly out of scope. Until that follow-up, write
access to these files can affect the privilege of a subsequent boot.

## Implementation steps

1. Add `set_all_permissions` to the filesystem stack.
   - Add a named `RolePermissions` type to `async-fs` and use it for complete
     permission states, including `create_entry`; keep Metadata's raw bytes
     private and role-indexed.
   - Add a new request and encode/decode helpers in `moto-sys-io`; carry all
     three permission values in one message. They fit in the fixed message
     payload after the entry id, with no io_page. Extend the contiguous
     command-id range in `known_cmd` to cover the new command.
   - Add `FsClient::set_all_permissions(entry_id, permissions)` in `moto-io`.
   - In `sys-io`, pass the connection's trusted caller role to the filesystem.
   - Extend the `async-fs::FileSystem` trait and Motor FS implementation with
     an exact full-state operation.
   - Add one Motor FS transaction that reads the old state, authorizes only
     changed fields, validates the complete new state with the existing
     `perms_monotonic`, and writes all three bytes atomically. All three live
     in the entry's single block, so the existing transaction machinery
     already provides all-or-nothing; `do_set_permissions_txn` is the model.
     Update `Metadata.modified` in the same transaction, matching the existing
     setter.
   - Add a private authority mode to the exact transaction so its validation
     and write logic can be shared without exposing an unchecked operation.
     The runtime mode applies `may_set`; the image-admin mode first requires
     `caller == Role::System` and then permits widening any role while still
     requiring monotonicity.
   - Expose the image-admin mode only as an inherent `MotorFs` method under
     `cfg(all(feature = "image-admin", target_os = "linux"))`. Add a compile
     error for `feature = "image-admin"` on Motor OS, and do not add the method
     to `async-fs::FileSystem`, `moto-io`, `moto-sys-io`, or sys-io.
   - Update `PERMISSIONS_DESIGN.md` to describe the exact setter beside the
     cascading single-role setter and document the host-only administrative
     exception.

2. Add `sysbox chmod`.
   - Parse the fixed-width mode without any target-OS conditionals.
   - Parse directly into `RolePermissions`, whose named fields match the
     displayed System/Interactive/None order.
   - Resolve each path to its Motor FS entry and call the new client API,
     reusing the direct `FsClient` resolution already used by `ls`.
   - Add the command module, dispatcher/help entries, and the
     `/system/bin/chmod` rush shim. Commit the shim with the host executable
     bit set: imager derives image permissions from host file modes.

3. Add host image editing to imager.
   - Add the `chmod` subcommand without changing the existing image-build
     invocation; dispatch on the subcommand word before the existing
     fixed-arity argument check.
   - Enable motor-fs's `image-admin` feature in imager's dependency.
   - Add an offset- and length-bounded block-device view for a Motor FS
     partition in a raw MBR disk. Read the partition table with the existing
     `mbrman` dependency, which indexes partitions from 1 where sys-io's own
     parser indexes from 0. The view needs a byte offset: the data partition
     is sector-aligned but not 4 KiB-aligned. Implement the view through
     `AsyncFileBlockDevice::open_region`.
   - Handle qcow2 through temporary raw/qcow2 conversions and publish the
     changed image only on success. The qcow2-to-raw direction is a new
     `qemu-img` invocation; the raw-to-qcow2 helper already exists.
   - Open Motor FS and resolve the in-image path through the normal
     `FileSystem` API as `Role::System`. Apply the exact mode through the
     Linux-only administrative setter with `caller = Role::System`.

4. Make the tty role configurable.
   - Extend the dependency-free sys-init parser to accept both legacy
     `tty:COMMAND` and explicit `tty:ROLE:COMMAND` lines. The tty value stays
     a bare program path; unlike `svc:` lines, it takes no arguments.
   - Construct sys-tty's fixed operational mask plus the selected role bit
     instead of always adding `CAP_INTERACTIVE`.
   - Make sys-tty pass its derived role to the console command while retaining
     only the operational capabilities that command needs.
   - In rush's Motor spawn policy, explicitly propagate System from a System
     rush to ordinary children unless the command supplies its own capability
     mask. Preserve System in the detached-program grant as well. Do not change
     `moto-sys::default_child_capabilities`.
   - Update `docs/process-roles.md` §7, which records the current sys-init and
     sys-tty masks as normative.

5. Add tests without adding unit tests to sysbox.
   - Add Motor FS tests for authorization, monotonicity, exact results, and
     rollback on a rejected full-state request. Under the Linux image-admin
     feature, verify that non-System callers are rejected and System may widen;
     the ordinary runtime setter must continue rejecting the same widening.
   - Add `systest` coverage for the new IPC path and for both `sysbox chmod`
     and `/system/bin/chmod`.
   - Exercise every legal triplet, malformed modes, non-monotonic modes,
     multiple paths, missing paths, partial multi-path failure, and round-trip
     the resulting nine characters through `ls -l`. Parse and assert the
     permission field itself, and operate on dedicated scratch files because
     full-test.sh asserts the permissions of shipped paths.
   - Test imager chmod on disposable raw and qcow2 images, including exact
     permission verification after reopening and preservation of the original
     qcow2 image on failure. Cover lower-role widening/narrowing, System
     narrowing and widening, temporarily widening an `r-x` file and directory
     to edit/add content, restoring their modes, and failure to traverse a path
     denied to System. Keep the fixtures small: step 6 runs the full suite six
     times.
   - Test both sys-init tty forms. Build the System-tty image as a new imager
     configuration that overrides `sys-init.cfg` through a later `static_dirs`
     entry, with a Makefile target. Boot it and drive the serial console
     through a FIFO as `test-tui.sh` does; verify via `ps` that sys-tty and
     the console shell hold the System role; run the System-role chmod cases
     through both `chmod` and `sysbox chmod` without per-command grants. Also
     verify an ordinary external command and a detached pass-listed command
     retain System. Do not run the systest suite on this image — it asserts the
     standard image's Interactive console roles.
   - Keep the tests transitively included in `src/tests/full-test.sh`; the
     motor-fs and imager suites are already invoked there, so only the new
     boot script needs wiring in, within the script's global timeout.

6. Format and validate the core-OS patch. Run debug and release builds, check
   for new compiler or clippy warnings, and run `src/tests/full-test.sh` three
   times each in debug and release configurations before committing.
