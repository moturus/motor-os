# Secure system logging and runtime filesystem permissions

## Summary

Secure runtime file and directory defaults and centralize logging through
System-role strobe while preserving the
`None ⊆ Interactive ⊆ System` permission invariant.

## Planned changes

- Permit the exact self-role transition `rw-` → `r-x` for every role,
  including System. Keep all other self changes narrow-only. This is the one
  case in which a role, System included, widens its own byte: it adds `x` while
  giving up `w`, and the same role cannot regain `w` from `r-x`, so narrowing
  `w` off remains a permanent self-role seal. The System exception is
  intentional: a user working at a System-role interactive console must be
  able to create or replace a shell script, write it while it is `rw-`, and
  finalize it as `r-x`. Editing a finalized script replaces it through a
  writable parent directory; its System byte never transitions back to `rw-`.
  System may separately grant `r-x` to lower roles when the script is intended
  for them. Narrowing System to `rw-` alone is no longer permanent; a seal that
  must also deny listing or execution narrows to `r--` or `---`. The cap and
  cascade rules are unchanged: the ceiling must already hold `x`, and lower
  roles lose `w`.

  Existing behavior, retained and re-tested rather than implemented: System
  may change Interactive and None freely, and Interactive may change None
  freely, including changing a directory from `r-x` to `rwx`, provided the
  resulting complete mode remains monotonic (`may_set` plus the ceiling check
  in `async-fs`).
- Set new regular-file defaults relative to the creator:

  | Creator | System | Interactive | None |
  |---|---|---|---|
  | System | `rw-` | `r--` | `r--` |
  | Interactive | `rwx` | `rw-` | `r--` |
  | None | `rwx` | `rwx` | `rw-` |

  Set new-directory defaults to `rwx` for the creator and every higher role,
  and `r-x` for every lower role:

  | Creator | System | Interactive | None |
  |---|---|---|---|
  | System | `rwx` | `r-x` | `r-x` |
  | Interactive | `rwx` | `rwx` | `r-x` |
  | None | `rwx` | `rwx` | `rwx` |

  sys-io computes these defaults from the connection's role and the entry
  kind in `on_cmd_create_file` / `on_cmd_create_dir`, replacing the hardcoded
  `[Rwx; 3]`. sys-io's internal creation already passes explicit permissions
  and is unaffected. While modifying these handlers, correct the pre-existing
  `on_cmd_create_dir` response that labels the new entry as a file, and cover
  the response kind directly even though the current high-level client ignores
  that field.
- Add `FsClient::create_entry_with_permissions`, backed by a distinct sys-io
  request that carries a complete `RolePermissions`. Sys-io passes the caller's
  role and requested mode to Motor FS so its existing creation-authority and
  monotonicity checks apply before the entry is linked. Keep `create_entry` as
  the default-producing API, and do not change the Rust standard library or
  moto-rt interfaces.
- Make every runtime producer of executables perform the `rw-` → `r-x` step.
  Motor FS checks the `w` byte on every `write` and `resize`
  (`motor-fs/src/fs.rs`), not at open time, so a file born `r-x` — through
  the exact-permissions API or otherwise — can never receive its contents
  through any handle. An executable is therefore always created `rw-`,
  written, and then moved to `r-x` once its contents are complete. The move
  is one-way: replacing an executable deletes and recreates it, which needs
  only parent-directory `w`, and an `O_TRUNC` open of an `r-x` file fails.

  Audit the whole repository before changing the defaults. The tracked list
  includes russhd SFTP, sysbox `cp`, every production use of `std::fs::copy`
  followed by permission preservation, Gears self-host installation, Lorry
  archive extraction and Git materialization, Lorry bundle/install helpers,
  the executable-permissions tests, and the out-of-tree compiler/linker. For
  each match, either show that it never produces an executable on Motor OS or
  change it to finalize a completed file as `r-x`. Keep this inventory in the
  implementation commit so a search for `set_permissions`, `set_perm`,
  `set_file_perm`, and executable `PermissionsExt` modes has no unexplained
  Motor OS match.

  - **russhd SFTP.** `open` currently ignores the requested attributes,
    `mkdir` applies its attribute mode to the new directory, and
    `setstat`/`fsetstat` map any `x` bit to `rwx`, which is rejected.

    What the OpenSSH client sends (`sftp-client.c`): `put` stats the local
    file and sends its mode (`perm & 0777`, so `0755` for a host executable)
    in the OPEN attributes of every upload, not only with `-p`; with `-p` it
    also sends FSETSTAT with the same mode and times after the last WRITE and
    before CLOSE. `put -R` sends a mode derived from the local directory's
    mode in MKDIR attributes before uploading that directory's contents, and
    SETSTAT on the directory after they are uploaded. `chmod` sends a
    path-based SETSTAT carrying only the mode. `get -p` and `ls -l` read the
    mode back from stat. The OpenSSH server releases a handle on CLOSE
    whatever `close()` returns and reports the failure as a status; the client
    reports a CLOSE failure and never retries it. Confirm these sequences
    against the installed client with `sftp -v` before relying on them.

    Map a requested mode by entry kind. Regular file: `r-x` when any `x` bit
    is set, `rw-` when any `w` bit is set, else `r--`. Directory: `x` is
    traversal, so `rwx` when any `w` bit is set, else `r-x`; apply directory
    modes immediately on MKDIR and SETSTAT, which keeps a `put -R` target
    writable while its contents arrive and re-states it afterwards. For
    files:

    - An OPEN attribute that maps to a non-writable mode (`r--` or `r-x`) on a
      writable handle is stored as a pending final mode and is not applied
      while the upload still needs to write. A mapped `rw-` mode is applied
      immediately. On a non-writable handle every mapped mode is applied
      immediately.
    - An `x`-bearing FSETSTAT on a writable handle replaces that pending final
      mode; on a non-writable handle it is applied immediately. A mode-bearing
      non-`x` FSETSTAT clears any pending OPEN mode and is applied immediately:
      FSETSTAT is an explicit operation on an already-open file, so a client
      that changes it to `r--` accepts that later writes through the handle
      fail. An FSETSTAT carrying only times does not disturb a pending mode.
    - SETSTAT has no handle to defer against, so its mapped mode is applied
      immediately as an explicit chmod of an already-addressable file.

    CLOSE flushes and applies a pending `r--` or `r-x` only if that flush
    succeeds, then always releases the handle. It reports a failure status if
    flushing or finalization failed — the OpenSSH server's behavior. A failed,
    abandoned, or disconnected upload whose mode is still pending therefore
    remains writable but non-executable. A harness that uploads over an
    existing `r-x` executable must delete it first. Reported modes fold `r-x`
    to `555`; `test-sftp.sh`'s executable round-trip expectations — the
    uploaded file and its guest `cp -r` copy — change from `777` to `555`, and
    the plain ones stay `666`.
  - **`std::fs::copy` and sysbox `cp`.** rt.vdso's `copy` — the `fs_copy`
    vtable entry behind `std::fs::copy` — preserves the source permission
    reported to the calling role, as std's contract requires. It reads that
    permission before creating or truncating the destination, ensures the
    destination's caller-role byte is `rw-` before copying any contents (also
    under the old `rwx` default), and then applies the final mode: `r--` stays
    `r--`, `rw-` stays `rw-`, and `r-x` stays `r-x`. The legacy
    writable-executable mode `rwx` finalizes as `r-x`, consistently with the
    executable-production rule above; `---` cannot be copied by that role
    because opening the source for reading fails. If establishing the
    writable staging mode or finalization fails, `std::fs::copy` reports the
    error; a finalization failure leaves the destination writable but
    non-executable rather than exposing a partial executable. This is a
    vdso-only change with no std or moto-rt interface change, and it is what
    makes Cargo's uplifted artifacts executable (below).

    Preserving `r--` means the documented recovery procedure for a sealed file
    can no longer use `std::fs::copy`. Replace it with an explicit
    read/create/write/delete/rename procedure: create a different destination
    with the ordinary `rw-` default and transfer the bytes through reads and
    writes before replacing the original. sysbox `cp` needs no
    file-permission handling of its own beyond `std::fs::copy`; directory
    copies keep the creator-relative `rwx` default rather than copying a source
    directory's narrower mode, and directory-copy tests verify that.
  - **Other in-tree producers.** Change Motor-specific Lorry archive and Git
    materialization paths that currently request `rwx` to request `r-x` only
    after their output is complete. Apply the same rule to every audited
    Gears, Lorry, and test producer; do not rely on a host `0o7xx` mode mapping
    to `rwx`.
  - **Toolchain (out of tree).** Do not infer executable creation from
    `open(O_CREAT, mode)` and chmod generically at `close()`: `O_CREAT` may open
    an existing file, and duplicated or independently opened descriptors make
    close-time inference incorrect. Instead, make the Motor linker-output path
    explicitly finalize a successfully written output as `r-x`. Expose the
    existing fd permission operation to C with a minimal
    `moto_rt_set_file_perm` wrapper in `moto-rt-cabi`, implement the required
    mlibc `fchmod` path with it, and have the Motor compiler/linker finalizer
    call that operation only after output and flushing succeed. This changes
    moto-rt-cabi, but not the Rust standard library or moto-rt's Rust API or
    vtable. Record the exact mlibc/toolchain commits and rebuilt image artifacts
    in the implementation change.

    The linker finalizer alone is not sufficient. Cargo places every artifact
    with `link_or_copy`, which tries `hard_link` and falls back to
    `std::fs::copy` on any error, and Motor has no hard links; Cargo then
    executes the uplifted copies — each build script under
    `target/…/build/<pkg>-<hash>/` and each binary under `target/<profile>/`.
    Those copies are executable only because `std::fs::copy` preserves `x`
    (above), so that vdso change is a prerequisite. Land the toolchain changes
    before switching the default file mode, and validate them by mode, not by
    execution: under the old permissive default everything runs regardless,
    so assert that a freshly linked output and its uplifted copy read back
    exactly `r-x`, which the finalizer produces by narrowing `rwx` under the
    old default too. `test-dev-sources.sh --release` passing at that point
    shows only that nothing regressed; its pass after the default switch is
    the real gate.
- Make `CAP_LOG` a grantor-controlled capability.

  Intention: `CAP_LOG` admits a process to the kernel log and, after this
  change, to the record channel of System-role strobe. The set of holders is
  chosen by trusted grantors — System through configuration or an explicit
  mask, Interactive through an explicit mask only — and must not spread by
  default or from a least-privilege process. A None process may hold and use
  `CAP_LOG` for its own diagnostics, but it is never a grantor.

  This builds on the current policy. The kernel's subset rule already limits a
  non-System parent to capabilities it holds, and `default_child_capabilities`
  already intersects a non-System parent's default with its own capabilities,
  so Interactive can only ever pass on a `CAP_LOG` it holds and a None parent
  without `CAP_LOG` already cannot pass it. What changes:

  - Interactive defaults omit `CAP_LOG`; an Interactive parent that holds it
    grants it only through an explicit child capability mask.
  - A None parent may not delegate `CAP_LOG` at all, even when it holds it.
    This is one role-sensitive check added beside the kernel's subset rule,
    and `default_child_capabilities` omits `CAP_LOG` for None parents so an
    unadorned spawn from a `CAP_LOG`-holding None process still succeeds.
  - A System spawner keeps `CAP_LOG` in its default grant and may grant it
    regardless of whether it holds it (existing behavior).
  - All other non-System child capabilities remain subject to the existing
    subset rule.
- Route rt.vdso diagnostics to stderr instead of the kernel log. rt.vdso owns
  the process's stdio, so its `log` facade output and its `log_to_kernel`
  vtable entry, which backs `moto_rt::moto_log!`, write to the process's stderr.
  The backtrace is a separate vtable path: change rt.vdso's
  `log_backtrace(rt_fd < 0)` branch to use the same stderr-first helper instead
  of calling `SysRay::log` directly. The helper falls back to `SysRay::log`
  only when the stderr write fails and the process holds `CAP_LOG`. Implement
  the stderr side by cloning stderr's underlying `StdioPipe` reference and
  writing to that pipe directly, without going through `SelfStdio::with_impl`,
  the POSIX descriptor table, or the `log` facade. Thus a warning emitted while
  a stdio relay or reclaim path owns the normal stdio state cannot wait on its
  own claim. Guard the helper against recursion, never log a pipe-write
  failure, and treat a short write as failure for fallback purposes. A
  reentrant call skips stderr and uses the kernel fallback only when it has
  `CAP_LOG`; otherwise it is dropped. The helper does not add level filtering:
  it routes every record admitted by rt.vdso's configured `log` level,
  including debug records in a debug build, to stderr. Runtime logic and the
  vtable ABI in moto-rt remain untouched, but update moto-rt's
  `log_backtrace` documentation because a negative descriptor now selects the
  process diagnostic sink rather than unconditionally selecting the kernel
  log. Ordinary commands, which no longer hold `CAP_LOG`, therefore keep their
  loader warnings, panic message, and backtrace on the stderr their parent or
  terminal already captures. System services that call `SysRay::log` or
  `moto_sys::moto_log!` directly hold `CAP_LOG` and are unchanged.
- Audit every default and explicit spawn mask in sys-init, sys-tty, russhd,
  rush, and the tests. Preserve intentional service grants, remove assumptions
  that Interactive defaults contain `CAP_LOG`, and explicitly launch the full
  systest suite with `CAP_SPAWN | CAP_LOG | CAP_INTERACTIVE` (`0x4c`) from each
  full-test or soak harness that runs it. Before this change, `0x4c` is what an
  SSH shell's unadorned spawn yields; afterward the explicit mask is required.
  The focused lifetime suite keeps `0x6c`.
- Change `/system/logs` to `rwxr-x---` and log files to `rw-r-----` across the
  shared image policy. Use `rwxr-x---` for the directory, `rw-r-----` for its
  regular-file profile, and the schema-valid fail-closed `r-xr-----` for both
  script and ELF profiles. Script and ELF profiles require System execute and
  ELFs may not be writable; image validation also verifies that no script or
  ELF is actually shipped under `/system/logs`. Promote strobe to
  `CAP_SYS | CAP_LOG`; lower-role services continue submitting records through
  `moto_log` and never write log files directly. Strobe uses the
  exact-permissions creation API so a new log is linked with its final mode
  before it is opened or written; rename preserves that mode during rotation.
  Strobe gains a `moto-io` dependency and runs that call on a local executor,
  as sysbox does.
- Harden the `sys-log` channel before enabling System privilege. The
  requirements below apply to the `sys-log` IPC server only; strobe's
  `moto-stats-registry` server stays open to every role, because `sysbox
  stats` and `free` run as ordinary commands without `CAP_LOG`.

  - Require `CAP_LOG` using connection-bound peer capabilities.
  - Enforce a CONNECT-before-LOG state machine and reject repeated CONNECT.
  - Bounds-check payload lengths and validate the server-issued tag ID.
  - Reject simultaneous connections whose sanitized tags resolve to the same
    filename; allow reuse after disconnect.
  - Return `E_NOT_ALLOWED`, `E_INVALID_ARGUMENT`, or `E_ALREADY_IN_USE` as
    appropriate instead of panicking on client-controlled input.
  - Reply and disconnect after unauthorized, malformed, or invalid-state
    requests. A well-formed initial CONNECT rejected only because its canonical
    tag is already active remains unregistered and may retry with another tag;
    CONNECT after a successful CONNECT is invalid and disconnects.
  - Handle malformed and unregistered disconnects without assertions or failed
    channel sends terminating the service.
  - Replace the `moto_log` client's `todo!()` on a failed LOG RPC with a
    stderr fallback that disables further RPCs, so a server-side disconnect
    never panics a client.

## Tests and acceptance

- Cover the complete authority table, the exact `rw-` → `r-x` exception for
  every role including System, ceiling and cascade behavior, and all
  creator-relative file and directory defaults. Verify `r-x` never regains
  `w` through a self-role change, and that a role still cannot change its own
  byte from `r-x` to `rwx`. At a System-role console, create and write a shell
  script as `rw-`, finalize and run it as `r-x`, prove in-place editing and a
  self-role transition back to `rw-` fail, then replace it through its writable
  parent and finalize the replacement. Re-verify the existing behavior that
  System and Interactive can change lower-role directories from `r-x` to
  `rwx`.
- Verify exact-permissions creation is atomic, rejects non-monotonic or
  unauthorized modes without creating an entry, and leaves ordinary creation
  on the creator-relative defaults. Verify a file created `r-x` rejects
  `write` and `resize` through its creating handle.
- Verify the executable producers: an SFTP upload of a host-executable file
  reads back as `555` and runs on the guest, an ordinary writable upload reads
  back as `666`, and a host-read-only upload reads back as `444`. Verify OPEN
  defers both `r--` and `r-x` until CLOSE, FSETSTAT has the immediate/deferred
  behavior specified above, path-based SETSTAT applies immediately, and a
  `put -R` of a tree holding a host-executable file and an empty directory
  succeeds and leaves its directories `rwx` and the file `r-x`. A disconnected
  partial upload remains writable and non-executable and its handle is
  released; `put` over an existing executable fails until it is deleted.
  Verify `std::fs::copy` preserves `r--`, `rw-`, and `r-x` exactly, folds a
  legacy `rwx` source to `r-x`, and makes the `r-x` copy runnable; verify the
  explicit read/create/write/delete/rename recovery procedure produces an
  editable replacement for an `r--` file. `sysbox cp` of an installed ELF
  yields a runnable `r-x` copy. Exercise the audited Lorry
  archive/materialization and Gears installation paths on Motor OS.
  `test-dev-sources.sh --release` must build and run a fresh binary and a Cargo
  build script produced by the rebuilt toolchain, and both the linked output
  and its uplifted copy must read back `r-x`.
- Verify a System spawner grants `CAP_LOG` by default and can grant it
  explicitly; an Interactive spawner that holds it can grant it only with an
  explicit mask; Interactive defaults omit it; a None spawner cannot grant it
  even when the parent holds it; and an unadorned spawn from a
  `CAP_LOG`-holding None parent still succeeds without it.
- Verify an Interactive child without `CAP_LOG` sends both an ordinary
  `moto_rt::moto_log!` marker and its complete panic message and backtrace to a
  piped stderr, and that `SysRay::log` returns `E_NOT_ALLOWED` for it. At a
  configured debug level, verify a `log::debug!` marker also reaches stderr.
  Exercise logging while the normal stderr state is claimed by a focused
  relay/reclaim test and prove it completes without waiting on that claim.
  With an unusable stderr, verify a child without `CAP_LOG` neither recurses
  nor emits to the kernel log, while a child with `CAP_LOG` uses the kernel
  fallback. Force a short direct-pipe write as well as a hard write failure so
  both take the same non-recursive fallback path.
- Verify strobe reports System role; Interactive and CAP_LOG-bearing None
  services can log through IPC; Interactive can read but cannot alter logs;
  None cannot access them; current and rotated files have `rw-r-----`.
- Add malformed-IPC, unauthorized-peer, bad-state, bad-tag-ID,
  oversized-payload, and canonical-tag-collision tests, proving strobe remains
  operational afterward. These tests drive a hand-rolled
  `moto_ipc::sync::ClientConnection`, not `moto_log`, because the client
  library cannot emit malformed requests and must not be disconnected. The
  collision test opens two live connections with the same sanitized tag,
  expects `E_ALREADY_IN_USE` on the second, succeeds with a different tag on
  the same connection, and succeeds with the original tag after the first
  disconnects. Allocate its tags from the bounded test-tag pool described
  below, so concurrent suites do not collide and repeated runs do not create
  new filenames.
- Remove the logging test's direct Interactive deletion of `systest.log`.
  Reserve a fixed, documented pool of test tag slots, sized for the supported
  number of concurrent suites. Before installing the process logger, try the
  slots in order and claim the first whose CONNECT succeeds; an active slot
  returns `E_ALREADY_IN_USE`, and exhausting the pool fails the test instead
  of inventing an unbounded tag. Derive every auxiliary tag used by that suite
  from its claimed slot, and release the connection normally. Include a PID and
  per-process nonce in the expected record, not in the tag, and wait for that
  unique record rather than comparing wall-clock timestamps or relying on old
  file contents. Reusing fixed tags lets strobe's current/previous rotation
  bound the number of test log files. The SFTP read test reads
  `/system/logs/sys-init.log` and is unaffected.
- Verify the shared image policy resolves `/system/logs` to the four specified
  profiles and that no script or ELF entry is present under that tree.

## Implementation sequence and gates

Keep patches in the 100–300 line range where practical and preserve a working
tree between them. Use this dependency order:

1. Add the self-role transition, exact-permissions protocol/API, authority and
   atomicity tests, and the sys-io directory-response fix. Do not change default
   creation modes yet.
2. Update and test in-tree executable producers while the old permissive
   default still exists. Split the rt.vdso `copy`, SFTP, sysbox, and
   Lorry/Gears work into separate component patches if needed. The copy tests
   must already prove that `r--` does not become `rw-`, and each executable
   producer must already finish at `r-x`, before proceeding.
3. Add the minimal moto-rt-cabi permission wrapper, land the pinned external
   mlibc/compiler/linker changes, rebuild the development image artifacts, and
   assert that a freshly linked output and its Cargo-uplifted copy read back
   exactly `r-x`. `test-dev-sources.sh --release` must still pass, but under
   the old default it is not the gate for this step.
4. Switch sys-io's ordinary file and directory defaults and run the filesystem,
   copy, execute-permission, SFTP, and development-image tests against them.
5. Change `CAP_LOG` delegation, vDSO diagnostics, explicit spawn masks, and
   their focused tests.
6. Harden the sys-log record channel and the moto-log client while strobe still
   runs at its old role. Keep the stats channel public and prove malformed and
   unauthorized clients cannot terminate the service.
7. Change the shared log-tree image policy, promote strobe to System, and move
   log creation to the exact-permissions API. Re-run the role/access, current
   and rotated mode, SFTP-read, and full logging tests.

Format every Rust patch with `cargo +nightly fmt` and introduce no compiler or
clippy warnings. Before committing each patch that changes anything under
`src/sys`, pass `src/tests/full-test.sh` three consecutive times in debug and
three consecutive times in release. Gate non-core component patches with their
component-specific tests. After the final integration, repeat both full-test
gates and `test-dev-sources.sh --release`.

This is syslog work, not explicit Lorry work, even though its integration
changes necessarily touch `src/bin/lorry`. The implementation-time decision is
to run no debug developer-image gate: use `full-test-dev.sh --release` or its
`test-dev-sources.sh --release` phase only. The main-image `full-test.sh` debug
and release gates remain required independently.

## Documentation

Update each authoritative document alongside the patch that changes its
behavior:

- `src/sys/lib/motor-fs/PERMISSIONS_DESIGN.md`: §4 authority table and §4a
  (the `rw-` → `r-x` self transition and its sealing consequence), §6.3
  (creator-relative defaults are computed by sys-io; the exact-permissions
  creation request), and the §8 test plan.
- `docs/process-roles.md`: §5.1 (`default_child_capabilities` listing and the
  `CAP_LOG` delegation rules, including the None-parent kernel check), §7
  items 2–4 (strobe is System; Interactive defaults omit `CAP_LOG`), §8 last
  bullet (client creates no longer use `[Rwx; 3]`), replace the
  `std::fs::copy`-based sealed-file recovery procedure with explicit
  read/create/write/delete/rename, the rt.vdso stderr diagnostics route, and
  the §10 regression list.
- `docs/fs-permissions.md`: the `/system/logs` row and purpose, the
  "every role can create" consequence, and the "Limits and follow-up work"
  bullets on runtime creation modes and log integrity.
- `src/sys/lib/moto-sys/src/caps.rs` doc comments (`CAP_LOG` now also admits
  to strobe; the `CAP_SPAWN_DETACHED` comment's "any capability it holds"
  gains the `CAP_LOG` exception), the sys-init configuration comments, and
  strobe's log-directory comment.
- `src/sys/lib/moto-rt/src/error.rs`: document the stderr-first diagnostic sink
  selected by a negative `log_backtrace` descriptor; runtime logic and ABI stay
  unchanged. Document the new moto-rt-cabi permission wrapper in
  `src/sys/lib/moto-rt-cabi/moto_rt.h`.

## Assumptions

- Cross-role monotonicity is never relaxed.
- The image policy change affects every image, not only the development image.
- Exact external mlibc and compiler/linker revisions are recorded before the
  default-mode patch lands; an unpinned external dependency is not acceptable.
- Migration of existing persistent images is entirely out of scope.
