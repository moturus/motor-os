# Synthesizing `/dev/null` in Rush

## What fails today

Every shell-level reference to `/dev/null` aborts *before the command runs*,
because Rush treats it as an ordinary path and `open_for()`/`dev_null()` call
`File::open`/`File::create`:

```
$ echo hi >/dev/null; echo st=$?        →  rush: /dev/null: NotFound (os error 10)   st=2
$ ls /nonexistent 2>/dev/null; echo $?  →  rush: /dev/null: NotFound ...             st=2
$ cat </dev/null; echo st=$?            →  rush: /dev/null: NotFound ...             st=2
$ echo hidden >&-; echo st=$?           →  rush: /dev/null: NotFound ...             st=1
```

The places responsible are:

- `src/exec.rs:1496-1523` (`open_for`) — `File::open`/`File::create`/`OpenOptions` for `Redirect::File`.
- `src/exec.rs:1525-1532` (`dev_null`) — hard-codes `File::create("/dev/null")` for `>&-`.
- `src/exec.rs:1428-1465` (`build_fds_for_simple`) — a failure here returns early, so the command is never executed.

Host tests don't catch it because Linux has `/dev/null`.

## Recommended fix: make `/dev/null` a symbolic sink in `FdSource`

Do **not** try to open anything. Add a fourth `FdSource` variant and map it to
the sinks the platform already has. This is a string compare on the redirect
path (no boot cost, no extra syscalls), and it is exactly the abstraction Rush
already needs for `>&-`.

1. `src/exec.rs:103` — extend `FdSource`:

```rust
enum FdSource {
    Inherit(u8),
    File(Arc<File>),
    Heredoc(Arc<String>),
    /// The bit bucket: `/dev/null`, and the stand-in for a closed fd (`>&-`).
    /// Holds no OS handle; builtins use `io::sink()`/`io::empty()`, children
    /// get `Stdio::null()` (Motor OS's `STDIO_NULL` sentinel).
    Null,
}
```

2. `FdSource::out_writer` / `err_writer` (`exec.rs:115-137`) → `FdSource::Null => Box::new(std::io::sink())`.
   `FdSource::reader` (`exec.rs:140-152`) → `FdSource::Null => Box::new(std::io::empty())`.

3. `child_in` / `child_out` (`exec.rs:1388-1408`):
   `FdSource::Null => ChildIn::Null` and `FdSource::Null => ChildOut::Null`.
   `ChildIn::Null` already exists and maps to `Stdio::null()`; add the symmetric
   `ChildOut::Null` in `src/jobs.rs:115`.

4. `src/jobs.rs` — add `Null` to `ChildOut` and handle it in the three matches
   (`out_file`, `err_file` → `None`; `cmd.stdout`/`cmd.stderr` → `Stdio::null()`), e.g.:

```rust
ChildOut::Inherit | ChildOut::ParentStdout | ChildOut::ParentStderr | ChildOut::Null => None,
...
ChildOut::Null => Stdio::null(),
```

5. `build_fds_for_simple` — in the non-dup branch:

```rust
_ => {
    let path = expand::to_string(target, shell, io);
    if path == "/dev/null" {
        fds[fd_num] = FdSource::Null;
        sole_use[fd_num] = false;
    } else {
        let file = open_for(*op, &path, shell)?;
        sole_use[fd_num] = file.metadata().is_ok_and(|m| m.is_file());
        fds[fd_num] = FdSource::File(Arc::new(file));
    }
}
```

This covers `>`, `>>`, `>|`, `<`, `<>` uniformly, and the `set -C` (noclobber)
check is bypassed for `/dev/null` as POSIX requires (it only protects existing
*regular* files). Do the match *after* expansion, so a quoted `/dev/null`,
`$NULL`, etc. all work.

6. In the `>&-` branch (`exec.rs:1437-1441`), replace
   `fds[fd_num] = FdSource::File(Arc::new(dev_null()?));` with
   `fds[fd_num] = FdSource::Null;` and delete `dev_null()` entirely. That also
   fixes `>&-` on Motor OS.

`Stdio::null()` is the right child-side primitive: std's Motor OS backend maps
it to `moto_rt::process::STDIO_NULL`
(`std/src/sys/process/motor.rs`), and rt.vdso turns it into an empty
`StdioPipe` whose writes succeed and are discarded — no new OS API is needed.

### Why not the alternatives

- **Real temp file** (`/user/tmp/...`): grows without bound
  (`yes >/dev/null` fills the FS), costs real I/O, races between shells, needs
  cleanup. Reject.
- **Try `File::create` and fall back on `NotFound`**: hides real errors, adds a
  syscall to every redirect, and makes behavior depend on the filesystem.
  Reject.
- **Create a pipe and drain it with a thread**: expensive and fragile;
  `STDIO_NULL` already exists. Reject.

Apply the special case on **both** platforms rather than `#[cfg(not(unix))]`:
the semantics are identical on a host, it keeps one code path, and it also
makes `>&-` consistent. If byte-for-byte host parity is wanted, gate it, but
the trade-off is probably not worth it.

## Tests

Host tests in `tests/phase3.rs`/`phase6.rs` will pass before and after this
change, so they are regression guards only. The real gate should be in the VM.
`src/tests/full-test.sh` already sources `src/tests/test-rush-script-caps.sh`
(line 410) and calls its functions around line 900, so add something like:

```sh
test_rush_dev_null() {
  local out
  out="$(vm_ssh_stdout "/user/bin/rush -c '
    echo hidden >/dev/null
    echo hidden >/dev/null 2>&1
    echo hidden 2>/dev/null >/dev/null
    /user/bin/ls /nonexistent-rush-devnull 2>/dev/null
    /user/bin/ls / >/dev/null
    cat </dev/null
    { echo hidden; } >/dev/null
    echo hidden >&-; echo closed=\$?
    echo msg 2>&1 1>/dev/null
    echo visible
  '")" || fail "rush /dev/null redirection failed"
  [ "$out" = $'closed=0\nmsg\nvisible' ] || fail "rush /dev/null output: '$out'"
}
```

called from `full-test.sh` next to `test_rush_script_caps rush`. Also add a
host regression in `tests/phase6.rs` asserting `echo x >/dev/null`,
`2>/dev/null`, `< /dev/null`, and `>&-` all reach the command and give the POSIX
status.

## Remaining gaps (worth documenting, not necessarily fixing now)

- Commands that open `/dev/null` *themselves* (`cat /dev/null`,
  `prog --log /dev/null`, a nested non-rush shell) still fail: Rush never sees
  that path. Fixing those needs a null device in `rt.vdso`'s `file_open`, which
  is a core OS change and should be argued separately.
- `test -e/-r/-w/-c /dev/null` still reports false (`builtins.rs:2140+`), so the
  common `[ -w /dev/null ] && …` idiom takes the false branch. This could be
  special-cased later, but the answers for `-c`/`-w` are a semantic decision.
- If agents commonly use them, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` are
  cheap follow-ups: map them to `FdSource::Inherit(0/1/2)` in the same place.
  `/dev/fd/N` would be similar for `N ≤ 2`.
- Match only the exact canonical path; don't swallow `/dev/<anything>`,
  `//dev/null`, or `dev/null`, so typos still fail loudly.
