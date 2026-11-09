# Motor FS: a flaky recovery test

Found on 2026-11-08 while validating the QuickJS port. It is not related to
QuickJS. It is a test bug, fixed in `3f06e57c`. It does not affect a live Motor
OS VM.

## Symptom

The motor-fs host test `tests::recovery_policy_and_completion`
(`src/sys/lib/motor-fs/src/tests.rs`, added in `7a711121`) failed at random:

```
panicked at lib/motor-fs/src/tests.rs:242:17:
assertion failed: fs.replayed_txn_log_on_open()
```

It stopped a debug `src/tests/full-test.sh` run, at the `motor-fs` step
(`cargo test --quiet --features image-admin`). The same tree had passed that
step six times before.

## How often

Measured on a 16-core host from `src/sys/lib/motor-fs`:

| Run | Before the fix | After the fix |
| --- | ---: | ---: |
| The test alone | 0 of 150 | |
| The whole motor-fs suite | 16 of 80 | 0 of 80 |
| The test alone, with 16 busy loops on the host | 25 of 60, 17 of 50 | 0 of 100 |

So the trigger was CPU load, not another test's state.

## Cause

The test opens the same image four times. Before each open it writes the old
superblock and root back, so each attempt starts from the same dirty journal.
The third attempt uses a fake device whose flush fails, so
`MotorFs::open_with_recovery_policy` returns an error.

On the host, `AsyncFileBlockDevice` writes through `tokio::fs::File`. Its
`write_all` returns once tokio has buffered the data; the real write runs later
on a blocking thread. Only `File::flush()` waits for it, and dropping the file
does not cancel it.

The fake device (`FlushErrorBlockDevice::flush`) returned its error without
calling the inner flush. So the last recovery write was still pending when the
third open failed. Under load it landed after the test had restored the old
superblock. The fourth open then found the journal already applied, did not
replay it, and the assertion failed.

A temporary check in the test confirmed the late write. After each restore it
waited briefly and read the restored blocks back. Under load, all 26 failures
in 50 runs came with a changed block before the last open. Runs with no late
write never failed. The check was removed afterwards.

An earlier version of this document blamed the block cache's background
writer. That was wrong. The block cache handles its messages in order, so every
write sent before a flush reaches the device before the flush reply. It writes
nothing when it is dropped.

## Fix

`3f06e57c` makes the fake device always call the inner flush, then return the
injected error. That matches a real flush error, which also waits for the
file's buffered writes first.

## Why a live VM is not affected

- sys-io does not use `tokio::fs`. It writes through `VirtioPartition`
  (`src/sys/sys-io/src/runtime/fs/devices.rs`).
- A failed open is fatal for that boot. A failed root open makes `fs::init`
  return an error. Any other failed mount panics sys-io in `config::load`.
  Nothing reopens the device in the same boot.
- On the Linux host, the imager's real flushes go through `File::flush()`,
  which waits for buffered writes.

## A related open issue

On a device write error, the block cache's background writer panics ("Error
writing blocks to the device", `src/sys/lib/moto-sdk/src/async_fs/block_cache.rs`
about line 487). A later `flush()` then panics with `RecvError` (about line
374). Both panics show up in every run of this test, during the attempt with
the failing write. On a live VM this needs a real device write error. Returning
the error instead of panicking would be more robust. This is not fixed.
