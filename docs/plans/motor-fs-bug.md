# Motor FS: writes continue after a failed open

Found on 2026-11-08 while validating the QuickJS port. It is not related to
QuickJS.

## Symptom

The motor-fs host test `tests::recovery_policy_and_completion`
(`src/sys/lib/motor-fs/src/tests.rs`, added in `7a711121`) fails at random:

```
panicked at lib/motor-fs/src/tests.rs:242:17:
assertion failed: fs.replayed_txn_log_on_open()
```

It stopped a debug `src/tests/full-test.sh` run, at the `motor-fs` step
(`cargo test --quiet --features image-admin`). The same tree had passed that
step six times before.

## How often

Measured on a 16-core host from `src/sys/lib/motor-fs`:

| Run | Failures |
| --- | ---: |
| The test alone | 0 of 150 |
| The whole motor-fs suite | 16 of 80 |
| The test alone, with 16 busy loops on the host | 25 of 60 |

So the trigger is CPU load, not another test's state.

To reproduce:

```sh
cd src/sys/lib/motor-fs
for i in $(seq 16); do timeout 300 sh -c 'while :; do :; done' & done
for i in $(seq 20); do
  cargo test --quiet --features image-admin --lib \
    tests::recovery_policy_and_completion -- --exact || echo FAIL
done
```

## Cause

The test opens the same image four times. Before each open it writes the old
superblock and root back, so each attempt starts from the same dirty journal.
The third attempt makes the device's flush fail, so
`MotorFs::open_with_recovery_policy` returns an error.

That error returns while recovery writes are still queued. `BlockCache` sends
its writes to a background task, started with `spawn_local` in
`src/sys/lib/moto-sdk/src/async_fs/block_cache.rs` (about line 551). The task's
handle is dropped. When the cache is dropped, the task keeps draining the
writes it already has. On the host each write runs on a tokio blocking thread,
so under load it can land much later.

When a late write lands after the test restored the old superblock, the fourth
open finds the journal already applied. It does not replay it, and the
assertion fails.

A temporary check in the test confirmed this. After each restore it waited
briefly and read the restored blocks back. Under load, all 26 failures in 50
runs came with a changed block before the last open. Runs with no late write
never failed. The check was removed afterwards.

## Impact

Any caller that retries an open after a failed recovery can race with writes
from the failed attempt. Those writes can overwrite what the new attempt reads
or writes. The test only makes this visible.

A related issue: on a device write error the background task panics
("Error writing blocks to the device", `block_cache.rs` about line 487). A
later `flush()` then panics with `RecvError` (about line 374). Both panics show
up in every run of this test, passing or failing, during the attempt with the
failing write.

## Possible fixes

- Keep the background task's handle. Have a failed open, or the cache's
  shutdown, wait for queued writes to finish before it returns.
- Or, once a write or flush has failed, make the background task drop the
  writes that are still queued.
- Return device write errors from the background task instead of panicking.

The fix belongs to the Motor FS and moto-sdk code, not to the QuickJS work.

## Status

Open. While this is open, the QuickJS work keeps the test commented out in its
working tree only. That change will not be committed.
