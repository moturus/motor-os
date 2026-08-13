# 2026-08-12 rebase analysis

Status: the rebase plus rebuild was not sufficient to restore the complete
Lorry workflow. Lorry builds itself, but the repository integration campaign
cannot consume the rebased Red package.

This document records diagnosis and required human decisions only. No repair
was attempted.

## Conclusion

The rebase introduced two dependency-related changes:

1. `moto-rt` moved from 0.17.1 to 0.17.2. Commit `841fd609` updated the Lorry,
   curl, and gears lockfiles after the rebase; the rebased Rush and other
   lockfiles already contain the new path-package version.
2. Red gained a Unix-only root dev-dependency on `libc` for
   `tests/resize.rs`.

The first change is operational after the lockfile updates. The second is not:
Lorry Stage 2 intentionally rejects root build-dependencies and
dev-dependencies, including target-conditioned ones. This is a package-model
failure before resolution, vendoring, admission reconstruction, or
compilation. Rebuilding cannot repair it.

There is also an independent Red test failure. The new resize integration test
builds under Cargo, but two of its three cases fail in this checkout. That must
be diagnosed rather than hidden with retries or longer timeouts before the
repository gates can close.

## Evidence

### Lorry itself works

The rebuilt Linux-host executable is:

```text
build/lorry/stage2/host-target/release/lorry
```

It reports `lorry 0.1.0`, validates the existing compact admission state, and
successfully completes a release self-build from `src/bin/lorry`:

```text
Compiling lorry v0.1.0 (.../src/bin/lorry)
Finished `release` profile
```

This demonstrates that the `moto-rt` 0.17.2 path-package lock entry does not
invalidate Lorry's registry admission commitment. No registry identity in
Lorry or curl changed, and `bootstrap/stage2-seed.toml` does not need a new
object for an in-tree path-package version bump.

The rebuilt `build/bin/release/lorry` is the Motor-target executable, not the
Linux-host executable, and should only be exercised in a Motor VM.

Rush also parses far enough to reach its expected unmaterialized-Git-patch
diagnostic:

```text
error: patch key `git` is not supported in Stage 2
help: run `lorry vendor` to pin and materialize a Git patch, or use only `path`
      and optional `package`
```

That is the normal pre-vendoring state and shows that Rush's `moto-rt` lock
update is not the current blocker.

### Red is outside Lorry's supported package model

The rebase added this declaration to `src/bin/red/Cargo.toml`:

```toml
[target.'cfg(unix)'.dev-dependencies]
libc = "0.2"
```

Running the rebuilt Linux-host Lorry from `src/bin/red` fails immediately:

```text
error: root `target.cfg(unix).dev-dependencies` is not supported in Stage 2
  --> .../src/bin/red/Cargo.toml:19
help: root build-dependencies and dev-dependencies are deferred
```

The result is expected from the current product contract in `spec.md` and the
explicit rejection in `src/bin/lorry/src/manifest.rs`. It is not stale
generated state and cannot be repaired by regenerating Cargo.lock, rerunning
`lorry vendor`, or rebuilding the image.

This breaks `src/tests/lorry-native-integration.sh` in its host preparation:

- the harness copies Red's real Cargo.toml, Cargo.lock, and `src` tree;
- `expect_vendor_required` expects the copied package to reach the actionable
  Git-patch/`lorry vendor` boundary;
- Red instead stops at manifest parsing, so the expected diagnostic is absent;
  and
- the subsequent staged `lorry vendor --accept-all` would fail for the same
  reason.

The harness currently does not copy Red's `tests` directory, but that does not
make the manifest acceptable: unsupported dependency semantics are rejected
even when no copied source happens to use them. Silently deleting the table in
the harness would mean the integration campaign no longer tests the package in
the repository.

Red has no committed `.lorry/dependencies-v2.toml`; the integration harness
creates its admission state in a private staged copy. There is therefore no
Red compact-state file to regenerate before resolving the manifest-model
decision.

### Red's new Cargo test is not green

The following focused offline command was run once, without retrying:

```sh
cd src/bin/red
cargo +nightly test --locked --offline
```

All 72 unit tests passed. `tests/resize.rs` then produced:

```text
test the_first_paint_is_the_shape_the_terminal_already_is ... ok
test a_resize_repaints_at_the_new_shape_with_no_key_typed ... FAILED
test the_second_resize_is_noticed_as_readily_as_the_first ... FAILED
```

Both failures observed no output after a resize. One reported:

```text
the resize did not repaint the screen: ""
```

This analysis does not claim a root cause. It establishes a separate failing
gate introduced by the rebased Red work. `src/tests/full-test.sh` runs Red's
host Cargo tests before booting the VM, so this failure blocks repository
closure independently of Lorry's manifest rejection.

## Human work required

### 1. Choose how Red remains a Lorry acceptance package

This is a product-scope decision and should be reviewed before code changes.
There are three coherent choices:

1. **Keep the current Lorry package model.** Remove the root dev-dependency
   from Red while preserving the host resize test. For example, place the
   host-only pty test in a separate test package, or replace its use of the
   `libc` crate with a small reviewed host-only FFI boundary. Red's own
   Cargo.toml must again have no root build/dev dependencies.
2. **Add root dev-dependencies to Lorry.** This is not a rebase repair. It
   widens the Stage-2 package model and needs a reviewed design plan, spec and
   user-documentation changes, resolver/unit-selection semantics for normal
   versus test commands, compact-review coverage, and Linux/cross/native
   acceptance tests.
3. **Stop using Red as a real downstream Lorry package.** Replacing it with a
   fixture or a sanitized manifest changes integration coverage and the stated
   Stage-1/Stage-2 assurance. That also requires explicit review; the harness
   must not make this change silently.

The first choice is the smallest restoration of the previously accepted Lorry
scope, but the Red and Lorry owners must make the decision.

### 2. Diagnose the Red resize failures

Determine why a pty resize produces no repaint in two of the three new tests.
Keep the existing correctness deadlines while diagnosing the signal/crossterm/
event path. Do not add retries, ignore the failures, or lengthen the waits.

Re-run the focused offline Cargo command only after addressing an identified
cause. Both debug and release forms must pass consistently before the broader
repository gates.

### 3. Regenerate and inspect Red's lockfile if its manifest changes

Use Cargo to update Cargo.lock after the reviewed manifest/test restructuring;
do not hand-edit the lockfile. Preserve compatible locked versions and inspect
the diff. Under the minimal approach, the root Red package should cease listing
`libc` directly; `libc` may remain in the lock graph because crossterm's Linux
dependencies already select it.

The `moto-rt` 0.17.2 entries in Lorry, curl, gears, Rush, and the other rebased
locks should remain. They are not candidates for rollback.

### 4. Validate the restored boundary

After the human-selected repair:

1. Confirm Red's offline Cargo tests pass in debug and release.
2. Run `src/bin/lorry/test-exhaustive.sh`. This is the authoritative proof that
   staged Red and Rush vendoring, host/cross/native builds, both Motor image
   profiles, native testing, and the second Lorry generation work together.
3. Because the likely repair is outside `src/bin/lorry`, also follow the root
   repository rule: run `src/tests/full-test.sh` three times in debug and three
   times with `--release` before committing.
4. Check the source tree for accidental staged `.lorry`, rewritten Git-patch,
   repository, target, or transaction artifacts. The integration harness must
   continue to generate those only in its private work directories.

Do not treat a successful `make`, dev-image rebuild, Lorry self-build, or
`lorry --version` as closure: all of those precede the broken Red integration
boundary.
