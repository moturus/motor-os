# Cargo-like Lorry validation and incremental builds

2026-08-15. Implemented and validated.

## Decision

Ordinary `lorry build`, `run`, and `test` will use Cargo's local trust model.
They will parse manifests, enforce policy, validate paths and archive extraction
safety, and detect ordinary source changes through persisted fingerprints and
filesystem metadata, but they will not reread file contents merely to prove
that an already-present source, tool, cache entry, or artifact still has the
same digest.

`--strict-validation` will opt into Lorry's current content-validation model.
It will rehash repository and Cargo-cache sources, mutable path sources, tools,
sysroot inputs, build-cache payloads, dep-info inputs, and installed artifacts.
The option is a common build option accepted by `build`, `run`, and `test`; it
is not accepted by `clean` or package-management commands. Structural safety,
resource limits, admission, and explicit deny rules remain mandatory in both
modes. "Non-strict" must never mean unsafe archive extraction or bypassed
policy.

An ordinary build will trust repository object metadata and the fact that a
previous Lorry transaction published the object, just as Cargo trusts its
completed registry cache. Strict mode will compare that metadata with the
actual retained archive/source. A strict build following an ordinary build may
need one rebuild when no strict artifact record exists; ordinary builds must
not hash a new artifact merely to prepare for a possible future strict build.

Debug builds will use persistent rustc incremental state on Linux and Motor.
Incremental state is a disposable compiler cache, not a published artifact or
an integrity authority.

## Problems addressed

The old warm path reconstructed admission and prepared the dependency
graph before it can check the root profile. Those operations content-verify
repository sources in every new process. Root freshness then hashes Lorry,
rustc, source inputs, and the complete installed artifact. A stale profile
also initializes a dependency cache by hashing the sysroot and rehashes source
and cache payload trees. This is stronger than Cargo's normal filesystem trust
model and dominates no-op build time.

Local path packages were hashed while resolving and again while producing
policy evidence. This prevents a fast freshness decision even though these
developer-owned inputs should use normal change detection.

Motor incremental compilation was disabled by commit `6694b494` in a one-line
change with no recorded rationale. Independently, the incremental directory is
was below the atomic build staging directory. Every dirty build created new
staging and replaced the old profile, so previous incremental state was not
available consistently even where the flag was enabled.

## Implemented patches

The implementation was split into small patches with focused tests.

1. **Specify and parse validation mode.** Update `spec.md`, `README.md`, and
   `design.md`; add `--strict-validation` to the shared `build`/`run`/`test`
   options; keep `clean` rejecting it. Introduce an explicit `ValidationMode`
   value rather than distributing boolean inversions through the build code.

2. **Add the ordinary trusted repository path.** Split repository-object
   loading into always-on structural/schema/path checks and strict content
   verification. Ordinary mode trusts recorded archive/source digests and
   Cargo's completed-cache marker; strict mode retains the current archive,
   source-tree, and Cargo-cache comparisons. Admission reconstruction uses the
   selected evidence mode but remains mandatory whenever a build is not
   accepted by the ordinary freshness fast path.

3. **Replace ordinary root content validation with Cargo-like freshness.** Add
   a new freshness format that can decide an ordinary warm build before
   dependency repository preparation. Its compilation identity covers parsed
   manifest/lock/admission/configuration, selected target/profile/features,
   rustc version, flags, and relevant environment. Its filesystem status uses
   rustc dep-info plus size/mtime/existence records for root and mutable local
   path inputs; immutable registry dependencies are trusted. Outputs are
   required to exist but are not rehashed. Strict mode retains content hashes
   and performs the current complete verification before reuse.

4. **Make dependency cache behavior mode-aware.** Ordinary cache keys use
   trusted registry identities and metadata fingerprints for mutable path
   inputs; they do not rescan immutable registry trees, rustc/sysroot contents,
   dependency artifacts, or cache payload bytes on every lookup. Cache writes
   may still record content digests while bytes are already being produced.
   Ordinary reads trust atomically published entries and required-file
   structure; strict reads retain full payload verification and quarantine.
   Carry enough dependency source metadata into the root freshness record to
   invalidate a local path dependency or build-script input normally.

5. **Persist debug incremental state on every host.** Move root and mutable
   local-package incremental directories out of per-build atomic staging into
   a profile/target/unit-keyed directory below `target/lorry`. Pass that stable
   path to rustc for all debug builds, remove the Motor exclusion, and leave
   release/registry units non-incremental as Cargo does. `lorry clean` already
   removes the owning target tree. Failed builds may leave incremental cache
   data, which rustc must be free to discard or repair.

6. **Finish behavioral coverage and documentation.** Prove that an unchanged
   ordinary command takes the pre-admission fast path without reading
   dependency or artifact contents; normal mtime changes still rebuild root and
   path sources; same-metadata content tampering is ignored ordinarily but
   detected by strict mode; strict mode detects repository/cache/artifact
   corruption; and `run`/`test` propagate the flag. The native gate must prove
   that two Motor debug compilations use the same persistent incremental root.

## Validation

Development used focused CLI, repository, freshness, cache, and rustc-argument
tests. The implementation was formatted with `cargo +nightly fmt` and did not
add clippy warnings. Because all changes remained within `src/bin/lorry`, the
final gate was the Lorry-owned `src/bin/lorry/tests/test-all.sh`, not the full OS
suite.

The completed product suite passed in 393 seconds on 2026-08-15. It covered
the Rust tests, three Cargo resolution oracles, native and cross-Motor artifact
identity, registry and curl production contracts, Linux-to-Motor self-build,
native Motor self-build/run/test, and reuse of one persistent incremental root
across two native Motor debug compilations.
