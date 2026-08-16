# Global dependency build cache

2026-08-15. Implemented.

## Goal

Keep compiled immutable dependency units across project-local `lorry clean`
operations and allow the same units to be reused by compatible projects. Root
artifacts, mutable path dependencies, tests, and incremental state remain
project-local.

## Design

1. Store immutable crates.io and reviewed required-patch dependency units in a
   per-user cache below `$HOME/.cache/lorry` on Linux or
   `/user/cfg/lorry/cache` on Motor by default. Allow system or user
   `lorry.toml` to configure another root. Keep mutable path-package units
   below the project's `target/lorry/.cache`.
2. Route each library unit to one cache without changing admission or source
   verification. Both stores retain the existing content-addressed keys,
   atomic publication, ordinary structural trust, strict payload validation,
   and corruption quarantine.
3. Normalize the workspace root and diagnostic-only rustc verbosity when
   computing shared keys. Compiler, target, profile, features, codegen flags,
   immutable source identity, dependency keys, build-script results, and
   approved tools remain cache inputs.
4. Make project-local `lorry clean` remove only `target/lorry`. Add
   `lorry cache clean`, which requires no package and safely removes exactly
   the current user's global Lorry cache. Global cache cleanup is explicit;
   automatic garbage collection is out of scope.
5. Document the ownership and trust boundary. A writable cache is per-user,
   never part of the immutable source repository. Strict validation rehashes
   shared payloads; ordinary validation trusts complete entries published by
   Lorry.

## Validation

Focused tests will cover cache routing, cross-workspace/verbosity-stable keys,
project clean preserving the global cache, global cache cleanup, CLI/help, and
safe handling of missing or non-directory cache roots. The final gate is
`src/bin/lorry/tests/test-all.sh`; no full OS test is required because the
implementation is confined to Lorry.
