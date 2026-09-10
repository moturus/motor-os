# Helix save-check compatibility

The 2026-09-09 overnight Helix integration request authorizes recording stop
conditions and continuing. Native hover and navigation work, but saving a
binary makes the pinned analyzer issue `check -p <Cargo package ID> --bin NAME`
even with `check.workspace=true`. The previous acceptance fixture contains
only a library and did not cover this path. Its rejection is retained in
`/tmp/motor-helix-lsp.4ulIjq/helix.log`.

Extend Lorry's existing check interface in small patches:

- Accept the exact Cargo path package ID of the package selected by an explicit
  `--manifest-path`. Reuse metadata's identity generator and reject a different
  package, version, or path before compilation. Keep ordinary name selectors
  and all other commands unchanged.
- Accept named binary and integration-test check selectors. Validate names
  against the selected manifest. Match Cargo's union semantics: `--all-targets`
  still selects all supported targets when a named selector is also present.
  Without it, check only the requested targets plus their library dependencies.
  Do not add unsupported examples, benchmarks, virtual-root selection, or
  arbitrary dependency package checks.
- Extend `tests/check-contract.sh` with real compiler invocations, exact metadata
  package IDs, wrong-ID/name rejection, named selection, and all-target unions.
  Native Helix acceptance proves the actual analyzer's binary-save command.

Run focused tests while iterating and the full product suite through
`src/tests/full-test-dev.sh --release`. This is necessary Lorry work within an
editor task; no debug developer-image run is added. Core runtime work elsewhere
in this task separately requires three debug and three release main-image gates.

Focused validation passes: CLI unit tests (16), `tests/check-contract.sh`, and
Clippy with `-D warnings`. Logs are `/tmp/motor-helix-ra-lorry-unit.log`,
`/tmp/motor-helix-ra-lorry-contract.log`, and
`/tmp/motor-helix-ra-lorry-clippy.log`. The contract uses real rustc calls;
its deliberate deprecation warning exercises diagnostic serialization.

The native Helix acceptance also passes with the packaged Lorry binary:
`/tmp/motor-helix-ra-tui-final.log`. Saving the example binary produces rustc
E0308, and saving its correction clears the diagnostic. The server issues
the exact `-p <metadata-id> --bin helix-rust-demo --all-targets` command against
a project path containing a space. The complete release developer-image gate
passed on 2026-09-10: `/tmp/motor-helix-ra-full-dev-release-final.log`.
This includes the developer-source phase and complete Lorry product suite
(623 seconds), Cargo artifact identity, all check contracts, and the native
Lorry self-build (258.183 seconds). The final editor evidence is retained in
`/tmp/motor-helix-lsp.ATaC8B/`.

The selected Cargo toolchain independently confirms that `check --test
integration` compiles the library and selected test only, while providing
`CARGO_BIN_EXE_first` without compiling the binary. This agrees with Lorry;
the contract fixture now requires that environment variable. Oracle evidence:
`/tmp/motor-helix-ra-cargo-select.log`.
The strengthened focused contract also passes at
`/tmp/motor-helix-ra-lorry-contract-final.log`; the full product suite reruns it.
