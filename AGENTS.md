# Motor OS development guidelines.

These apply both to human and to AI contributors.

Motor OS is a new operating system for VMs focused on simplicity, speed/efficiency, and security.
It is Rust-first. All work must only use standard Rust and native Motor OS APIs (in src/sys/lib)
unless instructed otherwise.

Prefer:
* secure code first
* correctness
* simple/clean code

General guidelines:

* Split your work in small (100-300 loc) patches, including tests.
* Only rarely, when it is hard to make a smaller change, make a larger patch.
* Document your code with comments, but use them sparingly: the ratio of comments to code should be about 1:5 on average.
* Stop if any non-obvious decision is required and ask for guidance.
* Stop if any preexisting bug is found and diagnose it. If the bug is test only and the fix
  is small and obvious, fix the test, commit, and continue. Otherwise stop and explain what happened.
* Make sure your tests are included in src/tests/full-test.sh either directly or transitively.
* If you are working on a core OS component (basically, anything under src/sys),
  make sure src/tests/full-test.sh passes consistently as both debug and release
  builds/runs at least three times each before committing a patch. If this step fails, please make
  a reasonable effort to root cause the failure, don't just stop.
* If you work on a non-core OS component (e.g. src/bin/red, src/bin/lorry, etc.) please gate your
  work with tests specific to your component, unless instructed otherwise.
* For work that is not explicitly Lorry work, run `src/tests/full-test-dev.sh`
  and its `test-dev-sources.sh` phase only in release mode (`--release`). If
  such work necessarily changes `src/bin/lorry`, ask the user whether to add a
  debug developer-image run; touching the Lorry path does not itself make the
  task explicit Lorry work. Without approval, keep the developer-image gate
  release-only. This does not change the debug-and-release requirement above
  for the main-image `src/tests/full-test.sh` gate.
* Complexity is frowned upon, and is tolerated only when really needed.
* Boot time latency is very important. Avoid adding any extra boot time work. If unavoidable, please stop for review.
* On larger tasks, first create a plan in an *.md file in docs/plans/, ask for review, then proceed
  in incremental steps. Do not change any code during the planning step.
* Quite often the workflow implies no commits, only local changes. If unclear, ask for clarification.
* Make sure your code does not introduce any new compiler or clippy warnings. Warnings in crates/packages
  outside of core Motor OS repo are tolerated (this file is in the root of the core Motor OS repo).
* Format your changes with `cargo +nightly fmt`.
* Be careful not to introduce performance regressions.
* Regular tests must not go out to the Internet, as this introduces flakiness to our tests and
  potentially destabilize (DDOS) the external resource. Only rare integration tests for internet-facing
  services like DNS lookup or ping should include reaching out to the internet, and only after
  an express discussion and approval.
* Explicit user instructions may override anything stated above.

Notes:

(1) Do not add retries, longer timeouts, ignored failures, or other workarounds
    that can conceal a defect or make a failing test appear reliable.
    Diagnose and fix the underlying issue instead. A bounded retry is permitted
    only when the operation is explicitly designed to tolerate a documented
    transient external failure, and only with prior user approval.

(2) Rust stdlib's Motor OS port only depends on moto-rt. It should have very little Motor OS-specific
    logic, and mostly should just call moto-rt functions. Any changes to Rust stdlib should be discussed
    and vetted.

(3) moto-rt has a bit of no-std functionality, but mostly calls into rt.vdso. Any changes to moto-rt
    should be discussed and vetted.

(4) Although Motor OS is not unix, it has a posixy shell in src/bin/rush; also it has
    functional libc port, llvm/clang, and rustc. If in doubt about what capabilities Motor OS has or what
    capabilities are expected to happen in the near future, stop and ask, don't assume a feature
    is not available.

General commands:

* build (debug): `make -j$(nproc)`
* build (release): `make -j$(nproc) BUILD=release`
* the full test (debug): `src/tests/full-test.sh`
* the full test (release): `src/tests/full-test.sh --release`
* the developer-image full test for non-Lorry work (release only):
  `src/tests/full-test-dev.sh --release`
