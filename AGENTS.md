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
* Stop if any non-obvious decision is required and ask for guidance.
* Stop if any preexisting bug, including in test harness, is found and ask for guidance.
* Make sure your tests are included in src/tests/full-test.sh either directly or transitively.
* Make sure src/tests/full-test.sh passes consistently (at least three times sequentially) before committing a patch.
* Complexity is frowned upon, and is tolerated only when really needed.
* On larger tasks, first create a plan in an *.md file in docs/plans/, ask for review, then proceed
  in incremental steps. Do not change any code during the planning step.
* Quite often the workflow implies no commits, only local changes. If unclear, ask for clarification.
* Make sure your code does not introduce any new compiler or clippy warnings.
* Format your changes with `cargo +nightly fmt`.
* Be careful not to introduce performance regressions.
* Explicit user instructions may override anything stated above.
