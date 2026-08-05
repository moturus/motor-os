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
* Stop if any preexisting bug, including in test harness, is found and ask for guidance.
* Make sure your tests are included in src/tests/full-test.sh either directly or transitively.
* Make sure src/tests/full-test.sh passes consistently as both debug and release
  builds/runs at least three times each before committing a patch. If this step fails, please make
  a reasonable effort to root cause the failure, don't just stop.
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

Note:

Do not add retries, longer timeouts, ignored failures, or other workarounds
that can conceal a defect or make a failing test appear reliable.
Diagnose and fix the underlying issue instead. A bounded retry is permitted
only when the operation is explicitly designed to tolerate a documented
transient external failure, and only with prior user approval.

General commands:

* build (debug): `make -j$(nproc)`
* build (release): `make -j$(nproc) BUILD=release`
* the full test (debug): `src/tests/full-test.sh`
* the full test (release): `src/tests/full-test.sh --release`
