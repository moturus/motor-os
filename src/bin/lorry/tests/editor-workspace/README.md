The regular editor contract runs three hermetic workspace cases through
`../editor-workspace-contract.sh`, which is included in `../test-all.sh`.

The same helper also provides manual acceptance for a separately fetched and
admitted copy of Motor OS's system workspace:

```text
lorry-editor-workspace LORRY REPOSITORY WORK CONFIG_JSON SYS_WORKSPACE HOME
```

All paths must exist. CONFIG_JSON contains the shipped rust-analyzer settings;
WORK must be an unused directory. SYS_WORKSPACE must have its Cargo.lock,
verified local dependency sources, project policy, and local admission record.
Prepare that copy separately; the helper uses offline commands and does not
vendor or approve dependencies.

The fetched view proves member and Git-source navigation with execution denied.
The admitted view uses Cargo's default test configuration and checks a sysbox
save diagnostic. The application view proves navigation into generated netstack
constants, which intentionally have handwritten definitions under cfg(test).
The helper restores the admission record and edited source on a test failure,
checks unchanged lock bytes on success, and retains every Cargo invocation.
All views use one Cargo wrapper path so their compiler inputs stay stable;
the generated view also requires fresh compiler artifacts from the admitted pass.
