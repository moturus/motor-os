# Gears external tools implementation plan

This plan implements the proposed contract in
`src/bin/gears/external-tools.md`. It replaces the special built-in `sh` path
with a generic, directory-backed tool registry, adds optional `sh` and `ls`
tool directories, and lets interactive users change tool enablement for a
session or globally.

Only child-process execution is implemented here. The registry and manifest
keep common package metadata separate from `kind = "process"` settings so a
later WebAssembly loader can reuse discovery, enablement, authorization,
identity, provider, and UI code. Selecting a runtime, ABI, capability model, or
WASI surface is not part of this plan.

The following choices are intentionally part of the review boundary:

- an empty `[[tools]]` list means a chat-only agent; neither `sh` nor `ls` is
  silently enabled;
- config names exact tool directories rather than scanning projects or a
  search path;
- slash-command global state lives in a small Gears-owned override file, so
  Gears never rewrites the user's main TOML or destroys its comments;
- session toggles are durable append-only entries and follow conversation
  branches;
- version 1 toggles directory tools only, not tools registered by hooks;
- a process child always starts in the selected workspace, while its package
  remains available through `GEARS_TOOL_DIR`; and
- allow-all grants are distinct from enablement, cannot override permission
  hooks, and bind to a tool approval identity rather than its name alone.

No migration of old session data is required. Existing sessions containing
historical `sh` calls remain readable provider messages; tool availability for
the next request comes from current configuration and session tool-state
entries.

## 1. Parse and validate tool directories

- Add a small `tools` module with common package metadata, normalized tool,
  enablement, approval identity, registry, and a version-1 process-kind type.
- Extend config version 1 with ordered `[[tools]]` entries containing an
  absolute directory and a default `enabled` boolean.
- Load `tool.toml`, `parameters.json`, and optional `prompt.md` without running
  the tool. Reject missing/special resource files, escaping relative paths,
  invalid names/schemas/templates, duplicate tool names, unsupported versions,
  unknown kinds, invalid process limits, and a missing command for the current
  platform.
- Require `kind = "process"` and keep timeout, stdin, output bounds, and command
  selection under `[process]`. Do not place process-only state in the common
  registry API a future loadable executor would have to imitate.
- Resolve a leading `./` program inside the tool directory, allow an explicit
  absolute system program, and reject bare names so ambient `PATH` cannot
  silently change execution or approval identity.
- Keep parsing and normalization platform-neutral, selecting only the command
  vector through `cfg(unix)` / `cfg(not(unix))` so Motor OS remains a first-class
  build target.
- Add unit tests using temporary self-contained tool directories. Do not add a
  dependency; use the existing `serde`, `serde_json`, and `toml` crates.

## 2. Implement the process executor and replace the built-in path

- Give `Runtime` a registry of configured directory tools. Build provider tool
  specs and prompt fragments from only its effective enabled set.
- Remove `sh_spec`, `Runtime::execute_sh`, the hard-coded `call.name == "sh"`
  branch, and `runtime.sh_timeout_seconds` after the external `sh` manifest owns
  those settings.
- Execute an enabled directory tool through the existing bounded process
  runner. Expand only whole-argument string placeholders, optionally write the
  exact argument JSON to stdin, set the documented non-secret environment, and
  remove the provider credential.
- Set the child working directory to the canonical selected workspace. Resolve
  a leading `./` program against the tool package first and expose the package
  separately as `GEARS_TOOL_DIR`.
- Preserve separate live stdout/stderr events, exit status, cancellation,
  timeout, process-tree cleanup, result bounds, hook permission decisions, and
  hook result transformations.
- Reserve every configured directory-tool name while hooks initialize. Reject
  collisions even when the directory tool starts disabled, because it may be
  enabled later.
- Include normalized enabled manifests and prompt fragments in runtime
  identity. Compute a separate approval identity from the name, kind, owner,
  schema, execution configuration, and package-controlled executable hashes. A
  disabled or unknown tool call must produce an error result without spawning
  anything.
- Add runtime tests for enabled execution, disabled calls, direct argv
  substitution without shell splitting, stdin JSON, non-zero exit, timeout,
  cancellation, output streaming, credential removal, and hook/tool name
  collisions.

## 3. Add global and session enablement state

- Add a versioned global override reader/writer at
  `~/.config/gears/tools.toml` on Linux and `/user/cfg/gears/tools.toml` on Motor
  OS. Use checked regular files and atomic replace; never partially overwrite a
  valid file.
- Apply main-config defaults, then global overrides, then active-session
  overrides. Report names that no longer correspond to a configured directory
  rather than ignoring stale overrides silently.
- Add a `tool_state` session entry and helpers to find the latest value on the
  active branch. Ensure select, resume, new, fork, clone, and ephemeral sessions
  have the documented behavior.
- Add runtime methods to list tools with state provenance and to enable,
  disable, or reset a tool at session/global scope. Represent session reset as
  an append-only `inherit` state. Rebuild the effective prompt/tool set and
  append runtime identity after a successful change.
- Make a global command update only the atomic global file. Recompute the
  current effective state from normal precedence; an existing session override
  remains in force until the user changes or resets it.
- Add state and session tests for precedence, persistence, branch selection,
  cloning, reset, unknown names, corrupt files, and interrupted-write safety.

## 4. Add scoped approval grants

- Replace the approver's boolean answer with `deny`, `once`, `session`, and
  `global` outcomes. Keep unattended approval as deny.
- Preserve the decision order: unknown/disabled rejection, permission hooks,
  matching grants, then interactive approval. A permission-hook deny or
  failure must win even when a grant exists; a hook allow needs no grant.
- Store session grants and revocations as session-wide append-only entries, not
  active-branch state. Saved sessions retain them across resume, ephemeral
  sessions retain them in memory, and new/forked/cloned sessions do not copy
  them.
- Add a versioned, atomically replaced global grant file at
  `~/.config/gears/permissions.toml` on Linux and
  `/user/cfg/gears/permissions.toml` on Motor OS. Global means all workspaces
  for that user.
- Key grants by the approval identity. Include a relative process executable's
  content hash and, for absolute system programs, the selected path/vector while
  documenting that later system-program updates remain trusted. Define the
  identity API so a future loadable tool can add its module hash.
- If persisting `session` or `global` fails, do not execute the pending call as
  if persistence succeeded. Report the error and keep the call unapproved.
- Add `/permissions` and `/permission revoke NAME [--global]`. Show scopes and
  short fingerprints; retain stale records for diagnosis but never match them
  to a changed identity.
- Test precedence, persistence, resume, branch changes, fork/clone exclusion,
  identity changes, revocation, write failure, and the fact that grants never
  bypass permission hooks.

## 5. Expose slash commands and approval choices in both UIs

- Add `/tools` plus `/tool enable|disable|reset NAME [--global]` to the shared
  command vocabulary and help text.
- Have the line UI print the configured tools, effective state, and source.
- Have the TUI render the same information as notices. The commands are entered
  only while the editor is enabled, so no provider turn can observe a changing
  tool list midway through a request.
- Extend line and TUI permission prompts with `[y]` once, `[n]` deny, `[s]`
  session, and `[g]` global. Show the exact tool/detail, workspace, and scope
  being granted before accepting a persistent choice.
- Render `/permissions` and support session/global revocation in both UIs.
- Keep command parsing strict and return short usage errors for missing names,
  unsupported flags, and unknown tools.
- Factor the parser/state action enough that line and TUI tests exercise one
  behavior rather than two subtly different grammars.

## 6. Ship optional sh and ls directories

- Add `src/bin/gears/tools/sh/` with its manifest and one-string command schema.
  Select `sh -c` on Linux and `/system/bin/rush -c` on Motor OS. Preserve the
  exact-command permission display and current timeout/output semantics.
- Add `src/bin/gears/tools/ls/` with a required path schema and a direct,
  non-shell `/bin/ls` or `/system/bin/ls` argument vector.
- Update the hermetic mock scenarios and integration fixtures so tests that
  need `sh` explicitly configure its directory. Add a real external-`ls` tool
  round without contacting the Internet.
- Ensure the development image retains the two directories at a documented
  path. If the existing `/devtools/src/src/bin/gears/tools/` copy already
  provides them, test that path rather than adding a second installed copy.
- Update `README.md`, `redesign.md`, `redesign-plan.md`, and mock-provider help
  where they still describe `sh` as built in or always present.

## 7. Gate the completed change

- Format with `cargo +nightly fmt` and deny all new Clippy warnings.
- Run the Gears and mock-provider component suites. All network behavior must
  use the hermetic local backend.
- Build Gears for Motor OS in debug and release modes.
- On Linux and Motor OS, manually verify a chat-only configuration, configured
  but disabled tools, session enable/disable, global enable/disable/reset,
  allow-once/deny/session/global approval, revocation, changed-tool
  invalidation, `sh`, `ls`, resume, workspace-relative paths, and TUI
  rendering.
- Check that the provider credential is absent from external children and that
  disabling a tool removes its schema and prompt fragment from the very next
  request.
- Commit in small, reviewable patches unless keeping the registry/runtime/UI
  boundary coherent makes a larger patch materially safer.
