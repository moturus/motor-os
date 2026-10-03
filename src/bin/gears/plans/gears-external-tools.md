# Gears external tools implementation plan

This plan implements the proposed contract in
`src/bin/gears/external-tools.md`. It replaces the special built-in `sh` path
with a generic, directory-backed tool registry, adds optional tool
directories for `sh`, `ls` and the common commands, and lets interactive
users change tool enablement for a session or globally.

Only child-process execution is implemented here. The registry and manifest
keep common package metadata separate from `kind = "process"` settings so a
later WebAssembly loader can reuse discovery, enablement, authorization,
identity, provider, and UI code. Selecting a runtime, ABI, capability model, or
WASI surface is not part of this plan.

The following choices are intentionally part of the review boundary:

- an empty `[[tools]]` list means a chat-only agent; no shipped directory,
  `sh` and `ls` included, is silently enabled;
- config names exact tool directories rather than scanning projects or a
  search path;
- slash-command global state lives in a small Gears-owned override file, so
  Gears never rewrites the user's main TOML or destroys its comments;
- session toggles are durable append-only entries and follow conversation
  branches;
- version 1 toggles directory tools only, not tools registered by hooks;
- a process child always starts in the selected workspace, while its package
  remains available through `GEARS_TOOL_DIR`; and
- saved grants, allow or deny, for a session or globally, are distinct from
  enablement, bind to a tool approval identity rather than its name alone,
  and in unattended runs only the deny grants apply. Gears checks them
  before a hook can authorize the call (batteries plan question 1).

No migration of old session data is required. Existing sessions containing
historical `sh` calls remain readable provider messages; tool availability for
the next request comes from current configuration and session tool-state
entries.

## 1. Parse and validate tool directories

- Add a small `tools` module with common package metadata, normalized tool,
  enablement, approval identity, registry, and a version-1 process-kind type.
- Read `gears.toml` in its Gears-directory location. Its move, old-location
  fallback, `api_key_file` alias and relative key/certificate paths belong to
  batteries phase 2.1, before this phase. Extend config version 1 with ordered
  `[[tools]]` entries containing a directory, absolute or relative to the
  Gears directory, and a default `enabled` boolean.
- Load `tool.toml`,
  `parameters.json`, and optional `prompt.md` without running the tool, applying
  the `[linux]` or `[motor]` overrides of description, parameters, prompt and
  display for the running system. Reject missing/special resource files,
  escaping relative paths, invalid names/schemas/templates, duplicate tool
  names, unsupported versions, unknown kinds and invalid process limits. A tool
  with no command for the running system is kept as "not available here":
  validated, listed, never sent.
- Require `kind = "process"` and keep timeout,
  stdin, output bounds, the `output` mode (`shell` or `stdout`), and command
  selection under `[process]`; parse the common `read_only` mark and the
  process's normal exit statuses. A status outside that set, a signal, timeout
  or failure to start is an execution error; stderr alone is not. Do not put
  process-only state in the common registry API a future loadable executor
  would have to imitate.
- Resolve a leading `./` program inside the
  tool directory, allow an explicit absolute system program, and reject bare
  names so ambient `PATH` cannot silently change execution or approval identity.
  Resolve the one exception, `gears-batteries`, beside the Gears executable.
- Keep parsing and normalization platform-neutral, selecting only the command
  vector through `cfg(unix)` / `cfg(not(unix))` so Motor OS remains a
  first-class build target.
- A process manifest may set `shell_state = true` to receive a private
  per-session `GEARS_SH_STATE_DIR`; Gears filters and saves the shell's
  `cwd.pending` and `env.pending` snapshots after the process exits.
- Add unit tests using temporary self-contained tool directories. Do not add
  a dependency; use the existing `serde`, `serde_json`, and `toml` crates.

## 2. Implement the process executor and replace the built-in path

- Give `Runtime` a registry of configured directory tools. Build provider tool
  specs and prompt fragments from only its effective enabled set.
- Remove `sh_spec`, `Runtime::execute_sh`, the hard-coded `call.name == "sh"`
  branch, and `runtime.sh_timeout_seconds` after the external `sh` manifest owns
  those settings.
- Execute an enabled directory tool through the shared bounded process
  runner. Expand typed string, boolean, integer, enum and list parameters into
  fixed arguments; the model never supplies a flag vector. Reject a value
  beginning with `-` unless it is after a literal `--` or exactly matches a
  manifest `allowed_flags` entry, which is placed before `--`; optionally
  write the exact argument JSON to stdin; set the documented non-secret
  environment, including `GEARS_SESSION_PATH` for a saved session; and remove
  the provider credential. Map the child's streams to the model-facing result
  according to the manifest's `output` mode.
- Set the child working directory to the canonical selected workspace. Resolve
  a leading `./` program against the tool package first and expose the package
  separately as `GEARS_TOOL_DIR`.
- Preserve separate live stdout/stderr events, raw exit status, cancellation,
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
  `~/.gears/tools.toml` on Linux and `/user/cfg/gears/tools.toml` on
  Motor OS. Use checked regular files and atomic replace; never partially
  overwrite a valid file.
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

- Replace the approver's boolean answer with six outcomes: allow once, allow
  for the session, allow globally, deny once, deny for the session, deny
  globally (batteries phase 3.3). Keep unattended approval
  as deny. A session or global answer in either direction is saved as a grant
  for the tool's approval identity; a saved denial refuses later calls
  without asking, a saved allowance runs them without asking.
- Grant precedence: a session grant beats a global grant for the same
  identity, and within a scope the latest answer replaces the earlier one.
  In an unattended run (`-p`), deny grants apply and allow grants do not.
- Decide in this order: reject unknown/disabled tools; look up saved grants
  for every call, with a saved denial winning; run permission hooks, whose
  denial or failure refuses and whose `confirm` asks for fresh attended
  approval; run when a hook allows; otherwise apply a saved allowance only
  in an attended run, then ask the attended user or deny. In unattended runs
  the batteries' hook policy supplies authority. Hooks use `confirm` for
  calls that publish or discard work (batteries plan question 1).
- Store session grants and revocations as session-wide append-only entries, not
  active-branch state. Saved sessions retain them across resume, ephemeral
  sessions retain them in memory, and new/forked/cloned sessions do not copy
  them.
- Add a versioned, atomically replaced global grant file at
  `~/.gears/permissions.toml` on Linux and `/user/cfg/gears/permissions.toml`
  on Motor OS. Global means all workspaces for that user.
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
  identity changes, revocation, write failure, saved denials before hook
  allowances, and `confirm` after saved allowances.

## 5. Expose slash commands and approval choices in both UIs

- Add `/tools` plus `/tool enable|disable|reset NAME [--global]` to the shared
  command vocabulary and help text.
- Have the line UI print the configured tools, effective state, and source.
- Have the TUI render the same information as notices. The commands are entered
  only while the editor is enabled, so no provider turn can observe a changing
  tool list midway through a request.
- Extend line and TUI permission prompts with six answers: `[y]` allow once,
  `[s]` allow for the session, `[g]` allow globally, `[n]` deny once, `[S]`
  deny for the session, `[G]` deny globally. Show the exact tool/detail,
  workspace, scope and direction being granted before accepting a persistent
  choice.
- Render `/permissions` and support session/global revocation in both UIs.
- Keep command parsing strict and return short usage errors for missing names,
  unsupported flags, and unknown tools.
- Factor the parser/state action enough that line and TUI tests exercise one
  behavior rather than two subtly different grammars.

## 6. Ship optional tool directories for sh, ls and the common commands

- Add `src/bin/gears/tools/sh/` with its manifest and one-string command schema.
  Select `bash -c` on Linux and `/system/bin/rush -c` on Motor OS. Preserve the
  working directory and exported variables between calls on both systems,
  exact-command permission display, and current timeout/output semantics.
- Add `src/bin/gears/tools/ls/` with a required path schema and a direct,
  non-shell `/bin/ls` or `/system/bin/sysbox ls` argument vector.
- Add directories for the common commands, each a manifest with the program's
  path per platform, a one-line description, typed parameters written down
  before building the directory, and a timeout. The read-only `rg`, `head`,
  `tail`, `diff`, `find`, `wc` and `cat` set `read_only = true`; `gix`, `lorry`,
  `cargo` and `sed` leave it false. Add `curl` for one HTTP or HTTPS URL,
  returning a redirect without following it. Each directory serves both
  systems: where the programs take different arguments, sysbox's `ls`,
  `find`, `head`, `tail`, `diff`,
  `wc` and `cat` against GNU's, the manifest gives a description and schema
  per system under `[motor]` and `[linux]`. Sysbox-backed commands invoke
  `/system/bin/sysbox COMMAND` directly; VM tests cover spaces and literal
  glob characters. Linux `find` exposes only name, type and path parameters,
  since GNU `find -exec` runs programs. `gix` and `lorry` have a Motor OS
  command only, `cargo` a Linux command only, and each is listed as not
  available on the other system. One example configuration lists every
  directory by a path relative to the Gears directory and is used on both
  systems. The pipeline filters the batteries plan's sysbox track adds
  (`sort`, `uniq`, `cut`, `tr`) and `xargs` get no directories: they work
  between pipes, which only `sh` has, and `xargs` runs other programs.
- Update the hermetic mock scenarios and integration fixtures so tests that
  need `sh` explicitly configure its directory. Add a real external-`ls` tool
  round and one read-only common command in `output = "stdout"` mode, without
  contacting the Internet.
- Have the developer image place the shipped directories under
  `/user/cfg/gears/tools/` and its `gears.toml` under `/user/cfg/gears/`, and
  test that path. A Linux user copies the same directories under
  `~/.gears/tools/`.
- Update `README.md`, `redesign.md`, `redesign-plan.md`, and mock-provider help
  where they still describe `sh` as built in or always present.

## 7. Gate the completed change

- Format with `cargo +nightly fmt` and deny all new Clippy warnings.
- Run the Gears and mock-provider component suites. All network behavior must
  use the hermetic local backend.
- Build Gears for Motor OS in debug and release modes.
- On Linux and Motor OS, manually verify a chat-only configuration, configured
  but disabled tools, session enable/disable, global enable/disable/reset,
  all six approval answers with a saved allow and a saved deny in each
  scope, a `-p` run that honors a deny grant and ignores an allow grant, a
  hook's `confirm`, revocation, changed-tool invalidation, `sh`, `ls`, a
  common command in each output mode, resume, workspace-relative paths, and
  TUI rendering.
- Check that the provider credential is absent from external children and that
  disabling a tool removes its schema and prompt fragment from the very next
  request.
- Commit in small, reviewable patches unless keeping the registry/runtime/UI
  boundary coherent makes a larger patch materially safer.
