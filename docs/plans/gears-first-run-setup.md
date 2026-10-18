# Gears first-run setup

Status: implemented 2026-10-17 (see "Decisions" for what was settled).

## Problem

`cargo run --release` in `src/bin/gears` exits with "no model selected" when
the Gears directory (`/user/cfg/gears` on Motor OS, `~/.gears` on Linux) has
no `gears.toml`, and also when it has the shipped one, which names no model.
A first run should instead let the user pick a provider, a model and an API
key in the TUI and then start working.

## What the user sees

1. **Which settings.** When Gears runs from its own source tree (see
   "Finding the configuration") and both configurations exist, it asks:

   > Gears is running from its source tree, `/…/src/bin/gears`. Which
   > settings should it use?
   > 1. Your settings: `~/.gears/gears.toml`
   > 2. The defaults that ship with this source: `config/gears.toml`

2. **Provider.** When no model can be selected, a picker lists the
   providers of the chosen `gears.toml`, its `default_provider` first. The
   shipped file defines `openrouter`, `openai` and `local`.
3. **Model.** A picker lists that provider's `models` from the file, plus
   "Other…", which asks for a model id.
4. **API key.** When the provider's key file does not exist and
   `OPENROUTER_API_KEY` is not set, Gears asks for the key with the typed
   characters hidden, and saves it to the key file in the Gears directory
   (owner-only permissions).
5. Gears saves the provider and model as the defaults in `provider.toml` in
   the Gears directory (what `/model ID --default` already writes) and
   starts the session. The next start asks nothing.

The line UI asks the same questions as numbered prompts. A `-p` run never
asks; it fails with "no model selected; run gears once without -p to choose
a provider and model, or pass --model".

## Built-in providers live in the shipped `gears.toml`

Nothing is compiled in. `config/gears.toml` (and `gears-batteries.toml`)
gain:

```toml
default_provider = "openrouter"

[providers.openrouter]
base_url = "https://openrouter.ai/api/v1"
api_key_file = "openrouter.key"
models = ["~deepseek/deepseek-v4-flash-latest", "google/gemini-3.8-flash",
          "google/gemma-4-26b-a4b-it:free", "openai/gpt-6.1-sol",
          "openai/gpt-6-astra"]

[providers.openai]
base_url = "https://api.openai.com/v1"
api_key_file = "openai.key"
models = ["gpt-6.1-sol", "gpt-6-astra"]

# No api_key_file: no Authorization header. Setup asks for the URL.
[providers.local]
base_url = "http://127.0.0.1:8080/v1"
models = ["local"]

[net]
egress_allowlist = ["openrouter.ai", "api.openai.com", "127.0.0.1"]
plain_http_allowlist = ["127.0.0.1"]
```

`models` is a new optional per-provider key, used only to fill the picker;
any model id can still be chosen. The existing top-level `[models] used`
list stays for `/model`.

## Finding the configuration

Today: `--config PATH`, else `gears.toml` in the Gears directory, else the
built-in defaults in `Config::default()`.

New:

- `--config PATH` wins, with no question.
- **User settings:** `gears.toml` in the Gears directory.
- **Source-tree defaults:** when the running executable lies under a
  `target/` directory whose parent holds a `Cargo.toml` for package `gears`
  and a `config/gears.toml`, that file. This covers `cargo run`,
  `lorry run` and running `target/release/gears` directly, without relying
  on environment variables.
- Only one exists: use it. Both exist: the TUI asks (step 1); a `-p` run
  uses the user settings. Neither exists: Gears fails with "no gears.toml:
  copy config/gears.toml and tools/ into ~/.gears".
- `Config::default()` stops carrying an OpenRouter URL and allowlist, so
  no provider is compiled in.

## Where changes go

Gears never writes `gears.toml`. Everything the user changes already goes to
the Gears directory: `provider.toml` (provider and model defaults),
`tools.toml`, `permissions.toml`, the sessions, and now the key files. That
stays true when the source-tree `gears.toml` is used:

- Relative `api_key_file` and `ca_cert` paths resolve against the Gears
  directory, never against the source tree, so a key typed at step 4 lands
  in `~/.gears/openrouter.key` either way.
- Relative tool directories resolve against the directory holding the
  `tools/` the file came with: the Gears directory for user settings, the
  crate root (`src/bin/gears`) for the source-tree defaults.
- The Linux default key path moves from `~/.config/gears/openrouter.key` to
  `~/.gears/openrouter.key`, the last old location left.

## Tests

- Config: per-provider `models`; relative key paths resolve against the
  Gears directory; source-tree detection from an executable path.
- Setup selection (pure function): which questions are needed for a given
  config, saved choice, session, `--model` and key state.
- TUI and line UI: driven with scripted input through the existing test
  hooks; the key is never echoed or written to a session or log.
- Process test: `gears` with an empty Gears directory and the source-tree
  config, answers on stdin, ends with `provider.toml` and the key file in the
  Gears directory and nothing written under the source tree.

Gears-only change: Gears host tests plus the Gears-only native run.

## Decisions (2026-10-17)

1. **Models.** `openrouter` lists `~deepseek/deepseek-v4-flash-latest`,
   `google/gemini-3.8-flash`, `google/gemma-4-26b-a4b-it:free`,
   `openai/gpt-6.1-sol` and `openai/gpt-6-astra` (the user's list). `openai`
   lists `gpt-6.1-sol` and `gpt-6-astra` (proposed from the same family;
   the user may correct them).
2. **Name.** `openai`.
3. **Local server.** Setup asks for its URL, suggesting `127.0.0.1` on Linux
   and `127.0.0.1` or `192.168.4.1` (the VM's host) on Motor OS, and saves it
   with the provider choice. A provider without `api_key_file` sends no
   `Authorization` header, and setup asks no key question for it.
4. **Settings question.** Asked every time Gears runs from its source tree
   and both files exist.
5. **Nobody edits `gears.toml`.** The TUI must offer an easy flow for every
   setting. `/setup` reruns the provider, model, URL and key questions at
   any time; `/tool` and `/permission` already cover tools and grants. Every
   answer is saved in the Gears directory; `gears.toml` is only the shipped
   starting point.
