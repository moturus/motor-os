# SSH clients

Motor OS provides `ssh`, `scp`, `sftp`, `ssh-keygen`, and `ssh-copy-id` in
`/user/bin`. These commands implement the capabilities below; unsupported
OpenSSH options are errors. Run `ssh --help` for the SSH option reference.

## Remote shells and commands

```sh
ssh user@host
ssh -p 2222 user@host echo hello
ssh -t user@host top
ssh -T user@host cat < input.txt > output.txt
```

Destinations use `[user@]host`; bracket IPv6 addresses, such as
`motor@[2001:db8::1]`. The default port is 22. With no command, `ssh` opens
an interactive shell and requires a terminal on stdin. Commands run without
a remote terminal by default; `-t` requests one (and requires a local
terminal), while `-T` disables it. Command arguments are joined with spaces
for the remote shell; preserve any required remote quoting explicitly.

Command sessions forward stdin, stdout, and stderr and return the remote
exit status (0–255); client errors or a missing usable status return 255.
Interactive sessions forward Ctrl+C and terminal size changes. At the
start of a line, `~.` disconnects and `~~` sends a literal tilde.

## Shared connection options and authentication

`ssh`, `scp`, `sftp`, and `ssh-copy-id` share authentication, host-key checks,
configuration, and jump routing. Put options before the destination or
transfer operands; `--` ends option parsing.

| Option | Meaning |
| --- | --- |
| `-p PORT` | Port for `ssh` and `ssh-copy-id`. |
| `-P PORT` | Port for `scp` and `sftp`. |
| `-i FILE` | Private identity for `ssh`, `scp`, and `sftp`; repeat to try multiple keys. For `ssh-copy-id`, selects the **public key to install**. |
| `-F FILE` | Config file; `none` or `/dev/null` disables configuration. |
| `-J JUMPS` | Jump host or comma-separated chain (see below). |
| `-o Key=Value` | Set a supported configuration option (see below). |

Clients try configured OpenSSH private keys, prompting for encrypted-key
passphrases when needed, then password authentication if the server offers
it. Keys with unsafe permissions are ignored. `BatchMode=yes` disables
password, passphrase, and host-confirmation prompts. Agents and
keyboard-interactive authentication are not supported. `IdentitiesOnly` is
accepted; identities always come from the configured files.

Host-key checking defaults to `ask`: display the unknown key's fingerprint
and record it only after `yes`. `StrictHostKeyChecking=yes` requires an
already trusted key; `accept-new` records unknown keys without prompting.
Changed keys of a known algorithm are rejected under every policy.
Known-host records use `HOST KEYTYPE BASE64` for port 22 and
`[HOST]:PORT KEYTYPE BASE64` otherwise, using the resolved `HostName`.
Blank lines, comments, and trailing key comments are accepted; hashed
hosts, patterns, comma-separated hosts, and `@` markers are unsupported.
The known-hosts file's parent directory must already exist.

## File transfers

`scp` and `sftp` use the remote SFTP subsystem; legacy SCP is unsupported.

```sh
scp -P 2222 file.txt user@host:/path/file.txt
scp first.txt second.txt user@host:/path/directory
scp -r user@host:/path/directory /user/tmp
sftp -P 2222 user@host
sftp -b /user/tmp/sftp.commands user@host
```

`scp [-r] SOURCE... TARGET` requires exactly one remote side, written
`[user@]host:path` (including bracketed IPv6). Uploads accept multiple local
sources when the remote target is a directory; downloads accept one remote
source. `-r` copies directory trees. Remote paths are literal, with no
wildcard or tilde expansion. Local-to-local and remote-to-remote copies,
symbolic links, and `scp -p` are unsupported. Transfers preserve an existing
target's permissions; new files and directories use source permissions
translated to Motor OS roles when local.

`sftp [-b FILE] [user@]host` opens a command prompt, or reads commands from
`FILE` (`-` means stdin). Batch mode disables authentication prompts and
stops on the first error; the interactive prompt reports errors and
continues. Commands accept single/double quotes and backslash escapes,
with literal paths and no wildcard expansion.

| SFTP command | Meaning |
| --- | --- |
| `pwd`, `lpwd` | Print remote/local working directory. |
| `cd PATH`, `lcd PATH` | Change remote/local working directory. |
| `ls [PATH]`, `lls [PATH]` | List remote/local names. |
| `get [-r] SOURCE [TARGET]` | Download a file or directory tree. |
| `put [-r] SOURCE [TARGET]` | Upload a file or directory tree. |
| `mkdir PATH`, `lmkdir PATH` | Create a remote/local directory. |
| `rm PATH`, `rmdir PATH` | Remove a remote file or empty directory. |
| `rename [-l] OLD NEW` | Rename remotely; use replacing `posix-rename` if advertised, otherwise ordinary no-replace rename. `-l` forces no-replace rename. |
| `help` | List commands. |
| `bye`, `exit`, `quit` | Close the session. |

## Generate and install login keys

```sh
ssh-keygen -t ed25519 -C motor-client
ssh-keygen -y -f /user/cfg/ssh/id_ed25519
ssh-copy-id -i /user/cfg/ssh/id_ed25519.pub user@host
```

`ssh-keygen` generates Ed25519 OpenSSH keys, defaulting to
`/user/cfg/ssh/id_ed25519` and a matching `.pub` file. `-f FILE` selects a
different output, `-C COMMENT` sets the comment, and `-q` suppresses success
messages. It prompts twice for an optional encryption passphrase unless
`-N PASSPHRASE` is supplied (`-N ''` creates an unencrypted key). Existing
private or public files are never overwritten. `-y -f FILE` prints the
public key from an existing private key, prompting to decrypt if needed.
Generation supports only `-t ed25519`.

`ssh-copy-id` reads exactly one OpenSSH public-key line (default
`/user/cfg/ssh/id_ed25519.pub`), authenticates using existing credentials,
and installs it through SFTP into `.ssh/authorized_keys` under the remote
SFTP home directory. It keeps existing content and skips keys with the
same type and key data, regardless of comments. It sets `.ssh` to 0700
and creates/appends the key file with mode 0600. Use `-p PORT` for a custom
port and `-o IdentityFile=PATH` to select an existing authentication key;
`-i` selects the public key being installed.

This installation targets servers that read `.ssh/authorized_keys`.
Motor OS's own `russhd` instead loads a single `authorized_key` per user
from `/system/cfg/sshd.toml` at startup; copying an `authorized_keys` file
does not authorize logins there. Edit that configuration and restart the
server, or provision `users.motor.authorized_key` in an image with
`imager set --ssh-key FILE -i IMAGE` (see [imager](imager.md)).

## Host configuration and jump hosts

Motor OS reads OpenSSH-style client configuration from `/user/cfg/ssh/config`.
For example:

```sshconfig
Host ssh-hub
    HostName 11.12.13.14
    User foo

Host ssh-leaf
    HostName 10.0.0.4
    User bar
    ProxyJump ssh-hub
```

Run `ssh ssh-hub` to connect directly, or `ssh ssh-leaf` to connect through
`ssh-hub`. The gateway must allow TCP forwarding to the destination. The local
client authenticates and checks host keys for both connections, so the gateway
does not need a copy of the destination's private key.

`ssh`, `scp`, `sftp`, and `ssh-copy-id` share configuration and jump routing.
For example, `scp file ssh-leaf:/path/file` uses the same gateway. Gix currently
passes `-F /dev/null`, explicitly disabling client config for its SSH commands.

`Host` supports multiple patterns, `*`, `?`, and `!` negation. Blank lines,
comments, double-quoted values, and `Key Value` / `Key=Value` syntax are
accepted. Directive names are case-insensitive. Match against the alias in
the command, even when `HostName` specifies a different network address.

Supported settings (also accepted through `-o Key=Value`):

| Setting | Meaning / default |
| --- | --- |
| `HostName` | Network destination; defaults to the command's host. |
| `User` | Login name; defaults to `$USER`, or `motor`. |
| `Port` | Remote port; 22. |
| `IdentityFile` | Private-key path; `/user/cfg/ssh/id_ed25519`. Repeatable; `none` suppresses the default. |
| `ProxyJump` | Gateway or chain; `none` disables jumping. |
| `IdentitiesOnly` | `yes` / `no`; default `no` (file identities only in either case). |
| `StrictHostKeyChecking` | `ask` (default), `yes`, or `accept-new`. |
| `UserKnownHostsFile` | `/user/cfg/ssh/known_hosts`. |
| `BatchMode` | `yes` / `no`; default `no`. |
| `ConnectTimeout` | Setup timeout in integer seconds; 0 (default) disables it. |
| `ServerAliveInterval` | Keepalive interval in integer seconds; 0 (default) disables it. |
| `ServerAliveCountMax` | Maximum unanswered keepalives; 3. |

Command-line settings take priority. Otherwise the first matching scalar
setting wins; put specific blocks before `Host *` defaults. Identity files
accumulate in order, without duplicates. Explicit identity lists replace the
default `/user/cfg/ssh/id_ed25519`; `IdentityFile none` suppresses the default
without adding a key. Without `User`, the default is `$USER`, or `motor`.
Known hosts default to `/user/cfg/ssh/known_hosts`.

Each jump uses its own matching host block. Target command-line settings do
not become jump settings. `ProxyJump` accepts aliases or `[user@]host[:port]`,
including bracketed IPv6 addresses and comma-separated chains. The first
jump in a chain can itself have a configured gateway. `ProxyJump none`
disables jumping. Routes are limited to 16 hosts, including the destination;
cycles fail before connection setup.

Use `ssh -J ssh-hub ssh-leaf` to choose a gateway on the command line, `-F path`
to choose a config file, or `-F none` / `-F /dev/null` to disable config.
The supported settings are also accepted with `-o Key=Value`.

Paths are literal. Use `/user/cfg/ssh/key`, not `~/.ssh/key`. `Include`,
`Match`, `ProxyCommand`, value expansion, SSH URI jump syntax, agents,
certificates, multiplexing, and system-wide config are not supported.
General port forwarding (`-L`, `-R`, `-D`), agent forwarding, and X11
forwarding are also unsupported; `ProxyJump` provides gateway routing.
Unsupported directives and malformed settings report a filename and line;
they are not silently ignored. A missing default config is allowed, while
a missing file explicitly selected with `-F` is an error.
