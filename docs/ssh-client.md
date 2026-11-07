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

## Local TCP forwarding

`ssh -N -L 8080:localhost:80 user@host` listens on local port 8080 and connects
to `localhost:80` from the remote host. `-N` runs without a command, terminal,
or stdin forwarding. Omit `-N` to use forwards alongside a command or shell.
Use `[bind:]port:host:port`, bracketing IPv6 addresses. Ports must be 1–65535.
Target names resolve at the remote host. Forwards also work through `-J`.

Listeners default to loopback. `-g` or `GatewayPorts yes` changes the default
to all interfaces; an explicit bind address takes priority. Empty binds and
`*` select all interfaces. Any local process that can reach a listener can
use the SSH connection to reach its target.

Setup failures warn and leave other forwards running. `ExitOnForwardFailure yes`
instead exits 255 and releases earlier listeners. A later refused target closes
only that connection. After a command finishes, listeners close and admitted
forwards drain before SSH returns its status. Ctrl+C or transport loss cancels
the forwards. A blocked command-output pipe can also pause forwarding; use
`-N` for a tunnel without command-output backpressure.

`ssh -N -D 1080 user@host` creates a SOCKS4, SOCKS4a and SOCKS5 CONNECT
proxy. No SOCKS authentication is required. The local SOCKS client selects
the target; names resolve at the SSH server. The same bind controls, setup
failure policy and connection lifetime apply. An incomplete handshake uses
one forwarding slot without blocking other connections; no handshake timer
is imposed.

## Remote TCP forwarding

`ssh -N -R 8080:localhost:80 user@host` asks the server to listen on port 8080
and connects each forwarded connection to `localhost:80` on this client.
Use `[bind:]port:host:port`, bracketing IPv6 addresses. Target names resolve
on the client. Remote forwards also work through `-J` and alongside commands.

Use remote listen port 0 to have the server allocate a port; SSH prints the
allocated port to stderr. Target ports must be 1–65535. The server controls
which interfaces its remote listeners use. Motor's default is loopback;
the server's `gateway_ports = true` exposes them on all interfaces.

The same setup-failure and connection-lifetime rules apply. After a command
ends, new remote connections are refused while admitted connections drain.
Configured forwards run only for SSH's final destination; copy applets load
the settings without starting listeners.

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
ssh-copy-id -t /user/cfg/ssh/authorized_keys.alice -i key.pub -p 2222 alice@motor-host
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
and installs it through SFTP. By default it targets servers that read
`.ssh/authorized_keys` under the SFTP start directory: it sets `.ssh` to 0700
and creates or appends the key file with mode 0600.

`-t PATH` names the key file instead, and is required for a Motor OS server.
`PATH` is absolute or relative to the SFTP start directory. Its parent must
exist, as `/user/cfg/ssh` does on every Motor OS image; `ssh-copy-id` neither
creates nor changes it. It keeps existing content, including comments and a
missing final newline, and skips a key already listed
as a plain record with the same type and key data, regardless of comments. If
the key's base64 is on any other line outside a comment, as in a record with
options such as `from=` or `command=`, it reports an error and leaves the file
unchanged rather than adding an unrestricted copy. Use
`-p PORT` for a custom port and `-o IdentityFile=PATH` to select an existing
authentication key; `-i` selects the public key being installed.

## Log in to a Motor OS server

Motor OS has one Interactive user. An SSH login name selects credentials: it
creates no OS user and changes nothing a session may do. Shells and commands
start in `/user`, which is also their `HOME`, under every name. Every
authenticated session can edit every credential file, so the lists below select
credentials rather than separate names from each other. Each name has an
optional password and any number of public keys:

| File | Holds |
| --- | --- |
| `/user/cfg/russhd/users.toml` | The login names and their password verifiers |
| `/user/cfg/ssh/authorized_keys.NAME` | The public keys of login name `NAME` |

```toml
version = 1

[users.alice]
salt = '...hex...'
password_hash = '...hex SHA-256 of the salt bytes followed by the password...'

[users.deploy]
```

A name is 1 to 64 ASCII letters, digits, `_`, or `-`. A record with an absent
or empty `password_hash`, like `deploy` above, has no password. Images ship one
name, `motor`, with a test password and key, and a test host key; replace all
three before any deployment that is reachable from a network you do not control.

`russhd` reads both files at every authentication, so a change applies to the
next login with no restart; sessions already established stay logged in. Every
username is offered the same methods, whether or not it exists. A connection
runs one session channel at a time, so a multiplexing client's second session is
refused until the first closes. Independent TCP forwards can share the connection.

To use `russhd` as a jump host or accept TCP forwards from another SSH client,
set `allow_tcp_forwarding = true` in `sshd.toml` and restart the service. This
optional version 2 setting defaults to false; shipped images enable it. It
allows connections to any destination reachable by the server, and remote
listener requests such as OpenSSH's `-R`. Remote listeners bind loopback by
default. `gateway_ports = true` exposes every remote listener on all interfaces,
as with OpenSSH's `GatewayPorts yes`; shipped images leave it false. Cancelling
a remote listener stops new accepts while existing forwarded connections finish.

A key file holds `KEYTYPE BASE64 [COMMENT]` lines, blank lines, and `#`
comments, with LF or CRLF line endings. A key listed for two names is listed in
both files. A record with options (`command=`, `from=`, `restrict`, and so on), a
certificate, a `cert-authority` entry, or a malformed line authorizes nothing but
costs only itself; `russhd` never strips options to recover a key. A NUL byte or
non-UTF-8 text anywhere in the file, even in a comment, refuses the whole file.
A key file alone creates no login name, and removing a record disables its name
at the next authentication, whatever key files remain.

To add a key to a running system, name its file on the client:

```sh
# Motor OS client
ssh-copy-id -t /user/cfg/ssh/authorized_keys.alice -i key.pub -p 2222 alice@host
# OpenSSH 9.4 or newer
ssh-copy-id -s -t /user/cfg/ssh/authorized_keys.alice -i key.pub -p 2222 alice@host
# Older OpenSSH
ssh -p 2222 alice@host 'cat >> /user/cfg/ssh/authorized_keys.alice' < key.pub
```

A name with a password but no key can install its first key this way. Other
forms fail without installing a key: without `-t` the SFTP installers try `/.ssh`
and get `Permission denied`, and OpenSSH's shell installer (no `-s`) stops at
`dirname`, which Motor OS does not have. Installers do not coordinate and have
no rollback, so serialize updates to one list. OpenSSH's `-s` mode rewrites the
whole file, and its `chmod 700` of the parent leaves `/user/cfg/ssh` at
`rwxrwx---`.

To add a name, create its key file first and its record second. Replace the
registry atomically, because `russhd` denies all new logins while it is
incomplete. A file created from a shell starts readable by None, which `russhd`
refuses in a registry, so narrow it before renaming it into place:

```sh
cp /user/cfg/russhd/users.toml /user/cfg/russhd/users.new
# ...edit users.new...
chmod rwxrw---- /user/cfg/russhd/users.new
mv /user/cfg/russhd/users.new /user/cfg/russhd/users.toml
```

`russhd` fails closed. Nothing is cached, so there is no last-known-good copy:

| Problem | Effect |
| --- | --- |
| Registry missing, unreadable, unsafe, oversized, or malformed | All new logins are denied |
| The same with a key file | That name's keys are denied; its password still works |
| Key file missing or empty | The name has no keys; its password still works |

Unlike a bad key record, one invalid record makes the whole registry malformed.
`russhd` logs why it refused a file or skipped a record to
`/system/logs/russhd.log`, with a line number where it has one, and never quotes
the file.

A credential file must be a regular file. None must not be able to write it, or
to replace any directory above it up to `/user` (through `/` for a location
outside `/user`), and must not be able to read the registry. Limits are 1 MiB per
file, 1,024 users, 1,024 keys per file, and 16 KiB per key line; going past one
refuses the whole file.

If no usable credential is left, recover through the VM console, or stop the VM
and use `imager set` (see [imager](imager.md)), which also creates names and
replaces whole key lists in a stopped image.

`/system/cfg/sshd.toml` holds the service settings and names the two credential
locations, as normalized absolute paths:

```toml
version = 2
listen_on = '0.0.0.0:2222'
path = '/system/bin:/user/bin'
host_key = '...OpenSSH private key...'
users_file = '/user/cfg/russhd/users.toml'
authorized_keys_dir = '/user/cfg/ssh'
```

Version 1 configurations, `[users]` sections, and unknown fields are rejected:
this file holds no login credentials.

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
| `LocalForward` | `[bind:]port host:port`; repeatable, SSH final destination only. |
| `DynamicForward` | `[bind:]port`; repeatable SOCKS listener, SSH final destination only. |
| `RemoteForward` | `[bind:]port host:port`; repeatable remote listener, SSH final destination only; listen port 0 allocates a port. |
| `GatewayPorts` | Default local binds to all interfaces; `no`. |
| `ExitOnForwardFailure` | Exit on forward setup failure; `no`. |

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
Remote (`-R`) forwarding, agent forwarding, and X11
forwarding are unsupported.
Unsupported directives and malformed settings report a filename and line;
they are not silently ignored. A missing default config is allowed, while
a missing file explicitly selected with `-F` is an error.
