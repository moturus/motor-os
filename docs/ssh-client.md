# SSH client configuration

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

Supported settings are `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`,
`IdentitiesOnly`, `StrictHostKeyChecking` (`ask`, `yes`, or `accept-new`),
`UserKnownHostsFile`, `BatchMode`, `ConnectTimeout`, `ServerAliveInterval`,
and `ServerAliveCountMax`.

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
Unsupported directives and malformed settings report a filename and line;
they are not silently ignored. A missing default config is allowed, while
a missing file explicitly selected with `-F` is an error.
