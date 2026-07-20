# russhd sends a duplicate channel close during shutdown

During Lorry Stage-1 closure, `src/tests/full-test.sh` exited after its system
and SFTP tests and ran its normal SSH shutdown cleanup. The OpenSSH client
reported:

```text
channel 0: protocol error: close rcvd twice
```

The problem is a race between two russhd paths for the same SSH channel.
Motor's special `exec("shutdown")` path sends the exit status, EOF, and
`CHANNEL_CLOSE` itself. An OpenSSH client invoked without stdin also sends
`CHANNEL_EOF` promptly. Because no child process or SFTP subsystem exists for
the special shutdown command, `ConnectionHandler::channel_eof` concludes that
nothing else owns channel completion and sends another `CHANNEL_CLOSE`.
Depending on packet and callback ordering, both close messages reach OpenSSH.

The failure originally looked like stale russhd state after sustained SSH/SFTP
traffic. Tracing showed that the new Lorry wrapper had actually exited before
its readiness probe due to an unrelated `set -e` shell-status bug; the
duplicate-close diagnostic came from the full-test cleanup's subsequent
`shutdown` command. A direct shutdown request reproduces the affected path.

The fix assigns every opened channel a shared close guard. The shutdown exec
path, normal child-reaping path, and fallback EOF handler must claim that guard
before explicitly closing the channel. Exactly one path can win, while later
completion callbacks become no-ops. The regression test runs the shutdown and
client-EOF owners concurrently and asserts that exactly one can claim the
channel close. End-to-end validation is a clean, status-zero
`ssh ... shutdown` with no OpenSSH protocol diagnostic.
