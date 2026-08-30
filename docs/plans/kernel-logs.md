# Kernel logs and the serial console

Status: **design, not started**. Bug 1 of `docs/plans/future-work.md` is the
trigger. Once the plan at the end is implemented, this document becomes the
official description of the feature: it is renamed to `docs/kernel-logs.md`,
the "Plan" section is dropped, and the file:line references are refreshed.
Audience: an engineer implementing or maintaining sys-tty and strobe.

## Summary

Kernel log lines -- the kernel's own records and every `SysRay::log` from
user space -- reach the serial console through sys-tty, the process that also
relays the console program's stdout and stderr. Today the three streams are
written to the UART in 80-byte pieces under independent lock acquisitions, so
a log line can land inside an application's escape sequence. In a debug build
the ~1200 lines that the vdso and sys-io emit while rmux runs break
`src/tests/test-terminal-size.sh` on every run.

Logging is best-effort, and this design keeps it that way: wherever the
choice was between a guarantee and less code, less code won.

The design has two parts:

1. **Console arbitration in sys-tty.** One writer thread owns the UART.
   Application output is written in whole relay chunks as it arrives, and a
   chunk from one relay is never written inside an escape sequence that the
   other relay's output began. Kernel log records prefer gaps in application
   output, and the writer never splits one of its own chunks or records.
   Avoiding the middle of a repaint is a best-effort quiet-window policy: the
   stdio byte streams carry neither the application's original `write()`
   boundaries nor repaint boundaries. Keyboard input is never delayed by
   output. An incomplete ANSI sequence gets a 100 ms grace period when a log
   record or the other relay's chunk is waiting; after that sys-tty cancels
   the sequence and writes what is waiting, intentionally disrupting the
   active TUI.
2. **A file mode.** When `sys-tty.cfg` says so, sys-tty forwards every kernel
   record it receives to strobe, which writes `/system/logs/kernel.log`.
   Only structurally classified WARN and ERROR records are also sent to the
   console; unclassified and free-text records remain file-only. The file copy
   is unfiltered and byte-preserving. Strobe rotates the file at 4 MB into
   `kernel.log.prev` and, when the filesystem has less than 50 MB free,
   deletes the oldest `.prev` file it keeps for any tag. Reading the retained
   copy takes `cat /system/logs/kernel.log` over ssh.
   Delivery to either sink is best-effort, as logging already is.

Part 1 is correct on its own and is what the debug full test needs. Part 2
takes the routine flood off the console, makes an unfiltered retained kernel
record stream readable remotely, and bounds its size on disk. Today a headless
daemon's records exist only on the serial line.

## Today

sys-tty (`src/sys/sys-tty/src/main.rs`) spawns the console command with
piped stdio and waits for it on the main thread. Three other threads touch
the UART, all through one mutex (`src/sys/sys-tty/src/serial.rs:83-93`):

- the input thread (`main.rs:136-162`) waits on the kernel's console object,
  which is woken both by the serial interrupt and by every kernel log message
  (`src/sys/kernel/src/uspace/serial_console.rs:96,166`); it forwards
  received bytes to the child's stdin, then drains the kernel log ring and
  writes it to the UART (`main.rs:154-158`, `main.rs:217-236`);
- the stdout relay (`main.rs:167-179`) and the stderr relay
  (`main.rs:182-192`) each read at most 80 bytes and write them under a fresh
  lock acquisition.

The UART code already changes two things on the way to the port and keeps
doing so after this change: every `\n` is sent as `\n\r` (`serial.rs:44-50`),
and a backspace or DEL is sent as backspace, space, backspace
(`serial.rs:36-43`).

The kernel copies each log message as unframed bytes into a 64 KB ring in
sys-tty's memory and advances a shared offset (`serial_console.rs:103-170`);
a `SysRay::log` message is at most 256 bytes
(`src/sys/kernel/src/uspace/sys_ray.rs:216`). A call need not contain a
newline, and wakes may coalesce, so the current consumer cannot recover
message boundaries from the byte stream. There is no back-pressure and no
detection of the ring being lapped. The module's header comment says why the
forwarding exists: so that kernel lines do not intermix with user output. The
arbitration that would make that true was left to sys-tty and never written.
Kernel panics turn raw serial writes back on
(`serial_console.rs:186-192`) and bypass sys-tty; this stays.

The child's stdout and stderr pipes are 2 KB rings (one page, half of it
data: `src/sys/lib/rt.vdso/src/stdio.rs:1327`,
`src/sys/lib/moto-ipc/src/stdio_pipe.rs:1217-1240`). A screen repaint of
several KB crosses in a few handoffs and then becomes ~100 separate serial
writes, each a slot for a log line.

In a debug build the console carries three streams:

- application stdout: frames, prompts, echoes;
- application stderr: the vdso's own diagnostics go to the process's stderr
  first (`src/sys/lib/rt.vdso/src/util/logging.rs:101-112`; commit 13735ac7
  made this deliberate), so rush's and the rmux client's `file_open`/`stat`
  debug lines arrive through the stderr relay. Only those two processes write
  this pipe: rmux merges its pane children's stderr into the pane stream
  (`src/bin/rmux/src/pane.rs:511`), and the rmux server runs with null stdio
  (`src/bin/rmux/src/client.rs:642-644`);
- the kernel ring: sys-io logs straight to `SysRay::log`
  (`src/sys/sys-io/src/main.rs:22`; its logger runs at Debug in debug
  builds, `src/sys/sys-io/src/logger.rs:38`), plus the kernel's own INFO and
  above, plus the vdso diagnostics of every process whose stderr is unusable:
  services such as russhd, whose pipes sys-init drops, and the rmux server
  fall back to `SysRay::log` (`logging.rs:91-99`).

Adjacent defects in the same code, fixed by part 1 whichever policy is used:

- no lap detection: if sys-tty falls more than 64 KB behind, it prints
  overwritten bytes;
- the wrap-around path (`main.rs:231-235`) inserts a stray `:` between the
  two halves and `unwrap()`s `from_utf8`, so a multi-byte character at the
  wrap, or a lapped ring, panics the console driver;
- `read_serial` takes the output lock, so a long write delays keystrokes;
- the relays busy-loop on EOF until the child exits.

## Requirements

1. Bytes in one relay read reach the wire contiguously, and a chunk from one
   relay is not written inside an escape or control sequence that the other
   relay's output began. This is intentionally not phrased in terms of the
   application's `write()` or `flush()`: stdout and stderr are byte-stream
   pipes, so a read may split or combine writes, and the two pipes do not
   expose one total source-write order. A relay read is the only observable
   unit sys-tty can keep whole without a new terminal protocol.
2. A framed kernel log record reaches each selected sink whole or not at all.
   The in-memory ring remains overwrite-on-wrap. If sys-tty is lapped or a
   bounded output queue drops records, it detects the resulting sequence gap
   or queue loss and emits one warning marker when possible.
3. The console writer gives an incomplete application escape or control string
   up to 100 ms to reach a scanner safe point once a console log record, or a
   chunk from the other relay, is waiting. At the deadline it emits `CAN`
   (`0x18`) to abort the sequence, followed by `\r\n` and the waiting output.
   Console logs are allowed to disrupt a TUI: all records use the console in
   console mode, while file mode limits this disruption to WARN and ERROR
   records. Between complete sequences, a quiet window makes insertion between
   repaints likely but cannot guarantee it because repaint boundaries are not
   present in the byte stream.
4. Keyboard input is never delayed by output.
5. Logging remains best-effort. Losses sys-tty detects are marked when
   possible, but a successful UART write or strobe RPC is not a durability
   guarantee, and no logging path retries, re-routes queued records, or waits
   to avoid a loss.
6. In file mode, every kernel record sys-tty receives is offered byte-for-byte
   to `/system/logs/kernel.log`, readable by an Interactive ssh session.
   Classification never filters or rewrites the file copy. Only structurally
   classified WARN and ERROR records also go to the console; unclassified and
   free-text records are file-only. Records emitted before ring registration
   retain their existing serial-only path.
7. The timing scanner consumes, removes, and rewrites no application byte;
   sys-tty remains the byte pump `docs/tui.md` describes, with the two
   translations the UART code already applies (see "Today"). The writer may
   add the explicit `CAN` and `\r\n` from requirement 3. In a console-bound
   log copy only, every ASCII `ESC` byte and every UTF-8 encoding of a
   C1 control is replaced by a safe diagnostic; the file copy is unchanged.

## Design

### Console arbitration

Threads after the change: the input/ring thread, the two relays, one
**writer**, in file mode one **forwarder**, and the main thread waiting on the
child.

- The **writer** is the only sys-tty thread that writes the UART. Kernel panic
  output, the kernel's nested-logging fallback, and the kernel's other raw
  serial writes (such as `WDIAG` lines) still bypass it. Stdout and stderr each
  have one bounded handoff, and console log records have a third. A full
  stdout or stderr handoff blocks only that relay and preserves the child's
  existing pipe back-pressure; a full log handoff drops complete records and
  never blocks the ring drain. The writer emits each accepted chunk or record
  whole.
- The **relays** read into buffers of at least 4 KB (the pipe holds 2 KB, so a
  read takes everything currently available) and send each read as one
  source-tagged screen chunk. Reads from either individual stream keep their
  order. There is no claimed total order between stdout and stderr: these are
  the only two output streams of sys-tty's single console child, and the pipes
  expose no write or flush boundaries beyond the chunks sys-tty reads.
- The **input/ring thread** no longer writes the UART. On every wake it first
  drains a validated ring snapshot (see "Framed kernel ring") and hands the
  records to the writer and, in file mode, the forwarder; then it reads the
  receive register without taking the transmit lock (RX and TX are distinct
  registers behind one port address, and there is one reader) and hands
  received bytes to the child's stdin. Slow UART output therefore delays
  neither keyboard reads nor ring copies. A child that stops reading its own
  stdin can still block later input-thread work; that pre-existing input
  back-pressure is not caused by output and is outside this change.

The writer starts before sys-tty prints anything. The existing "all services
up ... Starting <command>" message moves to the end of sys-tty initialization:
the writer is running, the kernel ring is registered, and the optional
forwarder thread has been launched. It is then printed immediately before
spawning the console child, so its wording and timestamp describe the actual
milestone. Temporary finer-grained timing messages may be used while measuring
boot latency, but are removed before the feature is complete.

The writer's policy, with initial values that are constants to tune:

- A screen chunk is written immediately, unless the scanner is inside a
  sequence that an earlier chunk from the *other* relay began (the writer
  remembers which relay wrote the last chunk while the scanner is not at
  ground). Then the chunk waits for the sequence to complete, up to the
  **ANSI grace period** below; chunks from the relay that owns the sequence
  keep flowing, and later chunks from the waiting relay queue behind it in
  order.
- In console mode every log record is console-eligible. In file mode only
  structurally classified WARN and ERROR records are console-eligible. An
  eligible record is written immediately if the screen has been quiet for the
  **quiet window** (30 ms); otherwise it is held.
- Held records become ready to flush when the screen goes quiet for the
  window, or when the **hold bound** is reached (500 ms of holding, or 16 KB
  held), whichever comes first.
- If the scanner is safe, a ready flush or a waiting chunk proceeds
  immediately. Otherwise the writer starts an **ANSI grace period** of
  100 ms. If application output reaches a safe point during that period, the
  flush proceeds there. At the deadline the writer emits `CAN` (`0x18`). The
  scanner must transition to its ground state; the writer then emits `\r\n`
  and writes what was waiting. This deliberately aborts the application's
  incomplete control function; disruption of its TUI is expected.
- At an ordinary safe-point flush, if the last screen byte was not a line end,
  the writer prefixes the log with `\r\n`. Neither sink adds a line end to a
  record that lacks one; as today, the next output follows it directly.
- Held log data is capped at 256 KB. Beyond that the oldest complete records
  are dropped and counted. One marker
  (`[kernel log: N records dropped: console backlog]`) precedes the next
  possible flush.

The **scanner** is a minimal incremental ECMA-48 framing state machine over
the combined bytes as they will reach the terminal. It tracks ESC sequences
with intermediates (including forms such as `ESC ( B`), CSI parameters and
intermediates, OSC, DCS, SOS, APC, and PM strings with their applicable BEL or
ST terminators, and an incomplete multi-byte UTF-8 character, which is also an
unsafe insertion point. It only answers whether insertion is syntactically
safe; it consumes and alters no application byte. `src/bin/rmux/src/ansi.rs`
is the closest in-tree parser, but it lives in a binary crate and also
interprets actions, so sys-tty gets a smaller framing-only module. A forced
`CAN` is fed through the same state machine, which must return to ground before
the following `\r\n` and waiting output.

Before a log record is offered to the console, sys-tty makes a console-only,
byte-oriented sanitized copy:

- every ASCII `ESC` byte (`0x1b`) becomes
  `[UNSAFE ASCII ESCAPE SEQUENCE DETECTED]`;
- every valid two-byte UTF-8 encoding of a C1 control, U+0080 through U+009F
  (`0xc2 0x80` through `0xc2 0x9f`), becomes
  `[UNSAFE C1 CONTROL CHARACTER DETECTED]`.

This neutralizes both the seven-bit `ESC` form and the UTF-8 C1 form that
terminals such as xterm may interpret directly (U+009B is CSI), while leaving
the surrounding text visible. Ring payloads are defined to be UTF-8, so a raw
single-byte C1 form is not valid input. The scanner consumes the sanitized
copy normally. The original record, including every replaced byte, is offered
unchanged to the file forwarder.

### Framed kernel ring

The 64 KB ring remains overwrite-on-wrap. Its control block contains two
aligned, kernel-owned `AtomicU64` words: `generation` and `end`, the cumulative
byte count published by the kernel. sys-tty only reads them; there is no
userspace cursor for the kernel to read or trust. The registration string
keeps its shape (`serial_console:{buf_addr}:{ctl_addr}`). Registration validates
that the control block is aligned and contained in mapped memory suitable for
atomic access. The byte layout and helpers live in `moto-sys`, which is already
shared by the kernel and sys-tty.

A record has one fixed 8-byte header: a 16-bit magic/layout version, a 16-bit
payload length, and a wrapping 32-bit record sequence, followed immediately by
the UTF-8 payload. There is no padding or trailer. The maximum payload is
65,528 bytes: the 64 KB ring minus the header. One kernel logger call or one
`SysRay::log` call is one record even when it has no newline.

Under the existing log lock, the kernel assigns the next sequence, stores the
odd `generation` with relaxed ordering, and executes a release fence before
touching ring bytes. The fence is the writer-side barrier that orders
publication of the odd generation before the copies that follow; a release
store alone would order only operations before that store. The kernel then
writes the complete header and payload with the existing two-piece copy (the
frame may cross the physical end), stores the new `end` with relaxed ordering,
and stores the next even `generation` with release ordering. The final store
publishes the byte copies and `end`; the kernel then wakes sys-tty.
`generation` and `end` are written as `AtomicU64` stores through the kernel's
direct mapping of the page, not with `copy_to_user`: that is a memcpy of a
runtime length (`src/sys/kernel/src/mm/user.rs:526-575`) and is not promised
to be one 8-byte store, so sys-tty could read a torn word. The kernel never
waits for the consumer and may overwrite unread records. The generation pair
is a minimal seqlock: it prevents sys-tty from accepting bytes copied while an
overwrite was in progress.

A payload larger than the defined maximum, or a failed copy, is sent to raw
serial and is not published to the ring. The kernel still returns generation
to an even value; a later sequence gap makes the best-effort loss visible if
another framed record follows. Kernel panic and nested-log fallback behavior
remain unchanged.

The **ring drain** keeps its last published boundary and last delivered
sequence. Both the ordinary and lapped paths use the same stable-snapshot
protocol. It loads `generation` with acquire ordering and returns if it is odd,
then loads `end` with relaxed ordering. If the wrapping distance from the
previous boundary fits in the ring, it copies that range into one reusable
linear 64 KB staging buffer, in two pieces when the range crosses the physical
end. If the distance exceeds the capacity, it notes a possible lap and copies
nothing. In both cases it then executes `atomic::fence(Acquire)` before loading
`generation` again with relaxed ordering. The sampled `end` and any copied
bytes are accepted only if the two generation values are equal and even.

On an odd first sample or a generation mismatch, sys-tty discards the
attempt, leaves its boundary unchanged, services serial input, and samples
again before sleeping; it does not spin waiting for a quiet producer. On a
stable lap, it discards the retained window and resumes at the sampled
`end`, which is a known record boundary. This deliberately gives up
recoverable old records instead of
adding trailers or a backward recovery walk. A stable ordinary copy is split
into records. A header with the wrong magic or a length that runs past the copy
is a kernel/layout bug: sys-tty emits one warning, discards that snapshot, and
resumes at its published end boundary.

When the next valid record is decoded, wrapping sequence arithmetic gives the
number of records skipped by a lap, bad snapshot, oversize record, or failed
copy. sys-tty offers one synthetic WARN record
`[kernel log: N records lost: ring overwrite]` before that record. The marker
goes to the file in file mode and to the console under the normal WARN policy.
No path inserts separators into payloads or converts UTF-8 after framing.

### File mode: forwarding to strobe

sys-tty does not write `/system/logs` itself, for three reasons:

- only System may create or rename entries there
  (`docs/fs-permissions.md`), and the shipped `tty:` lines run sys-tty as
  Interactive (`src/sys/sys-init/src/lib.rs:20`; only the System-console test
  image says `tty:system:`). Since 4939cdbb the console shell's role is
  derived from sys-tty's, so making sys-tty System to write a file would also
  make the console shell System;
- "System strobe alone creates and rotates the files" is documented
  (`docs/tools.md`, `docs/process-roles.md` section 5) and asserted by
  systest (`src/sys/tests/systest/src/logging.rs:290-292`);
- strobe already has the file creation with the right permissions
  (`src/sys/strobe/src/io_thread.rs:13-40`); a second copy is a second thing
  to keep right.

So in file mode sys-tty is a strobe client with the reserved tag `kernel`,
over the same `sys-log` channel and handshake every service uses
(`src/sys/lib/moto-log/src/lib.rs:112-143`; systest's raw client in
`logging.rs:44-59` is the model, since sys-tty must not install a global
`log` logger for this). The ordinary connection still requires `CAP_LOG`.
Strobe additionally requires `CAP_IO_MANAGER` to claim the canonical
`kernel` tag or submit its raw operation; sys-tty already holds both
(`src/sys/sys-init/src/main.rs:130-134`), and strobe already reads a peer's
capabilities from the connection handle (`src/sys/strobe/src/logging.rs:218`).
This prevents another `CAP_LOG` process from claiming or forging
`/system/logs/kernel.log`. The forwarder thread owns the connection and does
the RPCs; nothing else blocks on strobe.

- **Records.** The Small IPC channel carries about 4 KB of payload. A request
  may concatenate the payloads of several complete kernel records and is split
  only at record boundaries; ring headers are never written to the file. A
  dedicated `CMD_LOG_RAW` request tells strobe to write its payload verbatim
  instead of overloading the numeric log-level field. It is accepted only on
  the reserved `kernel` connection. Ordinary `LogRequest` behavior and
  validation stay unchanged.
- **Success semantics.** A successful raw RPC means strobe accepted the bytes
  into its bounded in-process I/O queue; it does not promise that a later
  write, flush, or rotation reached storage. Strobe writes and flushes each
  raw request best-effort. On its first file I/O failure it disables that
  connection's file and emits one best-effort diagnostic rather than creating
  a feedback loop. The existing flush policy for ordinary strobe records is
  unchanged;
  this feature defines only the raw kernel path.
- **File.** The fixed name is `/system/logs/kernel.log`, with the permissions
  of every strobe log: Interactive may read it. Strobe's "started log" header
  carries UTC; sys-tty's first raw request records the boot-relative timestamp
  captured at the same initialization milestone as the truthful "all services
  up ... Starting <command>" status. Native systest can therefore read the
  milestone without interpreting console output. Every kernel record payload
  is then written byte-for-byte, including its original line endings and all
  control bytes.
- **Rotation.** Size-based, for every tag, in strobe: before a write would
  take the current file past 4 MB (a constant in strobe for now), it is
  renamed to `.prev`, replacing the previous generation, and a new file is
  created. This adds to the existing rotate-on-reconnect (`io_thread.rs:72-86`)
  and keeps every service log within one maximum-size record of 8 MB on disk.
  Rotation failure keeps the current file when possible, disables further
  rotation for that connection, and reports one best-effort diagnostic. Cost:
  one rename and one create per 4 MB. Without a cap, a debug build under
  network load writes `kernel.log` at roughly 200 KB/s per thousand TCP
  segments per second (sys-io logs two or three DEBUG lines per data segment,
  `src/sys/sys-io/src/runtime/net/socket/tcp.rs:1226,1324,1363`), which fills
  the main image's 256 MB data partition (`src/imager/motor-os.yaml:39`) during
  one debug `full-test.sh`.
- **Disk-space rule.** Whenever strobe creates a log file -- at connection start
  and at rotation -- it first reads the filesystem's available bytes the way
  `df` does (`img_files/motor-os-base/system/bin/df` runs
  `sysbox stats get 2:1001`: sys-io's `fs.available_bytes` metric,
  `src/sys/sys-io/src/runtime/fs/stats.rs:84,156`, through
  `moto_stats::Collector`, which strobe already links because it hosts the
  stats registry, `src/sys/strobe/src/stats.rs`). No new filesystem operation
  is added. If fewer than 50 MB are available, strobe deletes `.prev` files in
  `/system/logs`, oldest first by the `modified` time `FsClient::metadata`
  reports, until 50 MB are available or none remain. A live `.log` is never
  deleted. If the provider is unreachable (sys-io registers a few moments after
  boot), the check is skipped and nothing is deleted. The base and system-tty
  images have 64 MB data partitions, so on them the rule keeps no `.prev` at
  all; 4 MB of current file per tag is what they retain.
- **Boot records.** Records emitted before sys-tty registers the console stay
  on the serial line as today; there is no boot ring to replay. The "all
  services up ... Starting <command>" status is also serial-only because it is
  sys-tty output rather than a kernel record. It now runs through the writer
  after ring registration, at the milestone described above.

### Failure rules

- **Strobe not configured, or the connect fails.** sys-init starts strobe
  before sys-tty and waits up to five seconds for it, so a failed connect
  means strobe is absent or broken. sys-tty prints one notice, switches to
  effective console mode, and does not retry during that process lifetime.
- **Strobe stops answering.** The raw RPC remains synchronous and has no
  timeout (`do_rpc(None)`), so a stalled strobe blocks only the forwarder
  thread. Its record queue is capped at 1 MB. When the cap is reached, the
  oldest record is dropped and counted; nothing is re-routed to the console,
  which continues receiving only WARN and ERROR records. If the outstanding
  RPC later completes, the file receives one
  `[kernel log: N records dropped: file backlog]` marker before subsequent
  records.
- **Strobe disconnects or rejects a request.** The forwarder disables file
  mode, drops its queue (counted), prints one notice with the count through
  the writer, and does not reconnect. All later records use console mode.
  There are no automatic retries.
- **A write fails after strobe accepted it.** The record may be absent from
  the file and cannot be recovered by sys-tty; this is part of the chosen
  best-effort logging contract. Strobe's one diagnostic is the only notice.
- **Kernel panic.** Unchanged: the kernel writes raw serial.
- **sys-tty exit.** Shutdown does not wait indefinitely for a blocked
  forwarder or claim that its queue was flushed. Process teardown drops the
  connection; any remaining file copies are best-effort.

### Console routing

In file mode, every record sys-tty receives goes to the file path and only
structurally classified WARN and ERROR records also go to the console through
arbitration. INFO, DEBUG, and unclassified/free-text records are file-only. In
console mode, or after file mode fails, every record goes to the console.

Classification looks only at the beginning of each framed record; it does not
search for level words further in. It accepts the exact structural prefixes of
the kernel's `{secs}:{millis} {cpu}: {LEVEL} {target}:{line} - {msg}` format
(`src/sys/kernel/src/xray/logger.rs:30-39`; the level is padded to six
characters) and the runtime's `{secs}:{millis}: {LEVEL} {file}:{line}: {msg}`
format (`rt.vdso/src/util/logging.rs:21-29`, `sys-io/src/logger.rs:19-27`;
the level is not padded). A record without one of those prefixes is
unclassified. Synthetic loss and file-failure notices generated by sys-tty
are explicitly WARN and therefore reach both sinks. Framing prevents a
newline-free record from being merged with the next formatted record.

### Configuration

`sys-tty.cfg` (`img_files/motor-os-base/system/cfg/sys-tty.cfg`, shared by
every shipped image; a per-test overlay such as `img_files/test-system-tty`
can replace it) becomes line-oriented, in the style of `sys-init.cfg`:

```
# Kernel log: console (the compatibility default) or strobe.
kernel-log:strobe
ENV=/system/cfg/rush.cfg /system/bin/rush -i
```

Each line is trimmed. Empty lines and lines whose first non-space byte is
`#` are ignored; comments are whole-line, as in sys-init. The only option is
`kernel-log:`, and it may appear only before the command. Duplicate options,
unknown keys, and bad values are errors. Exactly one remaining non-comment
line is required and is parsed in today's command form: leading `NAME=value`
words become the child's environment, followed by the program and arguments.
A legacy file containing only that command line means `kernel-log:console`.
The shipped base file explicitly says `kernel-log:strobe`; console-specific
tests use an overlay that explicitly says `kernel-log:console`.

### Debug builds: the write-back loop

File mode writes the kernel log through sys-io, and in a debug build the
write path logs, twice per flush of `kernel.log`:

- `std::fs::File::flush` is not a no-op on Motor OS: it calls
  `moto_rt::fs::flush`, the vdso turns that into an FS flush RPC
  (`src/sys/lib/rt.vdso/src/rt_fs.rs:959`), and motor-fs's flush handler
  records `Motor FS: flushing the Block Device.` at debug level on every
  flush (`src/sys/lib/motor-fs/src/txn_log.rs:251`);
- a write that no flush follows commits on the timeout path, which records
  `committing batch {txn_id} on timeout` at debug level (`txn_log.rs:189`).

Left alone, every flush of `kernel.log` produces a debug line, which becomes
the content of the next flush: the file never stops growing. Both lines are
demoted to trace ("FS txn writes to trace"). The other sources on the path
were checked: sys-io's FS server (`src/sys/sys-io/src/runtime/fs.rs`) logs
only on create, on a stat miss, and when it refuses a client; the vdso logs
only on open, so rotation costs a few lines; netstack's per-packet lines cause
no disk writes; sys-tty's and strobe's own diagnostics land in the kernel ring
(both run with null stdio, `sys-init/src/main.rs:88-96,140-142`) and so in the
same file, a handful of lines per boot. Quiescence -- an idle VM's
`kernel.log` stops growing -- is a test, not an assumption, so a future debug
line on the write path is caught.

### What does not change

- `docs/tui.md`: sys-tty removes or rewrites no application byte beyond the
  two UART translations it already applies, and takes no part in the size
  protocol. For application output, its scanner affects timing only. One
  sentence there will say so.
- Kernel log text formats, the per-record wake, the 256-byte `SysRay::log`
  cap, panic output, and nested-log fallback. Only the ring's shared byte
  layout changes.
- Roles and filesystem permissions: sys-tty stays Interactive and strobe
  remains the only writer of `/system/logs`. `CAP_LOG` retains its ordinary
  meaning; the existing `CAP_IO_MANAGER` distinguishes the reserved kernel
  stream.
- russhd: it has its own unrelated relay and is unchanged.

## Testing

No host-side behavioral test or assertion is added. Every new assertion runs
natively on Motor OS through systest, invoked by `src/tests/full-test.sh`.
For this feature, existing host scripts only boot the VM, invoke the native
test, and collect its result and diagnostics.

sys-tty stays one binary crate with one binary target. Before reading its
configuration or registering the UART, the binary recognizes an internal
`--self-test` argument. That mode exercises the production writer, scanner,
sanitizer, configuration-parser, routing, queue, and forwarder-state modules
against in-memory sources and sinks, then exits success or failure without
touching the console or strobe. Systest spawns that mode inside the guest. No
library target, second sys-tty target, or duplicate implementation is created.
The ring helpers remain in `moto-sys`, which systest already links.

Framed ring:

- systest checks of the `moto-sys` helpers cover the fixed 8-byte header,
  zero-length and newline-free payloads, the exact 65,528-byte maximum and an
  oversize rejection, a record crossing the physical end decoded from a linear
  copy, control-block alignment, odd/even generations, wrong magic/length,
  wrapping sequence arithmetic, and complete-record decoding;
- deterministic systest snapshot checks use a simulated producer (the
  `moto-sys` encoder writing a test ring and control block) before, during,
  and after a two-piece copy. Both the ordinary and lapped paths exercise the
  common second-sample fence. The drain helper must return either a validated
  whole-record snapshot or nothing, and a sequence gap must give the exact loss
  count;
- native `systest log-flood` remains an end-to-end stress check: sys-tty stays
  alive, every surviving record in the file is whole, and an overwrite-loss
  marker appears. Exact lap arithmetic is tested deterministically rather than
  inferred from flood scheduling.

Console arbitration:

- `sys-tty --self-test` has table-driven cases for ESC intermediates, CSI,
  OSC, DCS, SOS, APC, PM, BEL/ST split across chunks, malformed sequences,
  UTF-8 split across chunks, stdout/stderr ownership, the 30 ms quiet window,
  500 ms/16 KB hold bounds, the 100 ms `CAN` deadline, and bounded queue
  markers;
- native integration cases feed interleaved stdout, stderr, and log chunks
  through the production writer policy and inspect its in-memory output. No
  log or opposite-relay byte may occur inside a complete application ANSI
  sequence; the deadline case must contain `CAN` before the waiting chunk;
- sanitizer cases cover every `ESC` position and all 32 UTF-8 C1 controls.
  The console copy contains the exact diagnostic literal and no unsafe control
  introducer, while the file copy remains byte-for-byte identical.

File mode, using the shipped `kernel-log:strobe` configuration:

- native systest emits ERROR, WARN, INFO, DEBUG, unclassified, newline-free,
  and multi-line records and reads them byte-for-byte from
  `/system/logs/kernel.log` as an Interactive process;
- the native sys-tty routing test proves WARN and ERROR select both sinks while
  INFO, DEBUG, and unclassified/free-text records select only the file sink;
- an unsafe WARN record reaches the file unchanged, while the native
  console-sink test sees every `ESC` and UTF-8 C1 control replaced;
- an ordinary `CAP_LOG` client cannot claim `kernel` or send
  `CMD_LOG_RAW`; sys-tty's successful end-to-end write proves its
  `CAP_IO_MANAGER | CAP_LOG` connection can;
- rotation: native `systest log-flood` in file mode pushes `kernel.log` past
  4 MB and leaves `kernel.log.prev` plus a bounded `kernel.log`; systest
  floods its own tag past 4 MB and sees the same for an ordinary tag;
  reconnecting an ordinary tag still replaces its `.prev`;
- disk-space rule: a focused native systest fills the data partition with one
  temporary file until `fs.available_bytes` is below 50 MB, floods its own
  tag past 4 MB, checks that the oldest `.prev` is gone, and removes the
  temporary file before returning;
- quiescence: after five idle seconds the file size is unchanged in debug and
  release builds;
- absent strobe: an overlay whose `sys-init.cfg` has no `strobe:` line and
  whose `sys-tty.cfg` says `kernel-log:strobe` boots to a working
  console-mode session with no retry;
- native sys-tty self-tests cover forwarder backlog drops and recovery marker,
  disconnect/reject and no-retry transitions, non-blocking teardown, and every
  configuration-parser success and error path.

Boot latency also has no host assertion. The first raw kernel-log preamble
records the boot-relative timestamp captured at the same truthful
`all services up ... Starting <command>` milestone. Before log flooding or
rotation, native systest reads that value from `kernel.log` and checks it
against the pre-change debug or release baseline envelope recorded for the
implementation series. A measurable regression stops implementation for
review. Temporary timing diagnostics are removed before completion; the
existing status message remains at the truthful milestone.

For every implementation patch touching `src/sys`, the required gate remains
the complete main-image `full-test.sh` three consecutive times in debug and
three in release, plus `src/tests/full-test-dev.sh --release`. Those scripts
orchestrate the VM but add no feature-specific host assertion. Relevant native
focused tests run first; `cargo fmt` and clippy must add no warning. Regular
tests use no new Internet resource.

## Chosen defaults

- The shipped base image uses `kernel-log:strobe`. A legacy config with no
  option remains console mode for compatibility and focused console tests use
  an explicit `kernel-log:console` overlay.
- In file mode every received kernel record goes to the file, byte-for-byte.
  Only WARN and ERROR records also go to the console. If file mode is absent or
  fails, all later records go to the console.
- The fixed file name is `kernel.log`.
- Rotation: 4 MB per file and one `.prev` generation per tag, on reconnect
  and on size; below 50 MB of free space the oldest `.prev` of any tag is
  deleted. More generations can be added later if history is wanted. The
  separate 64 KB kernel-to-sys-tty memory ring does overwrite old unread
  records when it wraps.

## Plan

Each implementation step is a reviewable patch, normally 100–300 lines
including tests. The ABI producer/consumer switch may need one larger atomic
patch so no build uses mismatched framing. Whether patches are committed is
decided with the user before implementation; this planning edit creates no
commit.

1. **Shared framing and guest tests.** Add the fixed 8-byte layout, the
   control block, the encoder/decoder, and the sequence-gap and snapshot
   helpers to `moto-sys`, and the systest checks listed above. sys-tty gains
   no library target. No producer changes yet.
2. **Atomic overwrite ring switch.** Make the kernel write framed records,
   overwrite on wrap, and publish the `generation`/`end` pair with the
   producer release fence and atomic stores described above; make sys-tty use
   the common second-sample fence for ordinary and lapped snapshots, split
   whole records, and mark sequence gaps. Add the native end-to-end log flood.
3. **Console policy, scanner, and native self-test.** Add the bounded writer
   policy, framing scanner, two source queues, and console-only `ESC` and C1
   sanitization as modules in the sys-tty binary. Add the early `--self-test`
   path and its native cases for quiet/hold bounds, cross-relay ownership,
   incomplete UTF-8, sanitization, and 100 ms forced cancellation.
4. **Console integration and startup milestone.** Give TX to the writer,
   enlarge relay reads, separate RX from the TX lock, fix EOF loops, and route
   sys-tty status output through the writer. Move the existing `all services
   up ... Starting <command>` message to the defined initialization boundary,
   add the native in-memory integration cases, and record and check the same
   milestone natively for boot latency. Remove any temporary timing messages.
5. **FS trace level.** Demote `motor-fs/src/txn_log.rs:189` and `:251` from
   debug to trace so file-mode logging reaches quiescence; retain the explicit
   debug/release quiescence test.
6. **Reserved raw strobe operation.** Add `CMD_LOG_RAW`, reserve `kernel` for
   `CAP_IO_MANAGER | CAP_LOG`, write payloads byte-for-byte, preserve today's
   reconnect `.prev` rotation and ordinary-record flush semantics, raise
   strobe's `max_connections` from 10 to 11, and add the systest authorization
   check and the I/O-failure state.
7. **Strobe rotation and disk-space rule.** Add the 4 MB rotation for every
   tag and the `.prev` deletion below 50 MB of available space, read through
   `moto_stats::Collector` as `df` does, with the rotation and disk-space tests
   above.
8. **sys-tty configuration.** Add the line-oriented parser and its native
   self-test cases. Preserve command-only input as console mode; make the
   shipped base config explicitly `kernel-log:strobe`. There is no
   console-level option.
9. **File forwarder.** Add asynchronous startup, the bounded drop-and-count
   queue, fixed WARN/ERROR console classification, and no-retry failure
   transitions, with native self-test coverage plus the quiescence test and
   absent-strobe overlay. Launching it must not delay the console child.
10. **Diagnostics and documentation.** The existing host runner may fetch
    `kernel.log{,.prev}` on failure as diagnostics only; it adds no behavioral
    assertion. Update `docs/tools.md`, `docs/process-roles.md`,
    `docs/fs-permissions.md`, `docs/tui.md`, and
    `docs/plans/future-work.md`. Once implemented, move this document to
    `docs/kernel-logs.md`, remove this Plan section, and refresh source
    references.
