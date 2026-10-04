# Gears batteries

Optional coding workflows for Gears, implemented by the
[Gears batteries plan](../gears/plans/gears-batteries.md). Install the binary
beside `gears`; the Motor OS developer image installs both in `/devtools/bin`.
The hook reads `AGENTS.md` (or `.gears.md`) only at the selected workspace
root. Instructions are limited to 20,000 characters; oversized files retain
their beginning and end. Prompt fragments are saved by content hash and
reused on resume, fork, provider changes and other setup, until compaction
or a new session takes a fresh snapshot. A failed optional setup is reported
and leaves the previous hook state unchanged.

Tool permission requests are still refused. Coding tools are added in
subsequent patches; the installed Gears configuration does not enable the
batteries hook yet.

Run `src/tests/test-gears-batteries.sh` from the Motor OS repository root for
the hermetic host gate. The release developer-image gate exercises the
installed binary and rebuilds the packaged source with Lorry.
