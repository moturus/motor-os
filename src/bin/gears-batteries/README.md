# Gears batteries

Optional coding workflows for Gears, implemented by the
[Gears batteries plan](../gears/plans/gears-batteries.md). Install the binary
beside `gears`; the Motor OS developer image installs both in `/devtools/bin`.
The hook currently validates version 1 events and refuses tool permission
requests. Project instructions and coding tools are added in subsequent
patches; it is not enabled by the installed Gears configuration yet.

Run `src/tests/test-gears-batteries.sh` from the Motor OS repository root for
the hermetic host gate. The release developer-image gate exercises the
installed binary and rebuilds the packaged source with Lorry.
