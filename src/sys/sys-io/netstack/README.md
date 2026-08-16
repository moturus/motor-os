Moto-netstack is the Motor OS networking stack, owned by sys-io.

It grew out of [smoltcp](https://github.com/smoltcp-rs/smoltcp) and keeps its
layered structure and 0BSD license, but it has diverged far enough --
congestion control, SACK/RACK-TLP loss recovery, RFC 7323 timestamps,
admission and safety hardening, Motor-specific integration -- that it is no
longer a fork tracking upstream. Upstream fixes are references to port by
hand, not patches to merge.
