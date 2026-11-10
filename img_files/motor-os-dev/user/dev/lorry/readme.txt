Lorry data on the developer image

Each role has its own Lorry state: user/ for Interactive and none/ for None.
In each, `lorry vendor` stores fetched dependencies under vendor/, and
compiled dependency units are stored under cache/. The developer image ships
user/ with the dependencies of the Motor OS library sources in
/devtools/src/motor-os/sys/lib, vendored and compiled, so `lorry test` there
runs offline. Other projects run `lorry vendor` first.
