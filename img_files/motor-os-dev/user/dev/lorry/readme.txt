Lorry data on the developer image

Each role has its own Lorry state: /user/dev/lorry for Interactive and
/none/dev/lorry for None. None may read the Interactive repository and cache.
In each, `lorry vendor` stores fetched dependencies under vendor/, and
compiled dependency units are stored under cache/. The developer image ships
/user/dev/lorry with the dependencies of the Motor OS library sources in
/none/dev/motor-os/sys/lib, vendored and compiled, so `lorry test` there
runs offline. Other projects run `lorry vendor` first.
