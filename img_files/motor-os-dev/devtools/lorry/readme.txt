Lorry data on the developer image

Each role has its own Lorry state: user/ for Interactive and none/ for None.
In each, `lorry vendor` stores fetched dependencies under vendor/, and
compiled dependency units are stored under cache/. The developer image ships
these directories without dependency data.
