# distributed-tracer scripts
This folder contains the test scripts.

## server
This script starts the server, which returns the uppercase of any sent string. It also starts LTTng and distributed-tracer.
- `port` is the port to listen on.
```
./server <port>
```

## middle
This script starts a middle client/server, that simply transmit back and forth whatever the client and the server sends. It also starts LTTng and distributed-tracer.
- `port` is the port to lisent to
- `server address` is the address of the server to connect to
- `server port` is the port of the server to connect to
```
./middle <port> <server address> <server port>
```

## start_for_client
This scripts starts distributed-tracer for the client, but does not start the client itself. It simply adds the client's PID to the watch list of distributed-tracer.
To use this script, you must first start the client manually, using `python3 ./echo/client/client.py <server address> <server port>`. Whatever you write in the console will be sent to the server.

# How to run
To run the test, you **should** (must) run the scripts on different computers/VM that can talk to eachother using TCP.

Also, you need to install distributed-tracer and a special version of lttng-modules (https://github.com/charpercyr/lttng-modules).

Once that is done, simply run the server, then any number of middle, then the client, the run `./start_for_client` and you're all set.
