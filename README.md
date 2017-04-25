# distributed-tracer
This project is a prototype for tracing a distributed system without any change in user code.

# Installing
To install this module, do
```
git clone https://github.com/charpercyr/distributed-tracer.git
cd distributed-tracer/module
make
sudo make install
sudo depmod -a
```

# What does it do ?
This project is a kernel module that will set and unset a tracing flag in the kernel (see [Kernel Interface](#kernel-interface) depending if we should trace or not. Another module can then poll this flag to enable/disable the trace.

There are two conditions that can activate tracing, only one of them has to be met.
- The PID of the thread that is sending data is enabled by the user (see [User Interface](#user-interface)).
- The thread has received a marked packet. The tracing is activated until it sends a response on the same socket.

## Marked Packets
If a thread is flagged for tracing, any TCP packet it sends will be marked. If a thread (on a machine that runs distributed-tracer) receives a marked packet, tracing will be activated until a response, and any packet sent will also be marked. That way, the user only has to manually enable the client thread and the tracing will propagate in the distributed system.

The marking is done by setting the first Reserved bit in the TCP header. Routers may ask for retransmission, in that case, the packet will be resent, unmarked, and the tracing will not be activated. The same thing happens if the packet arrives at a Linux that does not have distributed-tracer loaded.

# Interface

## User Interface
To control this module, it exposes a set of sysfs files, under the `/sys/distributed-tracer` directory.
- `add_pid` : This write-only file is used to add a PID to the enabled threads. This is the file that is used to manually set the traced threads.
- `remove_pid` : This write-only file removes a PID from the enabled threads.
- `list_pid` : This read-only file lists all the currently flagged PIDs, manually or automatically.
- `probe` : This read-write file is used to activate/deactivate the module. Write 1 to activate, 0 to deactivate. Reading it will return the current status.
- `trace` : This read-only file will return the status of the tracing. 1 is activated, 0 is not.

## Kernel Interface
The module exposes a boolean variable named `dt_trace_active` of type `atomic_t`. It is set when the tracing is supposed to be active.

Right now, there is only one project that uses this variable, it is https://github.com/charpercyr/lttng-modules, a fork of lttng-modules that takes the boolean variable into account when tracing the kernel.
