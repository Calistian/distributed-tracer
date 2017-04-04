obj-m += distributed-tracer.o
distributed-tracer-objs += dt.o
distributed-tracer-objs += dt_probe.o
distributed-tracer-objs += dt_proc.o
distributed-tracer-objs += dt_sysfs.o
distributed-tracer-objs += dt_trace.o

LKMMAKE = $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)

all:
	$(LKMMAKE) modules

install: all
	$(LKMMAKE) modules_install

clean:
	$(LKMMAKE) clean