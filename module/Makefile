obj-m += distributed-tracer.o
distributed-tracer-objs += dt.o
distributed-tracer-objs += dt_pid.o
distributed-tracer-objs += dt_probe.o
distributed-tracer-objs += dt_sysfs.o

LKMMAKE = $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)

all:
	$(LKMMAKE) modules

install: all
	$(LKMMAKE) modules_install

clean:
	$(LKMMAKE) clean