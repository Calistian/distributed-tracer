obj-m += distributed-tracer.o

LKMMAKE = $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)

all:
	$(LKMMAKE) modules

install: all
	$(LKMMAKE) modules_install

clean:
	$(LKMMAKE) clean