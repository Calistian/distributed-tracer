
all:
	$(MAKE) -C module all

install:
	$(MAKE) -C module install
	$(MAKE) -C daemon install

clean:
	$(MAKE) -C module clean