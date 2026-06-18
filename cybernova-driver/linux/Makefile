# CyberNova LSM Kernel Module Makefile
# Build: make -C /lib/modules/$(uname -r)/build M=$(PWD) modules
# Clean: make -C /lib/modules/$(uname -r)/build M=$(PWD) clean
#
# Prerequisites:
#   apt-get install linux-headers-$(uname -r) build-essential

obj-m += cybernova_lsm.o

cybernova_lsm-objs := cybernova_lsm.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod cybernova_lsm.ko
	@echo "CyberNova LSM loaded. Check dmesg for status."
	@echo "Mount securityfs: sudo mount -t securityfs securityfs /sys/kernel/security"
	@echo "View stats: cat /sys/kernel/security/cybernova/stats"

uninstall:
	sudo rmmod cybernova_lsm
	@echo "CyberNova LSM unloaded."

load-test:
	@echo "Adding test blocklist entries..."
	@echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 99 Test hash" | sudo tee /sys/kernel/security/cybernova/blocklist
	@echo "Blocklist updated."

.PHONY: all clean install uninstall load-test
