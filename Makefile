.DEFAULT_GOAL := all

.PHONY: all test test-macos test-branch-guest test-qemu test-linux-static test-linux-dynamic test-linux-glibc inventory inventory-binary clean

all test test-macos test-branch-guest test-qemu test-linux-static test-linux-dynamic test-linux-glibc inventory inventory-binary clean:
	$(MAKE) -C reconstruct $@
