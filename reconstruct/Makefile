# Reconstruction from RosettaLinux decompilation
# The earlier rewrite is archived in ../legacy/translator.

CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -O2 -g
CFLAGS  += -Iinclude
# Cache identity must change whenever the translator inputs change, not
# only when HEAD moves: hash HEAD + uncommitted diffs + file status +
# compiler/flags so stale .oahjc files are invalidated. The value is
# generated into src/build_key.c so every object shares ONE key — a
# per-TU -D would let incremental builds mix keys and poison the cache.
BUILD_KEY := $(shell { git rev-parse HEAD 2>/dev/null; \
                       git diff HEAD -- src include Makefile 2>/dev/null; \
                       git status --porcelain src include Makefile 2>/dev/null; \
                       $(CC) --version 2>/dev/null | head -1; \
                       echo "$(CFLAGS)"; } | cksum | cut -d' ' -f1)
HOST_OS := $(shell uname -s)
ifeq ($(HOST_OS),Darwin)
CFLAGS  += -D_DARWIN_C_SOURCE
HOST_LDFLAGS = -framework AudioToolbox
else
CFLAGS  += -D_GNU_SOURCE
HOST_LDFLAGS = -pie
endif

SRC = \
    src/build_key.c \
    src/register.c \
    src/result.c \
    src/assembler_buffer.c \
    src/assembler.c \
    src/flags.c \
    src/linux_abi.c \
    src/decoder.c \
    src/condition.c \
    src/icache.c \
    src/bitmask_imm.c \
    src/host_syscall.c \
    src/guest.c \
    src/elf_map.c \
    src/decode_insn.c \
    src/interp.c \
    src/guest_signal.c

EXEC_SRC = \
    src/runtime_syscall.c \
    src/translate.c \
    src/arm_exec.c \
    src/arm_native.c \
    src/jit.c

LINUX_SRC = $(SRC) $(EXEC_SRC) src/syscall_bridge.c

ifeq ($(HOST_OS),Darwin)
HOST_SRC = $(SRC) $(EXEC_SRC) src/syscall_darwin.c src/dsp_darwin.c src/alsa_darwin.c
else
HOST_SRC = $(LINUX_SRC)
endif
OBJ = $(HOST_SRC:.c=.o)

TESTS = \
    tests/test_register \
    tests/test_assembler \
    tests/test_flags \
    tests/test_linux_abi \
    tests/test_decoder \
    tests/test_syscalls \
    tests/test_binary \
    tests/test_decode_insn \
    tests/test_interp \
    tests/test_elf_map \
    tests/test_translate \
    tests/test_arm_native

CC_X86_64      ?= x86_64-linux-gnu-gcc

# Debian guest fixtures ship in the app's runtime tree; auto-detect so
# test-macos exercises the glibc and Python paths whenever they exist.
DEBIAN_SYSROOT        ?= $(wildcard ../runtime/sysroots/debian-expanded)
DEBIAN_PYTHON_SYSROOT ?= $(wildcard ../runtime/sysroots/debian-python)
CC_AARCH64     ?= aarch64-linux-gnu-gcc
QEMU_X86_64    ?= qemu-x86_64
QEMU_AARCH64   ?= qemu-aarch64-static
# Keep oah's load address far from a typical ET_EXEC guest at 0x400000.
AARCH64_LDFLAGS ?= -static -Wl,-Ttext-segment=0x2000000000

.PHONY: all test test-unit test-macos test-macos-gate test-branch-guest test-linux-static test-linux-dynamic test-linux-glibc test-qemu clean inventory inventory-binary oah oah-aarch64

all: $(OBJ) oah

src/build_key.c: FORCE
	@printf 'unsigned oah_build_key(void){return %uu;}\n' '$(BUILD_KEY)' >$@.tmp; \
	 cmp -s $@.tmp $@ || mv $@.tmp $@; rm -f $@.tmp

FORCE:

src/%.o: src/%.c
	$(CC) $(CFLAGS) -fPIE -MMD -MP -c -o $@ $<

tests/%: tests/%.c $(OBJ)
	$(CC) $(CFLAGS) -fPIE $(HOST_LDFLAGS) -o $@ $< $(OBJ) -lm

oah: src/oah_main.o $(OBJ)
	$(CC) $(CFLAGS) -fPIE $(HOST_LDFLAGS) -o $@ src/oah_main.o $(OBJ) -lm

oah-aarch64: src/oah_main.c $(LINUX_SRC)
	$(CC_AARCH64) $(CFLAGS) -D_GNU_SOURCE $(AARCH64_LDFLAGS) -o $@ src/oah_main.c $(LINUX_SRC) -lm

tests/test_arm_native-aarch64: tests/test_arm_native.c $(LINUX_SRC)
	$(CC_AARCH64) $(CFLAGS) -D_GNU_SOURCE $(AARCH64_LDFLAGS) -o $@ tests/test_arm_native.c $(LINUX_SRC)

tests/hello.x86_64: tools/mk_hello_elf.py
	python3 tools/mk_hello_elf.py $@

tests/sse_guest.x86_64: tools/mk_sse_elf.py
	python3 tools/mk_sse_elf.py $@

tests/thread_guest.x86_64: tools/mk_thread_elf.py
	python3 tools/mk_thread_elf.py $@

tests/fault_store_guest.x86_64: tools/mk_fault_store_elf.py
	python3 tools/mk_fault_store_elf.py $@

tests/exec_guard_guest.x86_64: tools/mk_exec_guard_elf.py
	python3 tools/mk_exec_guard_elf.py $@

tests/flag_live_guest.x86_64: tools/mk_flag_live_elf.py
	python3 tools/mk_flag_live_elf.py $@

tests/smc_chain_guest.x86_64: tools/mk_smc_chain_elf.py
	python3 tools/mk_smc_chain_elf.py $@

tests/vec_align_guest.x86_64: tools/mk_vec_align_elf.py
	python3 tools/mk_vec_align_elf.py $@

tests/fault_state_guest.x86_64: tools/mk_fault_state_elf.py
	python3 tools/mk_fault_state_elf.py $@

tests/diff_guest.x86_64: tools/mk_diff_elf.py
	python3 tools/mk_diff_elf.py $@

test-unit: $(TESTS)
	@fail=0; \
	for t in $(TESTS); do \
	    echo "== $$t"; \
	    ./$$t || fail=1; \
	done; \
	exit $$fail

ifeq ($(HOST_OS),Darwin)
test: test-unit test-macos
else
test: test-unit oah tests/hello.x86_64
	@fail=0; \
	echo "== oah tests/hello.x86_64"; \
	./oah tests/hello.x86_64 > tests/hello.got || fail=1; \
	printf 'hello\n' | cmp -s - tests/hello.got || { echo "  FAIL hello output"; fail=1; }; \
	exit $$fail

endif

test-macos: oah tests/hello.x86_64 tests/sse_guest.x86_64 tests/thread_guest.x86_64 tests/fault_store_guest.x86_64 tests/fault_state_guest.x86_64 tests/exec_guard_guest.x86_64 tests/flag_live_guest.x86_64 tests/smc_chain_guest.x86_64 tests/vec_align_guest.x86_64 tests/diff_guest.x86_64 tests/test_elf_map
	@test "$(HOST_OS)" = Darwin || { echo "test-macos requires macOS"; exit 1; }
	./tests/test_elf_map
	python3 tools/test_macos.py --runner ./oah --hello tests/hello.x86_64 \
	    --sse tests/sse_guest.x86_64 \
	    --thread tests/thread_guest.x86_64 \
	    --fault-store tests/fault_store_guest.x86_64 \
	    --fault-state tests/fault_state_guest.x86_64 \
	    --diff tests/diff_guest.x86_64 \
	    --exec-guard tests/exec_guard_guest.x86_64 \
	    --flag-live tests/flag_live_guest.x86_64 \
    --smc-chain tests/smc_chain_guest.x86_64 \
	    --vec-align tests/vec_align_guest.x86_64 \
	    $(if $(BUSYBOX_STATIC),--busybox "$(BUSYBOX_STATIC)") \
	    $(if $(ALPINE_SYSROOT),--alpine-sysroot "$(ALPINE_SYSROOT)") \
	    $(if $(DEBIAN_SYSROOT),--debian-sysroot "$(DEBIAN_SYSROOT)") \
	    $(if $(DEBIAN_PYTHON_SYSROOT),--debian-python-sysroot "$(DEBIAN_PYTHON_SYSROOT)") \
	    $(REQUIRE_FIXTURES)

# test-macos-gate is the release check: it requires the pinned Debian
# sysroots to be provisioned and fails if they are missing.
test-macos-gate: REQUIRE_FIXTURES=--require-fixtures
test-macos-gate: test-macos



tests/branch_guest.x86_64: tests/branch_guest.c
	$(CC_X86_64) -O2 -nostdlib -static -no-pie -fno-stack-protector -fno-pie \
	    -fno-if-conversion -fno-if-conversion2 -masm=att -o $@ $<

tests/branch_guest-pie.x86_64: tests/branch_guest.c
	$(CC_X86_64) -O2 -nostdlib -static-pie -fPIE -fno-stack-protector \
	    -fno-if-conversion -fno-if-conversion2 -o $@ $<

test-branch-guest: oah tests/branch_guest.x86_64 tests/branch_guest-pie.x86_64
	@set -e; for guest in tests/branch_guest.x86_64 tests/branch_guest-pie.x86_64; do \
	    status=0; ./oah $$guest > tests/branch_guest.got || status=$$?; \
	    test "$$status" -eq 7; printf 'branch ok\nbranch no\n' | cmp - tests/branch_guest.got; \
	done

test-linux-static: oah
	@test -n "$(BUSYBOX_STATIC)" || { echo "Set BUSYBOX_STATIC to the pinned BusyBox ELF"; exit 1; }
	python3 tools/test_linux_static.py --runner ./oah --busybox "$(BUSYBOX_STATIC)" --qemu "$(QEMU_X86_64)"

test-linux-dynamic: oah
	@test -n "$(ALPINE_SYSROOT)" || { echo "Set ALPINE_SYSROOT to the pinned Alpine x86-64 root"; exit 1; }
	python3 tools/test_linux_static.py --runner ./oah --busybox "$(ALPINE_SYSROOT)/bin/busybox" \
	    --sysroot "$(ALPINE_SYSROOT)" --qemu "$(QEMU_X86_64)" --cc "$(CC_X86_64)"

test-linux-glibc: oah
	@test -n "$(DEBIAN_SYSROOT)" || { echo "Set DEBIAN_SYSROOT to the pinned Debian x86-64 root"; exit 1; }
	python3 tools/test_linux_glibc.py --runner ./oah --sysroot "$(DEBIAN_SYSROOT)" \
	    --qemu "$(QEMU_X86_64)" --cc "$(CC_X86_64)"

test-qemu: oah-aarch64 tests/test_arm_native-aarch64 tests/hello.x86_64
	@command -v $(CC_AARCH64) >/dev/null || { echo "need $(CC_AARCH64)"; exit 1; }
	@command -v $(QEMU_AARCH64) >/dev/null || { echo "need $(QEMU_AARCH64)"; exit 1; }
	@echo "== qemu $(QEMU_AARCH64) tests/test_arm_native-aarch64"; \
	$(QEMU_AARCH64) ./tests/test_arm_native-aarch64
	@echo "== qemu $(QEMU_AARCH64) oah-aarch64 tests/hello.x86_64"; \
	$(QEMU_AARCH64) ./oah-aarch64 tests/hello.x86_64 > tests/hello.qemu.got || exit 1; \
	printf 'hello\n' | cmp -s - tests/hello.qemu.got || { \
	    echo "  FAIL qemu hello output"; cat tests/hello.qemu.got; exit 1; }

inventory:
	python3 tools/extract_decomp_map.py ../research/decompilation/rosetta_decomp.c -o inventory

inventory-binary:
	@test -f bin/rosetta || { echo "drop the ELF at reconstruct/bin/rosetta"; exit 1; }
	python3 tools/extract_from_binary.py bin/rosetta -o inventory/from_binary \
	    --inc src/host_syscall_table.inc

-include $(OBJ:.o=.d) src/oah_main.d

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) src/oah_main.o src/oah_main.d src/build_key.c $(TESTS) oah oah-aarch64 \
	    tests/test_arm_native-aarch64 tests/hello.x86_64 tests/hello.got \
	    tests/branch_guest.x86_64 tests/branch_guest-pie.x86_64 tests/branch_guest.got \
	    tests/hello.qemu.got
