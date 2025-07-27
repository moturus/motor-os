# Motor OS.

BUILD ?= debug

ifeq ($(BUILD), release)
	CARGO_RELEASE := --release
	BIN_DIR := $(CURDIR)/build/bin/release
	OBJ_DIR := $(CURDIR)/build/obj/release
	SUB_DIR := x86_64-unknown-moturus/release
	IMG_CMD := release
else
	CARGO_RELEASE :=
	BIN_DIR := $(CURDIR)/build/bin/debug
	OBJ_DIR := $(CURDIR)/build/obj
	SUB_DIR := x86_64-unknown-moturus/debug
	IMG_CMD := debug
endif

ROOT_DIR := $(CURDIR)

DO_BUILD = cargo +dev-x86_64-unknown-moturus build --target x86_64-unknown-moturus $(CARGO_RELEASE)

DO_CLIPPY = cargo +dev-x86_64-unknown-moturus clippy --target x86_64-unknown-moturus $(CARGO_RELEASE)

all: boot core sys user img
boot: mbr.bin boot.bin kloader
core: kernel vdso
sys: sys-io sys-init sys-log sys-tty
user: sysbox systest mio-test tokio-tests \
	rush russhd httpd httpd-axum kibim \
	mdbg rnetbench crossbench

.PHONY: all boot core sys user img
.PHONY: mbr.bin boot.bin kloader kernel vdso
.PHONY: sys-io sys-init sys-log sys-tty
.PHONY: sysbox systest mio-test tokio-tests
.PHONY: rush russhd httpd httpd-axum kibim
.PHONY: mdbg rnetbench crossbench
.PHONY: clean clippy

mbr.bin:
	mkdir -p $(BIN_DIR)
	cd src/boot/x64.mbr && \
		MOTO_BIN="$(BIN_DIR)" CARGO_TARGET_DIR="$(OBJ_DIR)/mbr" \
		./build.sh

boot.bin:
	mkdir -p $(BIN_DIR)
	cd src/boot/x64.boot && \
		MOTO_BIN="$(BIN_DIR)" CARGO_TARGET_DIR="$(OBJ_DIR)/boot" \
		./build.sh

kloader:
	mkdir -p $(BIN_DIR)
	cd src/boot/x64.kloader && \
	MOTO_BIN="$(BIN_DIR)" CARGO_TARGET_DIR="$(OBJ_DIR)/kloader" \
	./build.sh $(CARGO_RELEASE)

kernel:
	mkdir -p $(BIN_DIR)
	cd src/sys/kernel && \
		MOTO_BIN="$(BIN_DIR)" CARGO_TARGET_DIR="$(OBJ_DIR)/kernel" \
		./build.sh $(CARGO_RELEASE)

vdso:
	mkdir -p $(BIN_DIR)
	cd src/sys/lib/rt.vdso && \
		MOTO_BIN="$(BIN_DIR)" CARGO_TARGET_DIR="$(OBJ_DIR)/vdso" \
		./build.sh $(CARGO_RELEASE)

sys-io: vdso
	mkdir -p $(BIN_DIR)
	cd src/sys/sys-io && CARGO_TARGET_DIR="$(OBJ_DIR)/sys-io" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sys-io" "$(OBJ_DIR)/sys-io/$(SUB_DIR)/sys-io"

sys-init:
	mkdir -p $(BIN_DIR)
	cd src/sys/sys-init && CARGO_TARGET_DIR="$(OBJ_DIR)/sys-init" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sys-init" "$(OBJ_DIR)/sys-init/$(SUB_DIR)/sys-init"

sys-log:
	mkdir -p $(BIN_DIR)
	cd src/sys/sys-log && CARGO_TARGET_DIR="$(OBJ_DIR)/sys-log" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sys-log" "$(OBJ_DIR)/sys-log/$(SUB_DIR)/sys-log"

sys-tty:
	mkdir -p $(BIN_DIR)
	cd src/sys/sys-tty && CARGO_TARGET_DIR="$(OBJ_DIR)/sys-tty" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sys-tty" "$(OBJ_DIR)/sys-tty/$(SUB_DIR)/sys-tty"

sysbox:
	mkdir -p $(BIN_DIR)
	cd src/sys/tools/sysbox && CARGO_TARGET_DIR="$(OBJ_DIR)/sysbox" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sysbox" "$(OBJ_DIR)/sysbox/$(SUB_DIR)/sysbox"

mdbg:
	mkdir -p $(BIN_DIR)
	cd src/sys/tools/mdbg && CARGO_TARGET_DIR="$(OBJ_DIR)/mdbg" $(DO_BUILD)
	strip -o "$(BIN_DIR)/mdbg" "$(OBJ_DIR)/mdbg/$(SUB_DIR)/mdbg"

systest:
	mkdir -p $(BIN_DIR)
	cd src/sys/tests/systest && CARGO_TARGET_DIR="$(OBJ_DIR)/systest" $(DO_BUILD)
	strip -o "$(BIN_DIR)/systest" "$(OBJ_DIR)/systest/$(SUB_DIR)/systest"

crossbench:
	mkdir -p $(BIN_DIR)
	cd src/sys/tests/crossbench && CARGO_TARGET_DIR="$(OBJ_DIR)/crossbench" $(DO_BUILD)
	strip -o "$(BIN_DIR)/crossbench" "$(OBJ_DIR)/crossbench/$(SUB_DIR)/crossbench"

mio-test:
	mkdir -p $(BIN_DIR)
	cd src/sys/tests/mio-test && CARGO_TARGET_DIR="$(OBJ_DIR)/mio-test" $(DO_BUILD)
	strip -o "$(BIN_DIR)/mio-test" "$(OBJ_DIR)/mio-test/$(SUB_DIR)/mio-test"

tokio-tests:
	mkdir -p $(BIN_DIR)
	cd src/sys/tests/tokio-tests && CARGO_TARGET_DIR="$(OBJ_DIR)/tokio-tests" $(DO_BUILD)
	strip -o "$(BIN_DIR)/tokio-tests" "$(OBJ_DIR)/tokio-tests/$(SUB_DIR)/tokio-tests"

rush:
	mkdir -p $(BIN_DIR)
	cd src/bin/rush && CARGO_TARGET_DIR="$(OBJ_DIR)/rush" $(DO_BUILD)
	strip -o "$(BIN_DIR)/rush" "$(OBJ_DIR)/rush/$(SUB_DIR)/rush"

russhd:
	mkdir -p $(BIN_DIR)
	cd src/bin/russhd && CARGO_TARGET_DIR="$(OBJ_DIR)/russhd" $(DO_BUILD)
	strip -o "$(BIN_DIR)/russhd" "$(OBJ_DIR)/russhd/$(SUB_DIR)/russhd"

httpd:
	mkdir -p $(BIN_DIR)
	cd src/bin/httpd && CARGO_TARGET_DIR="$(OBJ_DIR)/httpd" $(DO_BUILD)
	strip -o "$(BIN_DIR)/httpd" "$(OBJ_DIR)/httpd/$(SUB_DIR)/httpd"

httpd-axum:
	mkdir -p $(BIN_DIR)
	cd src/bin/httpd-axum && CARGO_TARGET_DIR="$(OBJ_DIR)/httpd-axum" $(DO_BUILD)
	strip -o "$(BIN_DIR)/httpd-axum" "$(OBJ_DIR)/httpd-axum/$(SUB_DIR)/httpd-axum"

kibim:
	mkdir -p $(BIN_DIR)
	cd src/bin/kibim && CARGO_TARGET_DIR="$(OBJ_DIR)/kibim" $(DO_BUILD)
	strip -o "$(BIN_DIR)/kibim" "$(OBJ_DIR)/kibim/$(SUB_DIR)/kibim"

rnetbench:
	mkdir -p $(BIN_DIR)
	cd src/bin/rnetbench && CARGO_TARGET_DIR="$(OBJ_DIR)/rnetbench" $(DO_BUILD)
	strip -o "$(BIN_DIR)/rnetbench" "$(OBJ_DIR)/rnetbench/$(SUB_DIR)/rnetbench"

img: boot core sys user
	cd src/imager && \
		cargo run $(CARGO_RELEASE) -- "$(ROOT_DIR)" $(IMG_CMD)
	cp "$(ROOT_DIR)/src/vm_scripts/"* \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/"
	@echo "built Motor OS image in $(ROOT_DIR)/vm_images/$(IMG_CMD)"

clippy: vdso
	cd src/sys/sys-io && $(DO_CLIPPY)
	cd src/sys/sys-init && $(DO_CLIPPY)
	cd src/sys/sys-log && $(DO_CLIPPY)
	cd src/sys/sys-tty && $(DO_CLIPPY)
	cd src/sys/tools/sysbox && $(DO_CLIPPY)
	cd src/sys/tools/mdbg && $(DO_CLIPPY)
	cd src/sys/tests/systest && $(DO_CLIPPY)
	cd src/sys/tests/crossbench && $(DO_CLIPPY)
	cd src/sys/tests/mio-test && $(DO_CLIPPY)
	cd src/sys/tests/tokio-tests && $(DO_CLIPPY)
	cd src/bin/rush && $(DO_CLIPPY)
	cd src/bin/russhd && $(DO_CLIPPY)
	cd src/bin/httpd && $(DO_CLIPPY)
	cd src/bin/httpd-axum && $(DO_CLIPPY)
	cd src/bin/kibim && $(DO_CLIPPY)
	cd src/bin/rnetbench && $(DO_CLIPPY)
	cd src/imager && cargo clippy $(CARGO_RELEASE)

clean:
	rm -rf build/*
	rm -rf vm_images
	rm -rf src/sys/target
	rm -rf src/boot/*/target
	cd src/imager && cargo clean && rm -rf target
	cd src/bin && rm -rf */target
	cd src/sys && rm -rf */target
	rm -f lib/rt.vdso/rt.vdso
