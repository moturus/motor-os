# Motor OS.

BUILD ?= debug

ifeq ($(BUILD), release)
	CARGO_RELEASE := --release
	BIN_DIR := $(CURDIR)/build/bin/release
	OBJ_DIR := $(CURDIR)/build/obj/release
	SUB_DIR := x86_64-unknown-motor/release
	IMG_CMD := release
else
	CARGO_RELEASE :=
	BIN_DIR := $(CURDIR)/build/bin/debug
	OBJ_DIR := $(CURDIR)/build/obj
	SUB_DIR := x86_64-unknown-motor/debug
	IMG_CMD := debug
endif

ROOT_DIR := $(CURDIR)
HOST_LORRY_TARGET_DIR := $(ROOT_DIR)/build/lorry/stage2/host-target
HOST_LORRY := $(HOST_LORRY_TARGET_DIR)/release/lorry
MOTOR_DNS_CLANG ?= $(abspath $(ROOT_DIR)/../llvm-project/build/bin/clang)
MOTOR_DNS_SYSROOT ?= $(abspath $(ROOT_DIR)/../motor-sysroot)
MOTOR_DNS_SDK ?= $(abspath $(ROOT_DIR)/../motor-sysroot/sys/tools/llvm)
ifneq ($(MOTOR_DNS_STRICT_LINK),1)
	MOTOR_DNS_COMPAT_LINK_ARG := -C link-arg=-Wl,--allow-multiple-definition
endif
MOTOR_DNS_RUSTFLAGS := -C linker=$(MOTOR_DNS_CLANG) \
	-C link-arg=--no-default-config \
	-C link-arg=--target=x86_64-unknown-motor \
	-C link-arg=--sysroot=$(MOTOR_DNS_SYSROOT) \
	$(MOTOR_DNS_COMPAT_LINK_ARG) \
	-C link-self-contained=no \
	-C default-linker-libraries=yes

DO_BUILD = cargo +dev-x86_64-unknown-motor build --target x86_64-unknown-motor $(CARGO_RELEASE)

DO_CLIPPY = cargo +dev-x86_64-unknown-motor clippy --target x86_64-unknown-motor $(CARGO_RELEASE)

all: main.img
boot: mbr.bin boot.bin kloader
core: kernel vdso
sys: strobe sys-io sys-init sys-tty dns-resolver
user: sysbox systest mio-test tokio-tests crossterm-smoke \
	rush kibim mdbg red rmux rnetbench crossbench \
	russhd httpd httpd-axum
# The dev-only binaries depend on lorry and are baked only into motor-os-dev.img.
user-dev: user gears gears-mock-provider lorry curl

.PHONY: all boot core sys user user-dev base.img main.img dev.img
.PHONY: mbr.bin boot.bin kloader kernel vdso
.PHONY: strobe sys-io sys-init sys-tty dns-resolver
.PHONY: sysbox systest mio-test tokio-tests crossterm-smoke
.PHONY: rush kibim red rmux russhd httpd httpd-axum gears gears-mock-provider
.PHONY: host-lorry lorry curl
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

strobe:
	mkdir -p $(BIN_DIR)
	cd src/sys/strobe && CARGO_TARGET_DIR="$(OBJ_DIR)/strobe" $(DO_BUILD)
	strip -o "$(BIN_DIR)/strobe" "$(OBJ_DIR)/strobe/$(SUB_DIR)/strobe"

sys-tty:
	mkdir -p $(BIN_DIR)
	cd src/sys/sys-tty && CARGO_TARGET_DIR="$(OBJ_DIR)/sys-tty" $(DO_BUILD)
	strip -o "$(BIN_DIR)/sys-tty" "$(OBJ_DIR)/sys-tty/$(SUB_DIR)/sys-tty"

dns-resolver:
	mkdir -p $(BIN_DIR)
	cd src/sys/dns-resolver && \
		MOTOR_DNS_CLANG="$(MOTOR_DNS_CLANG)" \
		MOTOR_DNS_SYSROOT="$(MOTOR_DNS_SYSROOT)" \
		MOTOR_DNS_SDK="$(MOTOR_DNS_SDK)" \
		CARGO_PROFILE_RELEASE_LTO=false \
		RUSTFLAGS="$(MOTOR_DNS_RUSTFLAGS)" \
		CARGO_TARGET_DIR="$(OBJ_DIR)/dns-resolver" $(DO_BUILD)
	strip -o "$(BIN_DIR)/dns-resolver" \
		"$(OBJ_DIR)/dns-resolver/$(SUB_DIR)/dns-resolver"

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

crossterm-smoke:
	mkdir -p $(BIN_DIR)
	cd src/sys/tests/crossterm-smoke && CARGO_TARGET_DIR="$(OBJ_DIR)/crossterm-smoke" $(DO_BUILD)
	strip -o "$(BIN_DIR)/crossterm-smoke" "$(OBJ_DIR)/crossterm-smoke/$(SUB_DIR)/crossterm-smoke"

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

red:
	mkdir -p $(BIN_DIR)
	cd src/bin/red && CARGO_TARGET_DIR="$(OBJ_DIR)/red" $(DO_BUILD)
	strip -o "$(BIN_DIR)/red" "$(OBJ_DIR)/red/$(SUB_DIR)/red"

rmux:
	mkdir -p $(BIN_DIR)
	cd src/bin/rmux && CARGO_TARGET_DIR="$(OBJ_DIR)/rmux" $(DO_BUILD)
	strip -o "$(BIN_DIR)/rmux" "$(OBJ_DIR)/rmux/$(SUB_DIR)/rmux"

rnetbench:
	mkdir -p $(BIN_DIR)
	cd src/bin/rnetbench && CARGO_TARGET_DIR="$(OBJ_DIR)/rnetbench" $(DO_BUILD)
	strip -o "$(BIN_DIR)/rnetbench" "$(OBJ_DIR)/rnetbench/$(SUB_DIR)/rnetbench"

gears:
	mkdir -p $(BIN_DIR)
	cd src/bin/gears && CARGO_TARGET_DIR="$(OBJ_DIR)/gears" \
		$(DO_BUILD) --locked --offline
	cd src/bin/gears && CARGO_TARGET_DIR="$(OBJ_DIR)/gears" \
		$(DO_BUILD) --locked --offline --examples
	strip -o "$(BIN_DIR)/gears" "$(OBJ_DIR)/gears/$(SUB_DIR)/gears"
	strip -o "$(BIN_DIR)/gears-crossterm-frame" \
		"$(OBJ_DIR)/gears/$(SUB_DIR)/examples/crossterm-frame"
	strip -o "$(BIN_DIR)/gears-measure" \
		"$(OBJ_DIR)/gears/$(SUB_DIR)/examples/gears-measure"

gears-mock-provider:
	mkdir -p $(BIN_DIR)
	cd src/bin/gears-mock-provider && \
		CARGO_TARGET_DIR="$(OBJ_DIR)/gears-mock-provider" \
		$(DO_BUILD) --locked --offline
	strip -o "$(BIN_DIR)/gears-mock-provider" \
		"$(OBJ_DIR)/gears-mock-provider/$(SUB_DIR)/gears-mock-provider"

# curl is cross-built by a Linux-hosted lorry. This is distinct from the
# Motor-target lorry installed in the image below.
host-lorry:
	cd src/bin/lorry && CARGO_TARGET_DIR="$(HOST_LORRY_TARGET_DIR)" \
		cargo build --release --locked

lorry:
	mkdir -p $(BIN_DIR)
	cd src/bin/lorry && CARGO_TARGET_DIR="$(OBJ_DIR)/lorry" $(DO_BUILD)
	strip -o "$(BIN_DIR)/lorry" "$(OBJ_DIR)/lorry/$(SUB_DIR)/lorry"

# curl is built by lorry (its Motor `cc`/`ring` trees only lorry can
# materialize), so its recipe is a script rather than the cargo block.
curl: host-lorry
	mkdir -p $(BIN_DIR)
	cd src/bin/curl && MOTO_BIN="$(BIN_DIR)" LORRY_HOST="$(HOST_LORRY)" \
		./build-motor.sh $(CARGO_RELEASE)

# The images share vm_images/$(IMG_CMD), so each recipe removes only its own
# image file(s); test.key is read-only, hence cp -f for the VM scripts.
define INSTALL_VM_SCRIPTS
	cp -f "$(ROOT_DIR)/src/vm_scripts/"* \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/"
	chmod 400 "$(ROOT_DIR)/vm_images/$(IMG_CMD)/test.key"
endef

# The base and the main images: no curl/lorry/gears (nothing lorry-built).
main.img: boot core sys user
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)"
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os.img" \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-base.img"
	cd src/imager && \
		cargo run $(CARGO_RELEASE) -- "$(ROOT_DIR)" $(IMG_CMD) motor-os.yaml
	cd src/imager && \
		cargo run $(CARGO_RELEASE) -- "$(ROOT_DIR)" $(IMG_CMD) motor-os-base.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built Motor OS images in $(ROOT_DIR)/vm_images/$(IMG_CMD)"

# The base image alone; what src/build-base.sh produces.
base.img: boot core sys rush russhd red rmux
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)"
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-base.img"
	cd src/imager && \
		cargo run $(CARGO_RELEASE) -- "$(ROOT_DIR)" $(IMG_CMD) motor-os-base.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the Motor OS base image in $(ROOT_DIR)/vm_images/$(IMG_CMD)"

# The dev image: the main image plus lorry, its curl transport, gears, the
# generated native LLVM/C/C++ and Rust toolchains, ripgrep, and selected source
# trees.
dev.img: boot core sys user-dev
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)"
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-dev.img"
	cd src/imager && \
		cargo run $(CARGO_RELEASE) -- "$(ROOT_DIR)" $(IMG_CMD) motor-os-dev.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the Motor OS dev image in $(ROOT_DIR)/vm_images/$(IMG_CMD)"

clippy: vdso
	cd src/sys/sys-io && $(DO_CLIPPY)
	cd src/sys/sys-init && $(DO_CLIPPY)
	cd src/sys/strobe && $(DO_CLIPPY)
	cd src/sys/sys-tty && $(DO_CLIPPY)
	cd src/sys/dns-resolver && \
		MOTOR_DNS_CLANG="$(MOTOR_DNS_CLANG)" \
		MOTOR_DNS_SYSROOT="$(MOTOR_DNS_SYSROOT)" \
		MOTOR_DNS_SDK="$(MOTOR_DNS_SDK)" \
		CARGO_PROFILE_RELEASE_LTO=false \
		RUSTFLAGS="$(MOTOR_DNS_RUSTFLAGS)" $(DO_CLIPPY)
	cd src/sys/tools/sysbox && $(DO_CLIPPY)
	cd src/sys/tools/mdbg && $(DO_CLIPPY)
	cd src/sys/tests/systest && $(DO_CLIPPY)
	cd src/sys/tests/crossbench && $(DO_CLIPPY)
	cd src/sys/tests/mio-test && $(DO_CLIPPY)
	cd src/sys/tests/crossterm-smoke && $(DO_CLIPPY)
	cd src/sys/tests/tokio-tests && $(DO_CLIPPY)
	cd src/bin/rush && $(DO_CLIPPY)
	cd src/bin/russhd && $(DO_CLIPPY)
	cd src/bin/httpd && $(DO_CLIPPY)
	cd src/bin/httpd-axum && $(DO_CLIPPY)
	cd src/bin/kibim && $(DO_CLIPPY)
	cd src/bin/red && $(DO_CLIPPY)
	cd src/bin/rmux && $(DO_CLIPPY)
	cd src/bin/rnetbench && $(DO_CLIPPY)
	cd src/bin/gears && $(DO_CLIPPY)
	cd src/bin/gears-mock-provider && $(DO_CLIPPY) --locked --offline
	cd src/bin/lorry && $(DO_CLIPPY)
	cd src/imager && cargo clippy $(CARGO_RELEASE)

clean:
	rm -rf build/*
	rm -rf vm_images
	rm -rf src/sys/target
	rm -rf src/boot/*/target
	rm -rf src/third_party/*/target
	rm -rf src/third_party/*/Cargo.lock
	cd src/imager && cargo clean && rm -rf target
	cd src/bin && rm -rf */target
	cd src/sys && rm -rf */target
	rm -f lib/rt.vdso/rt.vdso
