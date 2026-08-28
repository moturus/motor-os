# Motor OS.

BUILD ?= debug

ROOT_DIR := $(CURDIR)
TOOLCHAIN_SYSROOT := $(shell rustc --print sysroot 2>/dev/null)
MOTOR_TOOLCHAIN_KEY := $(strip $(shell \
	stamp="$(TOOLCHAIN_SYSROOT)/lib/rustlib/MOTOR-TOOLCHAIN-KEY"; \
	test -f "$$stamp" && grep -Ex '[0-9a-f]{64}' "$$stamp"))
ifeq ($(MOTOR_TOOLCHAIN_KEY),)
	$(error selected Rust toolchain is not a stamped Motor toolchain; run src/build-motor-os.sh)
endif
OBJ_ROOT := $(ROOT_DIR)/build/obj/$(MOTOR_TOOLCHAIN_KEY)

ifeq ($(BUILD), release)
	CARGO_RELEASE := --release
	BIN_DIR := $(CURDIR)/build/bin/release
	OBJ_DIR := $(OBJ_ROOT)/release
	SUB_DIR := x86_64-unknown-motor/release
	IMG_CMD := release
else
	CARGO_RELEASE :=
	BIN_DIR := $(CURDIR)/build/bin/debug
	OBJ_DIR := $(OBJ_ROOT)/debug
	SUB_DIR := x86_64-unknown-motor/debug
	IMG_CMD := debug
endif

IMAGER_LOCK := $(ROOT_DIR)/build/imager.lock
IMAGER_TARGET_DIR := $(OBJ_DIR)/imager
ASSEMBLY_SELECTOR := $(ROOT_DIR)/src/select-toolchain-assembly.sh
DO_BUILD = cargo build --target x86_64-unknown-motor $(CARGO_RELEASE)

DO_CLIPPY = cargo clippy --target x86_64-unknown-motor $(CARGO_RELEASE)

all: base.img main.img
images: base.img main.img dev.img
boot: mbr.bin boot.bin kloader
core: kernel vdso
sys-base: strobe sys-io sys-init sys-tty
sys: sys-base dns-resolver
user-base: sysbox rush red rmux russhd
user: user-base kibim httpd httpd-axum
user-dev: user curl gears gears-mock-provider lorry mdbg rnetbench crossbench \
	systest mio-test tokio-tests crossterm-smoke

.PHONY: all images boot core sys-base sys user-base user user-dev
.PHONY: base.img main.img dev.img system-tty.img
.PHONY: mbr.bin boot.bin kloader kernel vdso
.PHONY: strobe sys-io sys-init sys-tty dns-resolver
.PHONY: sysbox systest mio-test tokio-tests crossterm-smoke
.PHONY: rush kibim red rmux russhd httpd httpd-axum gears gears-mock-provider
.PHONY: lorry curl
.PHONY: mdbg rnetbench crossbench
.PHONY: clean clippy assembly-selected

assembly-selected:
	@"$(ASSEMBLY_SELECTOR)" --resolve >/dev/null

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
	cd src/sys/dns-resolver && CARGO_TARGET_DIR="$(OBJ_DIR)/dns-resolver" $(DO_BUILD)
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
		$(DO_BUILD)
	strip -o "$(BIN_DIR)/gears" "$(OBJ_DIR)/gears/$(SUB_DIR)/gears"

gears-mock-provider:
	mkdir -p $(BIN_DIR)
	cd src/bin/gears-mock-provider && \
		CARGO_TARGET_DIR="$(OBJ_DIR)/gears-mock-provider" \
		$(DO_BUILD)
	strip -o "$(BIN_DIR)/gears-mock-provider" \
		"$(OBJ_DIR)/gears-mock-provider/$(SUB_DIR)/gears-mock-provider"

lorry: assembly-selected
	mkdir -p $(BIN_DIR)
	assembly_image_root="$$($(ASSEMBLY_SELECTOR) --resolve)" && \
	assembly_sysroot="$$(realpath "$$assembly_image_root/../sysroot")" && \
	cd src/bin/lorry && \
		CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$$assembly_sysroot/bin/motor-clang" \
		CARGO_TARGET_DIR="$(OBJ_DIR)/lorry" $(DO_BUILD)
	strip -o "$(BIN_DIR)/lorry" "$(OBJ_DIR)/lorry/$(SUB_DIR)/lorry"

# ring's Git checkout generates packaged assembly on the Linux host. Curl is
# therefore cross-built by Cargo and is not part of the native Lorry surface.
curl: assembly-selected
	mkdir -p $(BIN_DIR)
	assembly_image_root="$$($(ASSEMBLY_SELECTOR) --resolve)" && \
	cd src/bin/curl && MOTO_BIN="$(BIN_DIR)" \
		MOTOR_ASSEMBLY_IMAGE_ROOT="$$assembly_image_root" \
		CARGO_TARGET_DIR="$(OBJ_DIR)/curl" \
		./build-motor.sh $(CARGO_RELEASE)

# The images share imager scratch files and vm_images/$(IMG_CMD). Compilation
# remains parallel, but the short imaging steps take a common host lock. Each
# recipe removes only its own image; test.key is read-only, hence cp -f.
define INSTALL_VM_SCRIPTS
	flock "$(IMAGER_LOCK)" sh -c 'cp -f "$(ROOT_DIR)/src/vm_scripts/"* \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/" && \
		chmod 400 "$(ROOT_DIR)/vm_images/$(IMG_CMD)/test.key"'
endef

# The standard image adds production networking and user programs to base.
main.img: assembly-selected boot core sys user
	assembly_image_root="$$($(ASSEMBLY_SELECTOR) --resolve)" && \
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)" && \
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os.img" \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os.qcow2" && \
	cd src/imager && \
		flock "$(IMAGER_LOCK)" env CARGO_TARGET_DIR="$(IMAGER_TARGET_DIR)" \
		MOTOR_ASSEMBLY_IMAGE_ROOT="$$assembly_image_root" \
		cargo run $(CARGO_RELEASE) -- \
			"$(ROOT_DIR)" $(IMG_CMD) motor-os.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the standard Motor OS image: $(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os.qcow2"

# A small test-only image whose later overlay selects a System serial console.
system-tty.img: boot core sys-base user-base
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)"
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-system-tty.img"
	cd src/imager && \
		flock "$(IMAGER_LOCK)" env CARGO_TARGET_DIR="$(IMAGER_TARGET_DIR)" \
		cargo run $(CARGO_RELEASE) -- \
			"$(ROOT_DIR)" $(IMG_CMD) motor-os-system-tty.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the System-console test image: $(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-system-tty.img"

# The minimal base image; it does not consume toolchain assembly overlays.
base.img: boot core sys-base user-base
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)"
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-base.img"
	cd src/imager && \
		flock "$(IMAGER_LOCK)" env CARGO_TARGET_DIR="$(IMAGER_TARGET_DIR)" \
		cargo run $(CARGO_RELEASE) -- \
			"$(ROOT_DIR)" $(IMG_CMD) motor-os-base.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the Motor OS base image in $(ROOT_DIR)/vm_images/$(IMG_CMD)"

# The dev image adds diagnostics, tests, sources, and native toolchains.
dev.img: assembly-selected boot core sys user-dev
	assembly_image_root="$$($(ASSEMBLY_SELECTOR) --resolve)" && \
	mkdir -p "$(ROOT_DIR)/vm_images/$(IMG_CMD)" && \
	rm -f "$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-dev.img" \
		"$(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-dev.qcow2" && \
	cd src/imager && \
		flock "$(IMAGER_LOCK)" env CARGO_TARGET_DIR="$(IMAGER_TARGET_DIR)" \
		MOTOR_ASSEMBLY_IMAGE_ROOT="$$assembly_image_root" \
		cargo run $(CARGO_RELEASE) -- \
			"$(ROOT_DIR)" $(IMG_CMD) motor-os-dev.yaml
	$(INSTALL_VM_SCRIPTS)
	@echo "built the Motor OS dev image: $(ROOT_DIR)/vm_images/$(IMG_CMD)/motor-os-dev.qcow2"

clippy: vdso
	cd src/sys/sys-io && $(DO_CLIPPY)
	cd src/sys/sys-init && $(DO_CLIPPY)
	cd src/sys/strobe && $(DO_CLIPPY)
	cd src/sys/sys-tty && $(DO_CLIPPY)
	cd src/sys/dns-resolver && $(DO_CLIPPY)
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
	cd src/bin/gears-mock-provider && $(DO_CLIPPY)
	cd src/bin/lorry && $(DO_CLIPPY)
	cd src/imager && CARGO_TARGET_DIR="$(IMAGER_TARGET_DIR)" cargo clippy $(CARGO_RELEASE)

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
