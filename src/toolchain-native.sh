#!/usr/bin/env bash
# Native Motor rustc build from the same selected Rust and LLVM source tuple.

toolchain_reject_assembly() {
	local reason="$1" marker="$ASSEMBLY_ROOT/MOTOR-ASSEMBLY-REJECTED" temporary
	mkdir -p "$ASSEMBLY_ROOT"
	if [ ! -e "$marker" ]; then
		temporary="$(mktemp "${marker}.tmp.XXXXXX")"
		printf '%s\n' "$reason" > "$temporary"
		chmod 0444 "$temporary"
		mv "$temporary" "$marker"
	fi
	toolchain_die "$reason; preserved $ASSEMBLY_ROOT"
}

toolchain_validate_native_elf() {
	local binary="$1" readelf="$2" unstripped="${3:-}" headers sections dynamic symbols
	local nm unwind_symbols
	[ -x "$binary" ] || { toolchain_die "native ELF is not executable: $binary"; return 1; }
	[ -x "$readelf" ] || { toolchain_die "ELF reader is not executable: $readelf"; return 1; }
	headers="$("$readelf" -W -h -l "$binary")" || return
	sections="$("$readelf" -W -S "$binary")" || return
	dynamic="$("$readelf" -W -d "$binary")" || return
	symbols="$("$readelf" -W --dyn-syms "$binary")" || return
	if ! awk '
		function decimal(value) {
			if (value !~ /^[0-9]+$/ || value + 0 > max) return -1
			return value + 0
		}
		function hex(value, number, position, digit) {
			if (value !~ /^0x[0-9a-fA-F]+$/) return -1
			sub(/^0x/, "", value)
			number = 0
			for (position = 1; position <= length(value); position++) {
				digit = indexof(tolower(substr(value, position, 1))) - 1
				if (digit < 0 || number > int((max - digit) / 16)) return -1
				number = number * 16 + digit
			}
			return number
		}
		function indexof(digit) { return index("0123456789abcdef", digit) }
		# AWK integers are exact only through 2^53 - 1; reject larger ELF values.
		BEGIN { max = 9007199254740991 }
		/Class:.*ELF64/ { class++ }
		/Data:.*little endian/ { endian++ }
		/Type:.*DYN/ { pie++ }
		/Machine:.*Advanced Micro Devices X86-64/ { machine++ }
		/Start of program headers:/ { phoff = decimal($5); phoff_seen++ }
		/Size of program headers:/ { phentsize = decimal($5); phentsize_seen++ }
		/Number of program headers:/ { phnum = decimal($5); phnum_seen++ }
		$1 == "INTERP" || $1 == "TLS" { bad = 1 }
		$1 == "GNU_STACK" {
			stack++
			flags = ""
			for (field = 7; field < NF; field++) flags = flags $field
			if (index(flags, "E")) bad = 1
		}
		$1 == "LOAD" {
			loads++
			offset = hex($2); address = hex($3); filesz = hex($5); memsz = hex($6)
			if (offset < 0 || address < 0 || filesz < 0 || memsz < 0 || address > max - memsz) {
				bad = 1
				next
			}
			flags = ""
			for (field = 7; field < NF; field++) flags = flags $field
			if (loads == 1) {
				first_offset = offset
				first_address = address
				first_filesz = filesz
			}
			if (index(flags, "W") && index(flags, "E")) bad = 1
			if (index(flags, "R")) {
				readable++
				read_start[readable] = address
				read_end[readable] = address + memsz
			}
		}
		$1 == "GNU_EH_FRAME" {
			eh_frames++
			eh_start = hex($3); eh_size = hex($6)
			if (eh_start < 0 || eh_size <= 0 || eh_start > max - eh_size) bad = 1
			else eh_end = eh_start + eh_size
		}
		END {
			if (class != 1 || endian != 1 || pie != 1 || machine != 1 || stack != 1 || bad ||
			    phoff_seen != 1 || phentsize_seen != 1 || phnum_seen != 1 ||
			    phoff < 0 || phentsize <= 0 || phnum <= 0 || loads == 0 ||
			    first_offset != 0 || first_address != 0 || eh_frames != 1) exit 1
			if (phnum > int((max - phoff) / phentsize)) exit 1
			header_end = phoff + phnum * phentsize
			if (first_filesz < header_end) exit 1
			for (slot = 1; slot <= readable; slot++)
				if (read_start[slot] <= eh_start && eh_end <= read_end[slot]) inside = 1
			exit !inside
		}
	' <<< "$headers"; then
		toolchain_die "native ELF has incompatible headers or unwind segment layout"; return 1
	fi
	if ! awk '
		{ sub(/^.*\] +/, "") }
		$1 == ".init_array" && $2 == "INIT_ARRAY" && $5 !~ /^0+$/ { found++ }
		$1 == ".eh_frame_hdr" && $5 !~ /^0+$/ { header++ }
		$1 == ".eh_frame" && $5 !~ /^0+$/ { frames++ }
		$1 == ".gcc_except_table" && $5 !~ /^0+$/ { exceptions++ }
		END { exit found != 1 || header != 1 || frames != 1 || exceptions != 1 }
	' <<< "$sections" || ! awk '
		/NEEDED|TEXTREL/ { bad = 1 }
		/\(INIT_ARRAYSZ\)/ && $3 > 0 { array++ }
		END { exit bad || array != 1 }
	' <<< "$dynamic" || ! awk '
		$7 == "UND" && $1 != "0:" { bad = 1 }
		END { exit bad }
	' <<< "$symbols"; then
		toolchain_die "native ELF has invalid constructors, unwind tables, dependencies, relocations, or symbols"; return 1
	fi
	if [ -n "$unstripped" ]; then
		[ -f "$unstripped" ] || { toolchain_die "unstripped native ELF is missing: $unstripped"; return 1; }
		nm="$(dirname "$readelf")/llvm-nm"
		[ -x "$nm" ] || { toolchain_die "LLVM symbol reader is not executable: $nm"; return 1; }
		unwind_symbols="$("$nm" --defined-only "$unstripped")" || return
		if ! awk '
			$NF ~ /^__unw_/ { bad = 1 }
			$(NF - 1) == "T" && $NF == "_Unwind_RaiseException" { raise++ }
			END { exit bad || raise != 1 }
		' <<< "$unwind_symbols"; then
			toolchain_die "native ELF does not contain exactly one Rust unwind provider"; return 1
		fi
	fi
}

toolchain_validate_native_rustc() {
	local binary="$1"
	[ -x "$binary" ] || toolchain_die "native rustc was not produced: $binary" || return
	grep -aFq "$EFFECTIVE_MOTOR_RUST_REV" "$binary" ||
		toolchain_die "native rustc lacks the effective Rust revision" || return
	grep -aFq "$SELECTED_TOOLCHAIN_DESCRIPTION" "$binary" ||
		toolchain_die "native rustc lacks the selected release description" || return
	toolchain_validate_native_elf "$binary" "$STANDALONE_LLVM_BIN/llvm-readelf" "$binary"
}

toolchain_validate_native_rustfmt() {
	local binary="$1" expected_build="$2"
	[ -x "$binary" ] || toolchain_die "native rustfmt was not produced: $binary" || return
	grep -aFq "$expected_build" "$binary" ||
		toolchain_die "native rustfmt lacks the expected build identity" || return
	toolchain_validate_native_elf "$binary" "$STANDALONE_LLVM_BIN/llvm-readelf" "$binary"
}

toolchain_render_native_llvm_config() {
	local real_bin="$1" target_root="$2" real_root
	local real_bin_q real_root_q target_root_q
	toolchain_bootstrap_absolute_path real_llvm_bin "$real_bin" || return
	toolchain_bootstrap_absolute_path target_llvm_root "$target_root" || return
	real_root="$(dirname "$real_bin")"
	printf -v real_bin_q %q "$real_bin/llvm-config"
	printf -v real_root_q %q "$real_root"
	printf -v target_root_q %q "$target_root"
	cat <<EOF
#!/usr/bin/env bash
set -euo pipefail
real=$real_bin_q
real_root=$real_root_q
target_root=$target_root_q
if [ "\$#" -eq 1 ] && [ "\$1" = --bindir ]; then
	exec "\$real" "\$@"
fi
if [ "\${TARGET:-}" != x86_64-unknown-motor ]; then
	exec "\$real" "\$@"
fi
output="\$("\$real" "\$@")"
printf '%s\n' "\${output//"\$real_root"/"\$target_root"}"
EOF
}

toolchain_generate_native_llvm_config() {
	local output_bin="$1" real_bin="$2" target_root="$3"
	local output temporary tool link
	toolchain_bootstrap_absolute_path native_llvm_bin "$output_bin" || return
	[ -x "$real_bin/llvm-config" ] ||
		toolchain_die "standalone llvm-config is not executable: $real_bin/llvm-config" || return
	mkdir -p "$output_bin"
	output="$output_bin/llvm-config"
	temporary="$(mktemp "${output}.tmp.XXXXXX")"
	if ! toolchain_render_native_llvm_config \
		"$real_bin" "$target_root" > "$temporary"; then
		rm -f "$temporary"
		return 1
	fi
	chmod 0755 "$temporary"
	if [ -e "$output" ]; then
		if ! cmp -s "$temporary" "$output" || [ ! -x "$output" ]; then
			rm -f "$temporary"
			toolchain_die "existing native llvm-config adapter does not match: $output"
			return 1
		fi
		rm -f "$temporary"
	else
		mv "$temporary" "$output"
	fi
	for tool in llvm-ar llvm-ranlib; do
		[ -x "$real_bin/$tool" ] ||
			toolchain_die "standalone LLVM tool is not executable: $real_bin/$tool" || return
		link="$output_bin/$tool"
		if [ -L "$link" ] && [ "$(readlink "$link")" = "$real_bin/$tool" ]; then
			continue
		fi
		[ ! -e "$link" ] && [ ! -L "$link" ] ||
			toolchain_die "existing native LLVM tool link does not match: $link" || return
		ln -s "$real_bin/$tool" "$link"
	done
}

toolchain_build_native_rustc() {
	local rust="$1" authoring_base="$2" bootstrap_cache="$3"
	local expected_digest="$AUTHORING_SOURCE_DIGEST"
	local prefix_before prefix_after native_llvm_bin target_llvm_root rustfmt_date
	toolchain_generate_cross_wrappers "$ASSEMBLY_SYSROOT" "$STANDALONE_LLVM_BIN" || return
	native_llvm_bin="$ASSEMBLY_ROOT/native-llvm-config/bin"
	target_llvm_root="$rust/build/x86_64-unknown-motor/llvm"
	toolchain_generate_native_llvm_config \
		"$native_llvm_bin" "$STANDALONE_LLVM_BIN" "$target_llvm_root" || return
	NATIVE_BOOTSTRAP_CONFIG="$ASSEMBLY_ROOT/native-bootstrap.toml"
	toolchain_generate_bootstrap_config "$NATIVE_BOOTSTRAP_CONFIG" "$rust" \
		"$TOOLCHAIN_PREFIX" "$ASSEMBLY_SYSROOT" "$native_llvm_bin" \
		"$bootstrap_cache" "$SELECTED_TOOLCHAIN_DESCRIPTION" || return
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || return
	prefix_before="$(toolchain_content_tree_digest "$TOOLCHAIN_PREFIX" .)" || return
	if ! (cd "$rust" && PYTHONDONTWRITEBYTECODE=1 \
		PYTHONPYCACHEPREFIX="$TOOLCHAIN_STATE_ROOT/python-cache" \
		./x.py --config "$NATIVE_BOOTSTRAP_CONFIG" build \
		--stage 2 compiler src/tools/rustfmt --host x86_64-unknown-motor \
		--target x86_64-unknown-motor); then
		toolchain_reject_assembly "native Rust bootstrap failed"
		return 1
	fi
	if ! toolchain_postbuild_locks_unchanged "$rust"; then
		toolchain_reject_assembly "$TOOLCHAIN_LOCK_REWRITE_REASON"
		return 1
	fi
	toolchain_reverify_selected_sources \
		"$rust" "$authoring_base" "$expected_digest" || {
		toolchain_reject_assembly "Rust sources changed during native bootstrap"
		return 1
	}
	prefix_after="$(toolchain_content_tree_digest "$TOOLCHAIN_PREFIX" .)" || return
	[ "$prefix_before" = "$prefix_after" ] || {
		toolchain_reject_assembly "native bootstrap modified the installed prefix"
		return 1
	}
	RUSTC_MAIN="$rust/build/x86_64-unknown-linux-gnu/stage2-rustc/x86_64-unknown-motor/release/rustc-main"
	RUSTFMT_MAIN="$rust/build/x86_64-unknown-linux-gnu/stage2-tools/x86_64-unknown-motor/release/rustfmt"
	toolchain_validate_native_rustc "$RUSTC_MAIN" || {
		toolchain_reject_assembly "native rustc identity validation failed"
		return 1
	}
	rustfmt_date="$(git -C "$rust" log -1 --date=short --format=%cd \
		"$EFFECTIVE_MOTOR_RUST_REV")" || {
		toolchain_reject_assembly "effective Rust revision date is unavailable"
		return 1
	}
	toolchain_validate_native_rustfmt "$RUSTFMT_MAIN" \
		"dev (${EFFECTIVE_MOTOR_RUST_REV:0:10} $rustfmt_date)" || {
		toolchain_reject_assembly "native rustfmt identity validation failed"
		return 1
	}
}
