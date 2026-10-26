#!/usr/bin/env bash
# Check that an ELF linked through the cross sysroot loads on Motor OS: a
# static PIE with no interpreter, TLS, dependencies, text relocations, or
# undefined dynamic symbols, one non-executable stack, no writable and
# executable segment, constructors, and unwind tables inside a readable
# segment. The toolchain build checks its native tools the same way.
#   src/build-scripts/validate-native-elf.sh ELF [UNSTRIPPED-ELF]

set -euo pipefail

fail() {
	echo "validate-native-elf: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] || [ "$#" -eq 2 ] || { echo "usage: $0 ELF [UNSTRIPPED-ELF]" >&2; exit 2; }
binary="$1"
unstripped="${2:-}"
[ -x "$binary" ] || fail "native ELF is not executable: $binary"
headers="$(readelf -W -h -l "$binary")"
sections="$(readelf -W -S "$binary")"
dynamic="$(readelf -W -d "$binary")"
symbols="$(readelf -W --dyn-syms "$binary")"
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
	fail "native ELF has incompatible headers or unwind segment layout: $binary"
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
	fail "native ELF has invalid constructors, unwind tables, dependencies, relocations, or symbols: $binary"
fi
# With the unstripped ELF: it carries exactly one Rust unwind provider.
if [ -n "$unstripped" ]; then
	[ -f "$unstripped" ] || fail "unstripped native ELF is missing: $unstripped"
	if ! nm --defined-only "$unstripped" | awk '
		$NF ~ /^__unw_/ { bad = 1 }
		$(NF - 1) == "T" && $NF == "_Unwind_RaiseException" { raise++ }
		END { exit bad || raise != 1 }
	'; then
		fail "native ELF does not contain exactly one Rust unwind provider: $unstripped"
	fi
fi
