use std::{fs, io, path::Path};

pub fn write(root: &Path) -> io::Result<()> {
    for (name, text) in FILES {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, text)?;
    }
    Ok(())
}

pub const BACKING: &str = r####";; One guest memory against the installed runner's 4 GiB limit, the whole
;; 32-bit range. Failed checks exit with distinct statuses.
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory 0)
  ;; Growth to 4 GiB must touch no page: the VM could not hold them.
  (func (export "grow-to-limit")
    (if (i32.ne (memory.grow (i32.const 65536)) (i32.const 0))
      (then (call $exit (i32.const 2))))
    (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1))
      (then (call $exit (i32.const 3))))
    (if (i32.ne (memory.size) (i32.const 65536))
      (then (call $exit (i32.const 4))))
    (if (i32.or (i32.load8_u (i32.const 0)) (i32.load8_u (i32.const -1)))
      (then (call $exit (i32.const 5)))))
  ;; Writes every 4 KiB page of 96 MiB, faulting them in.
  (func (export "touch") (local $offset i32)
    (if (i32.ne (memory.grow (i32.const 1536)) (i32.const 0))
      (then (call $exit (i32.const 2))))
    (loop $pages
      (i32.store8 (local.get $offset) (i32.const 1))
      (local.set $offset (i32.add (local.get $offset) (i32.const 4096)))
      (br_if $pages (i32.lt_u (local.get $offset) (i32.const 100663296))))))
"####;

pub const MISTYPED: &str = r####";; fd_write declared with the wrong type: the runner must refuse to instantiate.
(module
  (import "wasi_snapshot_preview1" "fd_write" (func (param i64 i64 i64 i64) (result i32)))
  (func (export "_start")))
"####;

pub const RUNNER: &str = r####"(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (func (export "_start"))
  (func (export "exit-zero") i32.const 0 call $exit)
  (func (export "exit-seven") i32.const 7 call $exit)
  (func (export "trap") unreachable)
  (func (export "loop") (loop $again br $again)))
"####;

pub const WASI: &str = r####";; WASI preview1 behavior of the installed wasmi runner. Each export reports
;; through its exit status; proc_exit is imported twice on purpose.
;; Memory: iovec at 0, count at 16, results at 32, buffer at 1024.
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit_again (param i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $fdstat (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "ready\n")
  (func $iov (param $len i32)
    (i32.store (i32.const 0) (i32.const 1024))
    (i32.store (i32.const 4) (local.get $len)))
  (func $write_buffer (param $fd i32) (result i32)
    (call $write (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 16)))
  (func (export "duplicate-exit") (call $exit_again (i32.const 0)))
  (func (export "write-ready")
    (call $iov (i32.const 6))
    (call $exit (call $write_buffer (i32.const 1))))
  ;; Echo what one read of stdin returns.
  (func (export "read-once")
    (local $errno i32)
    (call $iov (i32.const 4096))
    (local.set $errno (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 16)))
    (if (local.get $errno) (then (call $exit (local.get $errno))))
    (call $iov (i32.load (i32.const 16)))
    (call $exit (call $write_buffer (i32.const 1))))
  (func (export "close-twice")
    (drop (call $close (i32.const 0)))
    (call $exit (call $close (i32.const 0))))
  (func (export "read-closed")
    (drop (call $close (i32.const 0)))
    (call $iov (i32.const 16))
    (call $exit (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 16))))
  (func (export "write-closed")
    (drop (call $close (i32.const 1)))
    (call $iov (i32.const 6))
    (call $exit (call $write_buffer (i32.const 1))))
  (func (export "stat-closed")
    (drop (call $close (i32.const 2)))
    (call $exit (call $fdstat (i32.const 2) (i32.const 32))))
  (func (export "clock-invalid")
    (call $exit (call $clock (i32.const 999) (i64.const 0) (i32.const 32))))
  (func (export "clock-cputime")
    (call $exit (call $clock (i32.const 2) (i64.const 0) (i32.const 32))))
  ;; Exit 0 when realtime is after 2020 and monotonic does not go backwards.
  (func (export "clocks")
    (local $first i64)
    (if (call $clock (i32.const 0) (i64.const 0) (i32.const 32))
      (then (call $exit (i32.const 1))))
    (if (i64.lt_u (i64.load (i32.const 32)) (i64.const 1577836800000000000))
      (then (call $exit (i32.const 2))))
    (if (call $clock (i32.const 1) (i64.const 0) (i32.const 32))
      (then (call $exit (i32.const 3))))
    (local.set $first (i64.load (i32.const 32)))
    (if (call $clock (i32.const 1) (i64.const 0) (i32.const 32))
      (then (call $exit (i32.const 4))))
    (if (i64.lt_u (i64.load (i32.const 32)) (local.get $first))
      (then (call $exit (i32.const 5))))
    (call $exit (i32.const 0))))
"####;

pub const HELLO: &str = "console.log('hello from Motor', 6 * 7);\n";

const FILES: &[(&str, &str)] = &[
    (
        "hello.js",
        r####"console.log('hello from Motor', 6 * 7);
"####,
    ),
    (
        "typescript-workload.js",
        r####"
const motorTsResult = ts.transpileModule("interface Item { value: number }; const item: Item = { value: 42 }; console.log(item.value);", { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext }, reportDiagnostics: true });
console.log(JSON.stringify({version:ts.version,output:motorTsResult.outputText,diagnostics:motorTsResult.diagnostics.length}));
"####,
    ),
    (
        "plugins/Cargo.lock",
        r####"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "aho-corasick"
version = "1.1.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c982642fa9e8606056828ee9a8505737230110bb1099153c79efe865c59d12ba"
dependencies = [
 "memchr",
]

[[package]]
name = "allocator-api2"
version = "0.2.21"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "683d7910e743518b0e34f1186f92494becacb047c7b6bf616c96772180fef923"

[[package]]
name = "anyhow"
version = "1.0.104"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470"

[[package]]
name = "autocfg"
version = "1.5.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53"

[[package]]
name = "bindgen"
version = "0.72.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "993776b509cfb49c750f11b8f07a46fa23e0a1386ffc01fb1e7d343efc387895"
dependencies = [
 "bitflags",
 "cexpr",
 "clang-sys",
 "itertools",
 "log",
 "prettyplease",
 "proc-macro2",
 "quote",
 "regex",
 "rustc-hash",
 "shlex 1.3.0",
 "syn 2.0.119",
]

[[package]]
name = "bitflags"
version = "2.13.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3ded4057c258ba199e2d26386d3af3780957ecaee6c4ef4041c6b4b8b97c0b06"

[[package]]
name = "cc"
version = "1.7.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "50a649af8a827553c29fb0cb4bd4a6f1a0dd695bd3232b9bc98bd9c8a3ffbb8b"
dependencies = [
 "find-msvc-tools",
 "shlex 2.0.1",
]

[[package]]
name = "cexpr"
version = "0.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6fac387a98bb7c37292057cffc56d62ecb629900026402633ae9160df93a8766"
dependencies = [
 "nom",
]

[[package]]
name = "cfg-if"
version = "1.0.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4e7648175b45a9a48536d676f68d918270699102aa8dab5496df06904c914600"

[[package]]
name = "clang-sys"
version = "1.9.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "157a8ba7b480713b56f4c09fd13fc3e0a22a5dfab8097ba61cbc5feef950788a"
dependencies = [
 "glob",
 "libc",
 "libloading",
]

[[package]]
name = "convert_case"
version = "0.11.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "affbf0190ed2caf063e3def54ff444b449371d55c58e513a95ab98eca50adb49"
dependencies = [
 "unicode-segmentation",
]

[[package]]
name = "either"
version = "1.19.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0e9c71c2167ca323c882b99918929403426e2373ea17242ff5653e0d5e1058be"

[[package]]
name = "env_filter"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "900d271a03799a1ee8d1ca9b19893b48ca674a9284fefcfb85f05e74ed314217"
dependencies = [
 "log",
 "regex",
]

[[package]]
name = "env_logger"
version = "0.11.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "de671bd27a75a797dc9ae289ba1e77276e75e2026408aab65185384e2d5cd3f6"
dependencies = [
 "env_filter",
 "log",
]

[[package]]
name = "equivalent"
version = "1.0.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f"

[[package]]
name = "fastrand"
version = "2.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "da7c62ceae207dd37ea5b845da6a0696c799f85e97da1ab5b7910be3c1c80223"

[[package]]
name = "find-msvc-tools"
version = "0.1.14"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aedcfb3409746eddb02b9e19ebda1c3394f759a152e48ee875a0844d1b955484"

[[package]]
name = "float-cmp"
version = "0.10.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b09cf3155332e944990140d967ff5eceb70df778b34f77d8075db46e4704e6d8"
dependencies = [
 "num-traits",
]

[[package]]
name = "fnv"
version = "1.0.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3f9eec918d3f24069decb9af1554cad7c880e2da24a9afd88aca000531ab82c1"

[[package]]
name = "foldhash"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "77ce24cb58228fbb8aa041425bb1050850ac19177686ea6e0f41a70416f56fdb"

[[package]]
name = "getrandom"
version = "0.4.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099"
dependencies = [
 "cfg-if",
 "libc",
 "r-efi",
 "rand_core",
]

[[package]]
name = "glob"
version = "0.3.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e4eba85ea1d0a966a983acd07deee566e67395d2d96b6fb39e62b5a833f1eb0b"

[[package]]
name = "halfbrown"
version = "0.4.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0c7ed2f2edad8a14c8186b847909a41fbb9c3eafa44f88bd891114ed5019da09"
dependencies = [
 "hashbrown 0.16.1",
 "serde",
]

[[package]]
name = "hashbrown"
version = "0.16.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "841d1cc9bed7f9236f321df977030373f4a4163ae1a7dbfe1a51a2c1a51d9100"
dependencies = [
 "allocator-api2",
 "equivalent",
 "foldhash",
]

[[package]]
name = "hashbrown"
version = "0.17.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a"
dependencies = [
 "allocator-api2",
 "equivalent",
 "foldhash",
]

[[package]]
name = "heck"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2304e00983f87ffb38b55b444b5e3b60a884b5d30c0fca7d82fe33449bbe55ea"

[[package]]
name = "id-arena"
version = "2.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3d3067d79b975e8844ca9eb072e16b31c3c1c36928edf9c6789548c524d0d954"

[[package]]
name = "ident_case"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b9e0384b61958566e926dc50660321d12159025e767c18e043daf26b70104c39"

[[package]]
name = "indexmap"
version = "2.14.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cc4e190f5d26ca7051642629da2c52fc03bde85a03197c99408dcd291734c855"
dependencies = [
 "equivalent",
 "hashbrown 0.17.1",
 "serde",
 "serde_core",
]

[[package]]
name = "itertools"
version = "0.13.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "413ee7dfc52ee1a4949ceeb7dbc8a33f2d6c088194d9f922fb8318faf1f01186"
dependencies = [
 "either",
]

[[package]]
name = "itoa"
version = "1.0.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8f42a60cbdf9a97f5d2305f08a87dc4e09308d1276d28c869c684d7777685682"

[[package]]
name = "javy"
version = "8.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d5679b8c3d13df0aa91ed63adc87b98fa1a4e067634db394b694ea453c8291cb"
dependencies = [
 "anyhow",
 "bitflags",
 "fastrand",
 "quickcheck",
 "rquickjs",
 "rquickjs-serde",
 "serde",
 "serde-transcode",
 "serde_json",
 "simd-json",
]

[[package]]
name = "javy-plugin-api"
version = "7.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "354b2c35e84ad2c2aff099650ff844cd16aa9d0629f6853b52d986a0002cde57"
dependencies = [
 "anyhow",
 "javy",
]

[[package]]
name = "javy-smoke-plugin-p1"
version = "0.0.0"
dependencies = [
 "javy-plugin-api",
]

[[package]]
name = "javy-smoke-plugin-p2"
version = "0.0.0"
dependencies = [
 "javy-plugin-api",
 "wit-bindgen",
]

[[package]]
name = "leb128fmt"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "09edd9e8b54e49e587e4f6295a7d29c3ea94d469cb40ab8ca70b288248a81db2"

[[package]]
name = "libc"
version = "0.2.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ce5d3ddc6d3fa000eb1536d85e147bfe31aacaba692ed6a876f95cb7c855be78"

[[package]]
name = "libloading"
version = "0.8.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d7c4b02199fee7c5d21a5ae7d8cfa79a6ef5bb2fc834d6e9058e89c825efdc55"
dependencies = [
 "cfg-if",
 "windows-link",
]

[[package]]
name = "log"
version = "0.4.34"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f9f8bd3e56ce4dfc153cf470fffbfa98c7620958b312ca5c3a4b8d5181fd13c6"

[[package]]
name = "macro-string"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "59a9dbbfc75d2688ed057456ce8a3ee3f48d12eec09229f560f3643b9f275653"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 2.0.119",
]

[[package]]
name = "memchr"
version = "2.8.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98"

[[package]]
name = "minimal-lexical"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "68354c5c6bd36d73ff3feceb05efa59b6acb7626617f4962be322a825e61f79a"

[[package]]
name = "nom"
version = "7.1.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d273983c5a657a70a3e8f2a01329822f3b8c8172b73826411a55751e404a0a4a"
dependencies = [
 "memchr",
 "minimal-lexical",
]

[[package]]
name = "num-traits"
version = "0.2.19"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "071dfc062690e90b734c0b2273ce72ad0ffa95f0c74596bc250dcfd960262841"
dependencies = [
 "autocfg",
]

[[package]]
name = "prettyplease"
version = "0.2.37"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "479ca8adacdd7ce8f1fb39ce9ecccbfe93a3f1344b3d0d97f20bc0196208f62b"
dependencies = [
 "proc-macro2",
 "syn 2.0.119",
]

[[package]]
name = "proc-macro-crate"
version = "3.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e67ba7e9b2b56446f1d419b1d807906278ffa1a658a8a5d8a39dcb1f5a78614f"
dependencies = [
 "toml_edit",
]

[[package]]
name = "proc-macro2"
version = "1.0.107"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
dependencies = [
 "unicode-ident",
]

[[package]]
name = "quickcheck"
version = "1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "95c589f335db0f6aaa168a7cd27b1fc6920f5e1470c804f814d9cd6e62a0f70b"
dependencies = [
 "env_logger",
 "log",
 "rand",
]

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
dependencies = [
 "proc-macro2",
]

[[package]]
name = "r-efi"
version = "6.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf"

[[package]]
name = "rand"
version = "0.10.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "65c9fb96cbc91e3478eaae79a69fcd3f1ae4ad052e471fe6732fff548984b4af"
dependencies = [
 "getrandom",
 "rand_core",
]

[[package]]
name = "rand_core"
version = "0.10.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69"

[[package]]
name = "ref-cast"
version = "1.0.27"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "7e440fb4e4b4147295338efb76001ab9e4efc0e5839df2c47fc5ac2381d365c3"
dependencies = [
 "ref-cast-impl",
]

[[package]]
name = "ref-cast-impl"
version = "1.0.27"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "92ecd8964f8453721699a1ed72037b0db49ce2f5a5138486ee89bed6f67cdf3a"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 3.0.7",
]

[[package]]
name = "regex"
version = "1.13.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d"
dependencies = [
 "aho-corasick",
 "memchr",
 "regex-automata",
 "regex-syntax",
]

[[package]]
name = "regex-automata"
version = "0.4.18"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2"
dependencies = [
 "aho-corasick",
 "memchr",
 "regex-syntax",
]

[[package]]
name = "regex-syntax"
version = "0.8.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4"

[[package]]
name = "relative-path"
version = "2.0.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f2a073568cd8b9c4825429d3e9fc5f52851b4f97cc1348800689408921e6b8f8"
dependencies = [
 "serde",
]

[[package]]
name = "rquickjs"
version = "0.12.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4e04e4eedfb060b503b5f0a2644abb890b0b3620d3fb674f9455f230014964e4"
dependencies = [
 "rquickjs-core",
 "rquickjs-macro",
]

[[package]]
name = "rquickjs-core"
version = "0.12.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "16e4f499ac5b943d97ee6dbc44f23c2c10426f420f7d2f1793d6318911b6608c"
dependencies = [
 "hashbrown 0.17.1",
 "relative-path",
 "rquickjs-sys",
]

[[package]]
name = "rquickjs-macro"
version = "0.12.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3cbcc8219b70ee2faa08d5339f47f15741cba2ce0cb9640e8495f2ab51293f50"
dependencies = [
 "convert_case",
 "fnv",
 "ident_case",
 "indexmap",
 "proc-macro-crate",
 "proc-macro2",
 "quote",
 "rquickjs-core",
 "syn 2.0.119",
]

[[package]]
name = "rquickjs-serde"
version = "0.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "04cf0aa631f8d0c5051db35f9f59899c34074d7b6be280c03fd4ce6165d0ed35"
dependencies = [
 "rquickjs",
 "serde",
]

[[package]]
name = "rquickjs-sys"
version = "0.12.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a13ac243b86a74120814ef7e9e30ad5a2c1199b7b9963b1cf7c84e4cdc1cad99"
dependencies = [
 "bindgen",
 "cc",
]

[[package]]
name = "rustc-hash"
version = "2.1.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6b1e7f9a428571be2dc5bc0505c13fb6bf936822b894ec87abf8a08a4e51742d"

[[package]]
name = "ryu"
version = "1.0.23"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "9774ba4a74de5f7b1c1451ed6cd5285a32eddb5cccb8cc655a4e50009e06477f"

[[package]]
name = "semver"
version = "1.0.28"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "8a7852d02fc848982e0c167ef163aaff9cd91dc640ba85e263cb1ce46fae51cd"

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
dependencies = [
 "serde_core",
 "serde_derive",
]

[[package]]
name = "serde-transcode"
version = "1.1.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "590c0e25c2a5bb6e85bf5c1bce768ceb86b316e7a01bdf07d2cb4ec2271990e2"
dependencies = [
 "serde",
]

[[package]]
name = "serde_core"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348"
dependencies = [
 "proc-macro2",
 "quote",
 "syn 3.0.7",
]

[[package]]
name = "serde_json"
version = "1.0.151"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14"
dependencies = [
 "itoa",
 "memchr",
 "serde",
 "serde_core",
 "zmij",
]

[[package]]
name = "shlex"
version = "1.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0fda2ff0d084019ba4d7c6f371c95d8fd75ce3524c3cb8fb653a3023f6323e64"

[[package]]
name = "shlex"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba"

[[package]]
name = "simd-json"
version = "0.17.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e32d7ab2678282d21e53374fbead7119b7eacbede73685dcaac472870a29a11c"
dependencies = [
 "halfbrown",
 "ref-cast",
 "serde",
 "serde_json",
 "simdutf8",
 "value-trait",
]

[[package]]
name = "simdutf8"
version = "0.1.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3a9fe34e3e7a50316060351f37187a3f546bce95496156754b601a5fa71b76e"

[[package]]
name = "syn"
version = "2.0.119"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "syn"
version = "3.0.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d62a2e0561533f2ca2561d0cf27fd9fedb640a1bf2616ff5d5c80d99017faadc"
dependencies = [
 "proc-macro2",
 "quote",
 "unicode-ident",
]

[[package]]
name = "toml_datetime"
version = "1.1.2+spec-1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2b86d767906c6c42421dcba507eb9d203e779497710a47782a224bb871653053"
dependencies = [
 "serde_core",
]

[[package]]
name = "toml_edit"
version = "0.25.17+spec-1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e3641d5bbb5349a79e1020a242d251efbc546ad8048d133958323ce9c40a9c9c"
dependencies = [
 "indexmap",
 "toml_datetime",
 "toml_parser",
 "winnow",
]

[[package]]
name = "toml_parser"
version = "1.1.5+spec-1.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "baa693a8032d7e1cada7d0041e96126df243179ff061456783ac7f12bda4744c"
dependencies = [
 "winnow",
]

[[package]]
name = "unicode-ident"
version = "1.0.26"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "d245f478577f809a851594d02313b640fb437e0bb33866753cff937863096954"

[[package]]
name = "unicode-segmentation"
version = "1.13.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c6f5d3c3b1bf09027a88a6bc961fc00497d651009560b5463668dc81b0fa87a8"

[[package]]
name = "value-trait"
version = "0.12.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f3f4b4a98dfe54bc9ed3641af7ffcb837240269627dbd5cb047d13daa39736cc"
dependencies = [
 "float-cmp",
 "halfbrown",
 "itoa",
 "ryu",
]

[[package]]
name = "wasm-encoder"
version = "0.258.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f64765e43c000fae008a48db8b288e175e237fc9ce20a26586836878c1bee89f"
dependencies = [
 "leb128fmt",
 "wasmparser",
]

[[package]]
name = "wasm-metadata"
version = "0.258.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "47e10808eb27efde692f1b1706089fe19296728bf872291f5b4e0d50fba88f2f"
dependencies = [
 "anyhow",
 "indexmap",
 "wasm-encoder",
 "wasmparser",
]

[[package]]
name = "wasmparser"
version = "0.258.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fe9269dd817e0e7021bf534ccd9761bc2d64778b6708e41228b8439d75eaa0b1"
dependencies = [
 "bitflags",
 "hashbrown 0.17.1",
 "indexmap",
 "semver",
]

[[package]]
name = "windows-link"
version = "0.2.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5"

[[package]]
name = "winnow"
version = "1.0.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "23b97319f7b8343df12cc98938e5c3eb436064524c8d2b4e30a1d3a36eecdf81"
dependencies = [
 "memchr",
]

[[package]]
name = "wit-bindgen"
version = "0.61.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "e473fd0095479f9689ac7d2a52c427cc96bb2b973ace50238dfcc1ab1cd52d93"
dependencies = [
 "bitflags",
 "wit-bindgen-rust-macro",
]

[[package]]
name = "wit-bindgen-core"
version = "0.61.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "87445680dfe6d6b5369e884bd63c03a3335268e855365b2fc3f7bcdce96a630e"
dependencies = [
 "anyhow",
 "heck",
 "wit-parser",
]

[[package]]
name = "wit-bindgen-rust"
version = "0.61.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "72f2fe494de0d898216caf0fd0ae76af75753fcb3ff4f465b46131537cf24cf8"
dependencies = [
 "anyhow",
 "heck",
 "indexmap",
 "prettyplease",
 "syn 2.0.119",
 "wasm-metadata",
 "wit-bindgen-core",
 "wit-component",
]

[[package]]
name = "wit-bindgen-rust-macro"
version = "0.61.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "59283a01aec94f60f92ada22ffe182a5cea8acfce43be3be688de8d52df55312"
dependencies = [
 "anyhow",
 "macro-string",
 "prettyplease",
 "proc-macro2",
 "quote",
 "syn 2.0.119",
 "wit-bindgen-core",
 "wit-bindgen-rust",
]

[[package]]
name = "wit-component"
version = "0.258.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "f0fca88950af0c1f42bc77e17315e48798b8d68340171b6d204f62bc19a878a6"
dependencies = [
 "anyhow",
 "bitflags",
 "indexmap",
 "log",
 "serde",
 "serde_derive",
 "serde_json",
 "wasm-encoder",
 "wasm-metadata",
 "wasmparser",
 "wit-parser",
]

[[package]]
name = "wit-parser"
version = "0.258.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "72a2127663dcf3ee16614fb0e3c33d5c6c66fec9dad317a8b0fdd3869487a533"
dependencies = [
 "anyhow",
 "hashbrown 0.17.1",
 "id-arena",
 "indexmap",
 "log",
 "semver",
 "serde",
 "serde_derive",
 "serde_json",
 "unicode-ident",
 "wasmparser",
]

[[package]]
name = "zmij"
version = "1.0.23"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b"
"####,
    ),
    (
        "plugins/Cargo.toml",
        r####"# Test-only Javy plugins for javy-smoke. src/build-scripts/build-javy.sh
# builds them on the host into the assembly's tests/javy and test-wasm.sh
# uploads them; they are part of no image.
[workspace]
members = ["p1", "p2"]
resolver = "3"

[workspace.package]
edition = "2024"
publish = false

[workspace.dependencies]
javy-plugin-api = { version = "=7.1.0", features = ["json"] }

# Upstream Javy's own release profile.
[profile.release]
lto = true
opt-level = 3
"####,
    ),
    (
        "plugins/p1/Cargo.toml",
        r####"[package]
name = "javy-smoke-plugin-p1"
version = "0.0.0"
edition.workspace = true
publish.workspace = true

[lib]
crate-type = ["cdylib"]
test = false

[dependencies]
javy-plugin-api.workspace = true
"####,
    ),
    (
        "plugins/p1/src/lib.rs",
        r####"//! A preview 1 plugin with Javy's optional APIs, QuickJS's `gc()`,
//! `DOMException` and `atob` intrinsics and its string-kind diagnostic hook,
//! and two globals of its own.

use javy_plugin_api::{
    Config, import_namespace,
    javy::{
        Runtime,
        quickjs::{Ctx, Object, Value, prelude::Func, qjs},
    },
};

import_namespace!("javy-smoke-plugin-p1");

fn config() -> Config {
    let mut config = Config::default();
    config
        .event_loop(true)
        .weak_ref(true)
        .performance(true)
        .text_encoding(true)
        .javy_stream_io(true)
        .memory_limit(256 << 20);
    config
}

fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime.context().with(|ctx| {
        // These intrinsics are optional in QuickJS and absent from Javy's context.
        unsafe {
            assert_eq!(qjs::JS_AddIntrinsicDOMException(ctx.as_raw().as_ptr()), 0);
            assert_eq!(qjs::JS_AddIntrinsicAToB(ctx.as_raw().as_ptr()), 0);
        }
        let hooks = Object::new(ctx.clone()).unwrap();
        // QuickJS's run-test262 harness reads the same diagnostic.
        let string_kind = |ctx: Ctx<'_>, value: Value<'_>| {
            let raw = value.as_raw();
            unsafe { qjs::js_std_cmd(3, ctx.as_raw().as_ptr(), &raw) as i32 }
        };
        hooks.set("getStringKind", Func::from(string_kind)).unwrap();
        let globals = ctx.globals();
        globals.set("qjs", hooks).unwrap();
        globals
            .set("gc", Func::from(|ctx: Ctx<'_>| ctx.run_gc()))
            .unwrap();
        globals.set("motorAnswer", Func::from(|| 42_i32)).unwrap();
        globals
            .set("motorGreeting", "hello from a custom plugin")
            .unwrap();
    });
    runtime
}

#[unsafe(export_name = "initialize-runtime")]
fn initialize_runtime() {
    javy_plugin_api::initialize_runtime(config, modify_runtime).unwrap();
}
"####,
    ),
    (
        "plugins/p2/Cargo.toml",
        r####"[package]
name = "javy-smoke-plugin-p2"
version = "0.0.0"
edition.workspace = true
publish.workspace = true

[lib]
crate-type = ["cdylib"]
test = false

[dependencies]
javy-plugin-api.workspace = true
wit-bindgen = "=0.61.1"
"####,
    ),
    (
        "plugins/p2/src/lib.rs",
        r####"//! A preview 2 (component) plugin with two globals of its own.

use javy_plugin_api::{
    Config,
    javy::{Runtime, quickjs::prelude::Func},
    javy_plugin,
};

wit_bindgen::generate!({ world: "javy-smoke-plugin", generate_all });

fn config() -> Config {
    let mut config = Config::default();
    config
        .event_loop(true)
        .text_encoding(true)
        .javy_stream_io(true);
    config
}

fn modify_runtime(runtime: Runtime) -> Runtime {
    runtime.context().with(|ctx| {
        let globals = ctx.globals();
        globals.set("motorAnswer", Func::from(|| 42_i32)).unwrap();
        globals
            .set("motorGreeting", "hello from a custom plugin")
            .unwrap();
    });
    runtime
}

struct Component;

javy_plugin!("javy-smoke-plugin-p2", Component, config, modify_runtime);

export!(Component);
"####,
    ),
    (
        "plugins/p2/wit/world.wit",
        r####"package motor:javy-smoke-plugin@1.0.0;

world javy-smoke-plugin {
    export compile-src: func(src: list<u8>) -> result<list<u8>, string>;
    export initialize-runtime: func();
    export invoke: func(bytecode: list<u8>, function: option<string>);
}
"####,
    ),
];
