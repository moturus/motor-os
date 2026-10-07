(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (func (export "_start"))
  (func (export "exit-zero") i32.const 0 call $exit)
  (func (export "exit-seven") i32.const 7 call $exit)
  (func (export "trap") unreachable)
  (func (export "loop") (loop $again br $again)))
