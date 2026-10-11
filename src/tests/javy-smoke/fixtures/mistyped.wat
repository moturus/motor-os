;; fd_write declared with the wrong type: the runner must refuse to instantiate.
(module
  (import "wasi_snapshot_preview1" "fd_write" (func (param i64 i64 i64 i64) (result i32)))
  (func (export "_start")))
