;; One guest memory against the installed runner's 96 MiB (1536 page) limit.
;; Failed checks exit with distinct statuses.
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory 0)
  (func (export "grow-to-limit")
    (if (i32.ne (memory.grow (i32.const 1536)) (i32.const 0))
      (then (call $exit (i32.const 2))))
    (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1))
      (then (call $exit (i32.const 3))))
    (if (i32.ne (memory.size) (i32.const 1536))
      (then (call $exit (i32.const 4))))
    (if (i32.or (i32.load8_u (i32.const 0)) (i32.load8_u (i32.const 100663295)))
      (then (call $exit (i32.const 5)))))
  ;; Writes every 4 KiB page of the full memory, faulting in 96 MiB.
  (func (export "touch") (local $offset i32)
    (if (i32.ne (memory.grow (i32.const 1536)) (i32.const 0))
      (then (call $exit (i32.const 2))))
    (loop $pages
      (i32.store8 (local.get $offset) (i32.const 1))
      (local.set $offset (i32.add (local.get $offset) (i32.const 4096)))
      (br_if $pages (i32.lt_u (local.get $offset) (i32.const 100663296))))))
