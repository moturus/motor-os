# Coding tool contracts

These external tools run `gears-batteries tool NAME`, read one JSON object
on stdin, and return the model-facing result on stdout. An unsuccessful
operation writes a diagnostic to stderr and exits nonzero. Gears owns
approval, execution, timeouts and cancellation.

| Tool | Parameters | Result |
| --- | --- | --- |
| `read_file` | required `path`; optional nonnegative byte `offset`, default 0 | Numbered UTF-8 text, about 30 KB per page, the next byte offset and whether all pages of this version have been read. |
| `write_file` | required `path` and `content` | Atomic replacement and a record of the write. An existing file must have been read completely since its last change. UTF-8 BOMs and Windows line endings are preserved. |
| `patch` | required `path`, nonempty `old_text`, and `new_text` | A unique replacement and its diff. Matching tries exact text, trailing spaces, repeated spaces, indentation, then escaped newlines/tabs; ambiguous matches fail. |
| `search_files` | required `pattern`; optional `path`, default `.` | Bounded `rg --json --no-config -e PATTERN -- PATH` output. No-match exit 1 is a normal result. |

Relative file paths start at the selected workspace root. Absolute paths
and `..` can name other user-accessible files, subject to the normal Gears
approval policy. Automatic reading approval covers the workspace only.
Symbolic links are refused. File tools cannot access the Gears directory;
reading the current session's saved tool results is the sole exception.
Those results cannot be rewritten through these tools.

Reading records track byte ranges and the full file's hash. `read_file`
refuses binary and invalid UTF-8 data. The returned next offset avoids
splitting a UTF-8 character and can continue within a very long line.
Read and write records contain paths relative to the selected workspace;
per-session data remains under `batteries/sessions/SESSION/`.
