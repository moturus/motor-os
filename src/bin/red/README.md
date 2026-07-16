# red - A Vim-like Terminal Editor in Pure Rust (`std`)

**red** is a lightweight, high-performance, terminal-based text editor written in Rust. It behaves like `vi`/`vim` and is built **entirely from scratch using only the Rust standard library (`std`)**, with absolutely zero external crate dependencies.

---

## Core Architectural Highlights

*   **Zero Dependencies**: Written without crates like `crossterm`, `termion`, `libc`, or `nix`. It is powered entirely by raw, standard ANSI/ASCII escape sequences.
*   **Cell-Level Frame Diffing**:
    *   Every cycle, the editor renders the whole screen into an in-memory grid of `Cell`s (each cell is a character plus a self-contained SGR style sequence) and diffs it against the previously drawn frame.
    *   Only the columns that actually changed are repainted: typing rewrites just the edited line from the first divergent column onward, and a cursor move rewrites only the digits of the cursor readout in the status bar — the text area is never touched.
    *   The cursor is hidden only while cells are actually being repainted, so it never visibly skips around, and the entire update is flushed as a single batched write.
    *   A full clear-and-repaint happens only when the row count changes (first paint or a terminal resize), so a stable window never flickers.
*   **Dynamic Terminal Resizing (Pure ANSI Query)**:
    *   Queries terminal size on resize events using a pure ANSI escape sequence query (`\x1b[9999;9999H\x1b[6n`) that moves the cursor to the bottom-right and queries its coordinates.
    *   Performs this query invisibly (hiding the cursor during the check to prevent flashing) and only when handling events (0% CPU idle overhead).
    *   The editor viewport scales and re-layouts in real-time.
*   **Zero-Dependency Raw Mode & Timeout Hack**:
    *   Configures the terminal driver using the system `stty` utility (`stty raw -echo min 0 time 1`).
    *   The `min 0 time 1` configuration makes read operations non-blocking with a 100ms timeout, allowing synchronous parsing of multi-byte escape sequences (like Arrow keys or Page keys) without blocking on a standalone `Esc` keypress.
*   **Terminal Guard & Alt-Screen Buffer**:
    *   Uses a `TerminalGuard` implementing the `Drop` trait alongside a custom panic hook to guarantee that the terminal is *always* safely restored to normal cooked mode (`stty -raw echo`), even if the editor crashes or panics.
    *   Launches in the terminal's Alternate Screen Buffer (`\x1b[?1049h`), leaving the user's terminal scrollback history perfectly clean upon exit.
*   **UTF-8 & Tab rendering**:
    *   Fully decodes multi-byte UTF-8 characters from raw stdin bytes.
    *   Converts tabs (`\t`) to dynamic tab stops (`tabstop` columns wide, see [Configuration](#configuration)) during screen rendering, while preserving raw tab characters in the buffer.

---

## Feature & Command Reference

### 1. Modes
Like Vim, **red** operates in five distinct modes:
*   **NORMAL Mode**: Used for navigation and buffer manipulation (default on startup).
*   **INSERT Mode**: Used for typing text.
*   **VISUAL Mode (`v`)**: Used for character-wise text highlighting and selection.
*   **VISUAL LINE Mode (`V`)**: Used for line-wise text highlighting and selection.
*   **COMMAND Mode (`:`)**: Used for executing editor commands (saving, quitting).

---

### 2. NORMAL Mode Commands

| Key / Command | Action |
| :--- | :--- |
| **Mode Transitions** | |
| `i` | Enter **INSERT Mode** at the cursor |
| `a` | Enter **INSERT Mode** after the cursor (append) |
| `:` | Enter **COMMAND Mode** |
| `v` | Enter **VISUAL Mode** (character-wise selection) |
| `V` | Enter **VISUAL LINE Mode** (line-wise selection) |
| **Cursor Navigation** | |
| `h` | Move cursor Left |
| `l` | Move cursor Right |
| `k` / `↑` | Move cursor Up |
| `j` / `↓` | Move cursor Down |
| `←` / `→` | Switch to the previous / next buffer (Normal Mode only; arrows navigate cursor in Insert/Visual modes) |
| `0` (zero) | Move cursor to the absolute start of the line |
| `$` | Move cursor to the end of the line |
| `g` | Go to the very first line of the file |
| `G` | Go to the very last line of the file |
| **Page Scrolling** | |
| `Ctrl-F` / `PageDown` | Scroll down one full page (viewport height) |
| `Ctrl-B` / `PageUp` | Scroll up one full page (viewport height) |
| **Search Navigation** | |
| `/` | Enter **SEARCH Mode** (type a query and press Enter to search forward) |
| `?` | Enter **SEARCH Mode** (type a query and press Enter to search backward) |
| `n` | Jump to the next match in the search direction (wraps around) |
| `N` | Jump to the previous match in the opposite search direction (wraps around) |
| **Editing / Clipboard** | |
| `x` / `Delete` | Delete the character under the cursor |
| `o` | Open a new line *below* the cursor and enter INSERT Mode |
| `O` | Open a new line *above* the cursor and enter INSERT Mode |
| `p` | Paste yanked/deleted selection after (or below) the cursor |
| `J` | Join the current line with the line below it, normalizing spaces |

---

### 3. INSERT Mode Commands

| Key | Action |
| :--- | :--- |
| `Esc` | Return to **NORMAL Mode** |
| `Char` (any character) | Insert character at the cursor position |
| `Backspace` | Delete character before the cursor; merges lines if at the start of a line |
| `Delete` | Delete character under the cursor; merges next line if at the end of a line |
| `Enter` | Split the current line at the cursor and move to the next line |
| `Tab` | Indent to the next tab stop: spaces if `expandtab` is set, otherwise a tab character (`\t`) |
| `←` / `→` / `↑` / `↓` | Navigate cursor Left / Right / Up / Down |

---

### 4. COMMAND Mode (`:`) Commands

| Command | Action |
| :--- | :--- |
| `Esc` | Cancel command buffer and return to **NORMAL Mode** |
| `:w` | Save buffer to the current file |
| `:w <filename>` | Save buffer to a new file |
| `:q` | Quit the editor (fails if any loaded buffer has unsaved changes) |
| `:q!` | Force quit the editor (discards unsaved changes) |
| `:wq` or `:x` | Save current file and quit |
| `:<number>` | Jump directly to line `<number>` (e.g. `:10` jumps to line 10, clamps to buffer bounds) |
| `:set nu` or `:set number` | Enable line numbering (displays dynamic line numbers; enabled by default) |
| `:set nonu` or `:set nonumber` | Disable line numbering |
| `:set wrap` | Enable soft line wrapping (default; wraps long lines visually to fit the screen) |
| `:set nowrap` | Disable soft line wrapping (scrolls horizontally instead) |
| `:ls` or `:buffers` | List all loaded buffers (marks active buffer with `%` and unsaved changes with `+`) |
| `:bn` or `:bnext` | Switch to the next buffer (fails if current is modified) |
| `:bn!` or `:bnext!` | Force switch to the next buffer |
| `:bp` or `:bprev` | Switch to the previous buffer (fails if current is modified) |
| `:bp!` or `:bprev!` | Force switch to the previous buffer |
| `:b <id>` / `:b! <id>` | (Force) switch to buffer by numerical ID (e.g. `:b 2`) |
| `:b <name>` / `:b! <name>` | (Force) switch to buffer by matching filename fragment (e.g. `:b main`) |
| `:bd` or `:bdelete` | Close/delete the current buffer (fails if modified) |
| `:bd!` or `:bdelete!` | Force close/delete the current buffer, discarding changes |
| `:e <file>` or `:edit <file>` | Load and open a new file in a new buffer, switching to it (prevents duplicates) |

---

### 5. VISUAL and VISUAL LINE Mode Commands

| Key / Command | Action |
| :--- | :--- |
| `Esc` | Cancel highlight selection and return to **NORMAL Mode** |
| `y` | Yank (copy) highlighted selection into the clipboard and return to **NORMAL Mode** |
| `d` / `x` / `Delete` | Delete (cut) highlighted selection into the clipboard and return to **NORMAL Mode** |
| **Selection Expansion** | Use standard NORMAL Mode motions (`h`/`j`/`k`/`l`, `0`/`$`, `g`/`G`, page scrolls, arrows) to expand selection from the anchor |

---

## Project Module Structure

The project has been refactored into a highly clean and modular structure:
*   `src/main.rs`: The application entrypoint. Declares modules, instantiates the `TerminalGuard`, and runs the primary interactive event loop.
*   `src/terminal.rs`: Contains the `TerminalGuard` drop-restoration logic, panic hook, and raw mode command triggers. Exposes the pure ANSI-based `get_terminal_size()` size query engine.
*   `src/input.rs`: Contains the raw byte reader and escape sequence parser. Converts stdin into semantic `Key` events and decodes UTF-8.
*   `src/buffer.rs`: Defines the `Line` struct wrapping a `Vec<char>` for safe, indexable UTF-8 editing.
*   `src/editor.rs`: The heart of the editor. Manages state, handles keypress processing for all modes, calculates scroll offsets, and implements the highly optimized viewport rendering engine. Also houses the core unit tests.
*   `src/syntax/`: Contains the language-specific tokenizer engines and the unified `SyntaxManager`.

---

## Configuration

On startup **red** reads an optional config file:

| Platform | Location |
| :--- | :--- |
| Motor OS | `/user/cfg/red.toml` |
| Unix | `$HOME/.config/red.toml` |

The file is not required — without one, red uses the defaults below. Options are named after their vim equivalents, and the vim short names work too:

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `tabstop` (`ts`) | `4` | Width of a tab character, in columns (must be 1-32) |
| `expandtab` (`et`) | `true` | Insert spaces up to the next tab stop when Tab is pressed, instead of a tab character |

```toml
tabstop = 4
expandtab = true
```

Only the `key = value` subset of TOML is understood (plus `#` comments) — red has no dependencies, so there is no TOML crate behind this. A malformed entry is skipped and reported in the status bar; the rest of the file still applies.

---

## Syntax Highlighting

**red** comes with a high-performance, zero-dependency, **State-Cascading Incremental Syntax Highlighting** engine!

*   **Incremental Highlighting**: Only tokenizes and highlights the **currently edited line** when typing, keeping input latency virtually zero.
*   **State-Cascading**: For block structures (like multi-line `/* ... */` comments in Rust), each line maintains a lexer state at its end. If an edit changes a line's ending state, the highlighter cascades the calculations down subsequent lines, stopping immediately when the state stabilizes.
*   **Languages Supported**:
    *   **Rust (`.rs`)**: Highlights keywords, common types, string/char literals, single & block comments, numbers, and macros.
    *   **Bash (`.sh`, `.bash`)**: Highlights shell keywords, variables (e.g. `$VAR`, `${VAR}`), string literals, shebang preprocessors (`#!/bin/bash`), numbers, and comments (`#`).
    *   **C / C++ (`.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`, ...)**: Highlights C and C++ keywords and types, preprocessor directives (`#include`, `#define`, ...) with `<header>` includes, string/char literals, single & multi-line block comments, numbers (hex/float/suffixes), and macro-style `UPPER_CASE` constants.
    *   **TOML (`.toml`)**: Highlights section headers (`[section]`), keys, string literals, numbers, booleans (`true`/`false`), and comments (`#`).
*   **Seamless Selection Blending**: Integrates beautifully with **Visual Mode** highlights, ensuring highlighted text remains legible and inverted.

---

## Unit Testing

We maintain a comprehensive suite of unit tests verifying all core buffer modifications, cursor boundaries, page scrolling, line splitting, line merging, and mode transitions completely independently of terminal I/O.

Run the tests using Cargo:
```bash
cargo test
```

---

## How to Build and Run

1.  **Build the project**:
    ```bash
    cargo build --release
    ```
2.  **Run the editor**:
    *   Open a new empty buffer:
        ```bash
        cargo run
        ```
    *   Open or edit an existing file:
        ```bash
        cargo run -- <filename>
        ```