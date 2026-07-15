#!/usr/bin/env python3
"""Check rush's incremental repaint on a real Motor OS console.

The host pty tests (tests/phase8.rs) make the same claims, but on Linux. This
one makes them where the complaint came from: the Motor console, over a serial
line, through sys-tty. Two things are checked that a host test cannot vouch for:

  * the *bytes*. A keystroke that redraws the whole line reaches the identical
    screen and flickers on the way, because a slow console paints the blank
    before it paints the text back. So the fix is only real if the bytes are
    few, and only the platform can say what actually goes down the wire.
  * the *screen*. Painting only the difference is only correct if the
    differences add up to the right picture, so the whole console stream is
    replayed through a terminal emulator and compared against what a user would
    see.

qemu -nographic puts the guest console on our stdio; running qemu under a pty
makes this script the terminal on the other end.

TRAP: `-nographic` keeps **Ctrl-A for qemu itself** (it is the monitor escape
prefix, as in `Ctrl-A x` to quit). It never reaches the guest, so this script
must not use it: the editor's `^A` is typed as `ESC[H` (Home), which rush maps
to the same thing and qemu passes through. The keys that look ignored are being
eaten one layer above the shell.
"""
import os, pty, select, sys, tempfile, time

COLS = 80
ROWS = 30
# The repo root: this file is at <root>/src/bin/rush/tests/.
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), *[".."] * 4))
LOG = os.path.join(tempfile.gettempdir(), "rush-vm-console-check.log")

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else ""))
    sys.stdout.flush()


class VM:
    def __init__(self, log):
        self.log = open(log, "wb")
        self.buf = b""
        self.answered = 0
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(ROOT)
            os.environ["TERM"] = "xterm"
            os.environ["COLUMNS"] = str(COLS)
            os.execv("./vm_images/debug/run-qemu.sh", ["run-qemu.sh"])
            os._exit(1)
        self.pid, self.fd = pid, fd
        import fcntl, termios, struct
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    def pump(self, seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.buf += chunk
            self.log.write(chunk)
            self.log.flush()
            # Answer a cursor-position report as a terminal would. Matched
            # against the accumulated buffer, not the chunk: a serial console
            # delivers a byte at a time, so `ESC[6n` rarely arrives whole.
            while True:
                i = self.buf.find(b"\x1b[6n", self.answered)
                if i < 0:
                    break
                self.answered = i + 4
                os.write(self.fd, b"\x1b[%d;%dR" % (1, COLS))
        return self.buf

    def wait_for(self, needle, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.5)
            if needle.encode() in self.buf:
                return True
        return False

    def mark(self):
        """A point to measure the next paint from."""
        return len(self.buf)

    def since(self, m):
        """What the shell wrote after `mark()` -- one paint's worth of bytes."""
        return self.buf[m:].decode("utf-8", "replace")

    def rows(self):
        """The screen, from the whole session -- boot noise and all.

        Replaying only the newest bytes would start the grid mid-line with no
        prompt on it. A terminal has no such option, and neither has this.
        """
        return screen(self.text())

    def send(self, data, settle=0.6):
        if isinstance(data, str):
            data = data.encode()
        os.write(self.fd, data)
        self.pump(settle)

    def clear(self):
        self.buf = b""
        self.answered = 0

    def text(self):
        return self.buf.decode("utf-8", "replace")

    def kill(self):
        try:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
        except Exception:
            pass


def cells(c):
    o = ord(c)
    if (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF or 0xAC00 <= o <= 0xD7A3
            or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFF60
            or 0x1F300 <= o <= 0x1F64F or 0x20000 <= o <= 0x3FFFD):
        return 2
    return 1


def screen(s, cols=COLS):
    """Replay `s` onto a grid and return the rows — what the user would see.

    The same small emulator as the host tests', in the same vocabulary: enough
    CSI to follow the editor's repaints and no more.
    """
    grid, row, col = [[" "] * cols], 0, 0

    def put(r, c, ch):
        while len(grid) <= r:
            grid.append([" "] * cols)
        if c < cols:
            grid[r][c] = ch

    i = 0
    while i < len(s):
        ch = s[i]
        i += 1
        if ch == "\r":
            col = 0
        elif ch == "\n":
            row += 1
            while len(grid) <= row:
                grid.append([" "] * cols)
        elif ch == "\x07":
            pass
        elif ch == "\x1b":
            if i < len(s) and s[i] == "[":
                i += 1
                params = ""
                final = " "
                while i < len(s):
                    f = s[i]
                    i += 1
                    if "\x40" <= f <= "\x7e":
                        final = f
                        break
                    params += f
                n = params.lstrip("?").split(";")[0]
                n = int(n) if n.isdigit() else 1
                if final == "A":
                    row = max(0, row - n)
                elif final == "B":
                    row += n
                elif final == "C":
                    col += n
                elif final == "D":
                    col = max(0, col - n)
                elif final == "H":
                    row, col = 0, 0
                elif final == "K":
                    while len(grid) <= row:
                        grid.append([" "] * cols)
                    for x in range(col, cols):
                        grid[row][x] = " "
                elif final == "J":
                    grid, row, col = [[" "] * cols], 0, 0
            elif i < len(s) and s[i] == "]":
                while i < len(s) and s[i] != "\x07":
                    i += 1
                i += 1
        else:
            w = cells(ch)
            if col + w > cols:
                row += 1
                col = 0
            put(row, col, ch)
            for x in range(1, w):
                put(row, col + x, "\0")
            col += w
    rows = ["".join(c for c in r if c != "\0").rstrip() for r in grid]
    while rows and rows[-1] == "":
        rows.pop()
    return rows


def prompt_line(rows):
    for r in reversed(rows):
        if r.startswith("$ ") or r == "$":
            return r
    return ""


if __name__ == "__main__":
    vm = VM(LOG)
    # Wait for a painted *prompt*, not for the boot line that mentions rush by
    # name: "Starting /bin/rush." goes by well before there is a shell to type
    # at, and keys sent to a booting console are simply dropped. The login
    # shell's prompt is a coloured "rush:/$ ", so the end of a prompt paint is
    # what identifies one.
    if not vm.wait_for("$ \x1b[?25h", 150):
        print("FAIL: never reached a rush prompt")
        vm.kill()
        sys.exit(1)
    print("booted to a rush prompt")

    # A nested interactive rush with a known prompt: the login shell's own is
    # "rush:<cwd>$ ", which would make these checks about $PWD rather than about
    # the editor. It is the same editor on the same console either way.
    vm.send("PS1='$ ' /bin/rush -i\r", settle=0.2)
    if not vm.wait_for("\r\x1b[0K$ \x1b[?25h", 30):
        print("FAIL: the nested rush never prompted")
        vm.kill()
        sys.exit(1)
    print("nested rush with a plain prompt is up")
    # Let its startup stop talking. This is a debug image: motor-fs logs every
    # stat to this same console, and those lines land wherever the cursor is —
    # i.e. on the prompt row, under the editor's feet. No shell can defend
    # against another writer on its terminal; the tests just have to wait it out
    # and then take a clean row.
    vm.pump(3.0)

    def settle():
        """Abandon the line and take a fresh prompt on a clean row.

        `^U` alone would leave the prompt where it is — which may be a row some
        FS debug line has already scribbled on. Enter puts the next prompt on a
        row of its own, below the noise.
        """
        vm.send("\x15", settle=0.3)  # ^U: abandon whatever is on the line
        vm.send("\r", settle=0.8)    # a blank line runs nothing, and reprompts

    # ---- the editor is running at all ----
    settle()
    vm.send("echo hi")
    check("editor-echoes", "$ echo hi" == prompt_line(vm.rows()),
          repr(prompt_line(vm.rows())))
    settle()

    # ---- one press of Enter is one Enter ----
    # This console sends CRLF for one keypress. Counting both halves ran the
    # line and then a blank one after it, so every command left two prompts.
    # rush writes exactly one prompt per line it reads, so the prompts are the
    # count. Only the console can catch this: a pty sends a bare CR.
    m = vm.mark()
    vm.send("\r", settle=1.2)
    check("one-enter-one-prompt", vm.since(m).count("$ \x1b[?25h") == 1,
          f"{vm.since(m).count('$ \x1b[?25h')} prompts for one Enter")

    # ---- nothing that moves the cursor across the screen does it in public ----
    # The width probe throws the cursor at the right-hand edge, and the
    # partial-line marker walks it the full width of the row -- both once per
    # prompt. Visible, that is a cursor flickering across the screen after every
    # command.
    out = vm.since(m)
    for name, seq in [("probe", "\x1b[999C"), ("marker", "\x1b[7m%")]:
        i = out.find(seq)
        # Hidden means: the nearest cursor-visibility escape *before* it hides.
        before = out[:i]
        check(f"{name}-hides-the-cursor",
              i > 0 and before.rfind("\x1b[?25l") > before.rfind("\x1b[?25h"),
              repr(out[max(0, i - 12):i + 12]))

    # ---- what a keystroke costs: the whole point of the change ----
    vm.send("echo")
    m = vm.mark()
    vm.send("x")
    out = vm.since(m)
    # Exactly the character. Anything else is redrawing what is already there.
    check("append-costs-one-byte", out == "x", repr(out))

    m = vm.mark()
    vm.send("\x1b[D")  # Left
    out = vm.since(m)
    check("cursor-move-draws-no-text", "echo" not in out, repr(out))
    check("cursor-move-is-small", len(out) < 8, f"{len(out)} bytes: {out!r}")

    m = vm.mark()
    vm.send("\x7f")  # Backspace
    out = vm.since(m)
    check("backspace-no-repaint", "echo" not in out, repr(out))

    vm.send("\x1b[H")  # Home (not ^A: see the trap at the top)
    m = vm.mark()
    vm.send("X")
    out = vm.since(m)
    check("middle-edit-redraws-tail", "Xech" in out, repr(out))
    check("middle-edit-keeps-prompt", "$" not in out, repr(out))
    check("middle-edit-screen", prompt_line(vm.rows()) == "$ Xechx",
          repr(prompt_line(vm.rows())))

    # ---- and the picture all those differences add up to ----
    settle()
    vm.send("echo abc")
    vm.send("\x1b[H")                            # Home
    vm.send("\x1b[C\x1b[C\x1b[C\x1b[C\x1b[C")  # Right x5
    vm.send("Z")                                 # "echo Zabc"
    vm.send("\x05")                              # ^E: to the end
    vm.send("\x7f")                              # Backspace: "echo Zab"
    check("screen-after-edits", prompt_line(vm.rows()) == "$ echo Zab",
          repr(prompt_line(vm.rows())))
    vm.send("\r", settle=1.2)
    # The command's own output, on a row of its own -- not the echo of the line
    # that was typed, which says "$ echo Zab".
    check("it-runs", "Zab" in vm.rows()[-4:], repr(vm.rows()[-4:]))

    # ---- a line that wraps, painted a character at a time ----
    settle()
    long_line = "echo " + "a" * 90
    m = vm.mark()
    vm.send(long_line, settle=2.0)
    full = "$ " + long_line
    rows = vm.rows()
    check("wrapped-line-row0", rows[-2] == full[:COLS], repr(rows[-2]))
    check("wrapped-line-row1", rows[-1] == full[COLS:], repr(rows[-1]))
    # 95 characters typed; a full repaint per keystroke would be ~100x that.
    cost = len(vm.since(m))
    check("wrapping-line-is-cheap", cost < 3 * len(long_line),
          f"{cost} bytes to type {len(long_line)} characters")

    # The other half of drawing only the difference: what the old line put on
    # the screen and the new one does not reach has to be erased.
    vm.send("\x1b[H\x0b", settle=1.0)  # Home, then ^K
    check("kill-takes-the-wrapped-row", vm.rows()[-1] == "$", repr(vm.rows()[-2:]))

    # ---- history: the whole line changes at once ----
    vm.send("echo one\r", settle=1.2)
    vm.send("echo two\r", settle=1.2)
    vm.send("\x1b[A", settle=0.8)
    check("history-up", prompt_line(vm.rows()) == "$ echo two",
          repr(prompt_line(vm.rows())))
    vm.send("\x1b[A", settle=0.8)
    check("history-up-again", prompt_line(vm.rows()) == "$ echo one",
          repr(prompt_line(vm.rows())))
    vm.send("\x1b[B\x1b[B", settle=0.8)
    check("history-down-to-empty", prompt_line(vm.rows()) == "$",
          repr(prompt_line(vm.rows())))

    # ---- completion still lands ----
    # Last: on a debug image the FS logs every stat to this same console, and
    # completion stats the whole of $PATH. That noise scrolls the screen out
    # from under the editor, so nothing after it can be trusted.
    # Completion stats the whole of $PATH, and on a debug image every one of
    # those stats is a log line on this console -- so neither the screen nor the
    # bytes around the Tab can be read cleanly. Run the completed command
    # instead and look for its output: if the Tab did not turn "ec" into
    # "echo ", the line is "ecRUSHTAB" and nothing echoes it back.
    settle()
    vm.send("ec\t", settle=1.5)
    vm.send("RUSHTAB\r", settle=1.5)
    check("tab-completes", "RUSHTAB" in vm.rows()[-4:], repr(vm.rows()[-4:]))
    vm.send("\x03")  # ^C

    print()
    print(f"vm-console-check: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    vm.kill()
    sys.exit(1 if FAIL else 0)
