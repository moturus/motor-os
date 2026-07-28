#!/usr/bin/env python3
"""Check rmux on a real Motor OS console (details.md §9.4).

tests/host.rs makes most of these claims already, but on Linux, where a pane is
a pty and the console is one too. This one makes them where rmux is meant to
live: the Motor serial console, through sys-tty, where a pane is a *pipe* and
the console rewrites some of what is written to it (§3.3). Four things only
this can vouch for:

  * **Enter arrives as CRLF.** sys-tty synthesizes a newline after every CR
    (§3.4), so one keypress is two bytes; a pty sends a bare CR and cannot see
    the difference between a multiplexer that coalesces them and one that runs
    the line twice.
  * **A pane has no line discipline.** Nothing turns a program's `\\n` into a
    new line on Motor, so a pane must do it itself (§3.1, M7's staircase).
  * **What a paint costs**, on the console the cost is *for*: sys-tty reads
    rmux's output in 80-byte chunks and spins a polled UART one byte at a time
    (§6.3), which is why the frame diff is the feature and not an optimization.
  * **What a pane's program survives.** A real Motor program on a real pipe,
    with a console changing size under it (M11): a pty would have a `SIGWINCH`
    to deliver, and this has nothing but the bytes rmux chooses to write.

qemu -nographic puts the guest console on our stdio, and running qemu under a
pty makes this script the terminal on the other end.

TRAP: `-nographic` keeps **Ctrl-A for qemu itself** -- and `C-a` is rmux's
prefix (§2.1), so the two collide. `run-qemu-echr.sh` is the run script that
moves qemu's escape to Ctrl-T (`-echr 0x14`), which is why this harness uses it
and rush's does not (§9.4).

TRAP, measured: **use a release image.** A debug one logs sys-io's every TCP
message to this same console -- and rmux's client and server talk over loopback
TCP (§4.2), so using rmux is what produces the flood. Those lines land wherever
the cursor is, on top of a composited screen the frame diff will never repair,
and they bury the byte costs entirely: the keystroke measured below cost 1 byte
on a release image and 1893 on a debug one. This is the same shape as §3.5's
`^C` echo -- another writer on rmux's terminal -- and not something rmux can
defend against.

Not wired into src/tests/full-test.sh, and deliberately: it boots a VM of its
own, and that suite already has one. Run it by hand:

    src/bin/rmux/tests/vm-console-check.py [release|debug]
"""
import fcntl, os, pty, select, struct, sys, tempfile, termios, time

COLS = 80
ROWS = 30
# What rmux writes to ask the console how big it is, once a second (§3.2), and
# the same string as `keys::SIZE_REPROBE`. It is a question rather than a paint,
# so the byte costs below discount it.
SIZE_REPROBE = "\x1b7\x1b[9999;9999H\x1b[6n\x1b8"
# The repo root: this file is at <root>/src/bin/rmux/tests/.
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), *[".."] * 4))
BUILD = sys.argv[1] if len(sys.argv) > 1 else "release"
LOG = os.path.join(tempfile.gettempdir(), "rmux-vm-console-check.log")

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
        # What this terminal says when it is asked how big it is. A window the
        # user drags is a terminal that starts answering differently, and that
        # is the only way the guest can find out (§3.2).
        self.size = (ROWS, COLS)
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(ROOT)
            os.environ["TERM"] = "xterm"
            os.environ["COLUMNS"] = str(COLS)
            script = f"./vm_images/{BUILD}/run-qemu-echr.sh"
            os.execv(script, [os.path.basename(script)])
            os._exit(1)
        self.pid, self.fd = pid, fd
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
            # Answer a cursor-position report as a terminal would -- with the
            # bottom-right corner, because the question was asked after a
            # `ESC[9999;9999H` and a terminal clamps (§3.2). rmux takes the
            # answer as its console size, so this is where its geometry comes
            # from; matched against the whole buffer, since a serial console
            # splits the sequence across reads (§8.3).
            while True:
                i = self.buf.find(b"\x1b[6n", self.answered)
                if i < 0:
                    break
                self.answered = i + 4
                os.write(self.fd, b"\x1b[%d;%dR" % self.size)
        return self.buf

    def wait_for(self, needle, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.5)
            if needle.encode() in self.buf:
                return True
        return False

    def wait_painted(self, needle, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.5)
            if any(needle in row for row in self.rows()):
                return True
        return False

    def mark(self):
        """A point to measure the next paint from."""
        return len(self.buf)

    def since(self, m):
        return self.buf[m:].decode("utf-8", "replace")

    def rows(self):
        return screen(self.text())

    def send(self, data, settle=0.8):
        if isinstance(data, str):
            data = data.encode()
        os.write(self.fd, data)
        self.pump(settle)

    def text(self):
        return self.buf.decode("utf-8", "replace")

    def kill(self):
        try:
            os.kill(self.pid, 9)
            os.waitpid(self.pid, 0)
        except Exception:
            pass


def screen(s, rows=ROWS, cols=COLS):
    """Replay `s` onto a grid and return the rows -- what the user would see.

    Enough of a terminal to follow rmux, which is less than it sounds: every
    cell is placed with an absolute `ESC[{row};{col}H` (§3.3, §6.2), so this
    needs CUP, the two erases, and the alternate screen. Styling is dropped --
    the claims here are about the picture and the bytes, not the colours.
    """
    grid = [[" "] * cols for _ in range(rows)]
    row = col = 0
    saved = (0, 0)

    def clear():
        nonlocal grid, row, col
        grid = [[" "] * cols for _ in range(rows)]
        row = col = 0

    i = 0
    while i < len(s):
        ch = s[i]
        i += 1
        if ch == "\r":
            col = 0
        elif ch == "\n":
            row = min(row + 1, rows - 1)
        elif ch == "\b":
            col = max(0, col - 1)
        elif ch == "\x1b":
            if i < len(s) and s[i] == "[":
                i += 1
                params = ""
                final = ""
                while i < len(s):
                    f = s[i]
                    i += 1
                    if "\x40" <= f <= "\x7e":
                        final = f
                        break
                    params += f
                private = params.startswith("?")
                nums = [int(p) if p.isdigit() else 0 for p in params.lstrip("?").split(";")]
                first = nums[0] if nums else 0
                if final == "H" or final == "f":
                    row = min(max((nums[0] if nums else 1) - 1, 0), rows - 1)
                    col = min(max((nums[1] if len(nums) > 1 else 1) - 1, 0), cols - 1)
                elif final == "A":
                    row = max(0, row - max(first, 1))
                elif final == "B":
                    row = min(rows - 1, row + max(first, 1))
                elif final == "C":
                    col = min(cols - 1, col + max(first, 1))
                elif final == "D":
                    col = max(0, col - max(first, 1))
                elif final == "K":
                    span = range(col, cols) if first == 0 else (
                        range(0, col + 1) if first == 1 else range(0, cols))
                    for x in span:
                        grid[row][x] = " "
                elif final == "J":
                    # Every mode, since only the whole-screen one is common and
                    # the others are how a program that scrolled tidies up.
                    clear() if first == 2 else None
                    if first == 0:
                        for x in range(col, cols):
                            grid[row][x] = " "
                        for y in range(row + 1, rows):
                            grid[y] = [" "] * cols
                    elif first == 1:
                        for y in range(0, row):
                            grid[y] = [" "] * cols
                        for x in range(0, col + 1):
                            grid[row][x] = " "
                elif final in ("h", "l") and private and first in (1049, 47, 1047):
                    # The alternate screen is a fresh one either way (§5.3), and
                    # entering it is what separates rmux's picture from the boot
                    # noise above it.
                    clear()
            elif i < len(s) and s[i] == "]":
                while i < len(s) and s[i] not in ("\x07", "\x1b"):
                    i += 1
                i += 1
            elif i < len(s) and s[i] in ("7", "8"):
                # DECSC/DECRC, which the size probe uses to ask without moving
                # the cursor anywhere the user can see (`keys::SIZE_REPROBE`).
                if s[i] == "7":
                    saved = (row, col)
                else:
                    row, col = saved
                i += 1
            else:
                i += 1
        elif ch >= " ":
            if col >= cols:
                row, col = min(row + 1, rows - 1), 0
            grid[row][col] = ch
            col += 1
    return ["".join(r).rstrip() for r in grid]


def painted(vm, needle):
    return any(needle in row for row in vm.rows())


def rows_with(vm, needle):
    return [at for at, row in enumerate(vm.rows()) if needle in row]


if __name__ == "__main__":
    vm = VM(LOG)
    # The login shell's prompt, painted: "Starting /bin/rush." goes by long
    # before there is anything to type at, and keys sent to a booting console
    # are dropped.
    if not vm.wait_for("$ \x1b[?25h", 150):
        print("FAIL: never reached a rush prompt")
        vm.kill()
        sys.exit(1)
    print(f"booted a {BUILD} image to a rush prompt")
    # A debug image logs filesystem work to this same console, and those lines
    # land wherever the cursor is -- under rmux's composited screen, where the
    # frame diff will never repair them. Let the boot stop talking first.
    vm.pump(3.0)

    # ---- rmux runs on the real console at all ----
    # Start from a known rendezvous. The disk is real and survives a reboot, so
    # a port file outlives the server it names whenever this qemu is killed
    # rather than shut down -- and the client that finds it waits five seconds
    # on a port nobody is listening on, says so, and removes it (§4.2). That is
    # the right behaviour and a bad start for a harness, whose first `rmux`
    # would then be the one paying for the last run.
    # Motor's `rm` is `rm [-r] $FILE`: one file, no `-f`, and it complains about
    # one that is not there. Both of those are fine here.
    vm.send("/bin/rm /sys/tmp/rmux.port\r", settle=1.0)
    vm.send("/bin/rm /sys/tmp/rmux.lock\r", settle=1.0)
    vm.send("PS1='$ ' /bin/rmux\r", settle=3.0)
    check("rmux-starts", painted(vm, "[0] "), repr(vm.rows()[-1]))
    check("status-line-is-the-last-row", painted(vm, "[0] ") and "[0] " in vm.rows()[ROWS - 1],
          repr(vm.rows()[ROWS - 1]))
    if not vm.wait_painted("$", 20):
        print("FAIL: the pane never reached a prompt")
        vm.kill()
        sys.exit(1)

    # ---- Enter is one Enter (§3.4) ----
    # sys-tty writes CR *and* LF for one keypress. Counting both halves runs the
    # line and then a blank one after it, so every command would leave two
    # prompts; the composited screen is where that shows up as a gap.
    before = len(rows_with(vm, "$"))
    vm.send("echo o''ne\r", settle=1.5)
    check("pane-runs-a-command", painted(vm, "one"), repr(vm.rows()[:6]))
    after = len(rows_with(vm, "$"))
    check("one-enter-one-prompt", after == before + 1,
          f"{after - before} prompts for one Enter: {vm.rows()[:6]}")

    # ---- a pane turns \n into a new line itself (§3.1) ----
    # Motor has no line discipline and a pane is a pipe, so nothing but the pane
    # stands between a program's `\n` and the grid. Without it the second line
    # starts where the first ended -- M7's staircase, which no host test can see
    # because a pty's ONLCR has already done the work.
    vm.send("echo a''aa; echo b''bb\r", settle=1.5)
    starts = [row for row in vm.rows() if row.startswith("aaa") or row.startswith("bbb")]
    check("newline-starts-a-new-line", len(starts) == 2, repr(vm.rows()[:8]))

    # ---- what a keystroke costs, on the console the cost is for (§6.3) ----
    # The keystroke before it is not ceremony: the status line is reverse video,
    # so a frame ending on it leaves the console in that style and the next cell
    # painted in a pane pays for `ESC[0m` as well (tests/host.rs learned this).
    vm.send("e", settle=1.0)
    m = vm.mark()
    vm.send("x", settle=1.0)
    # The probe is not a paint, and this is a claim about paints. rmux asks the
    # console its size once a second (§3.2) because nothing tells it when a
    # window is dragged, so a second of settling holds one asking; it is
    # discounted here rather than counted, and named so that a *changed* probe
    # shows up as a failure rather than being quietly absorbed.
    out = vm.since(m).replace(SIZE_REPROBE, "")
    check("keystroke-costs-one-byte", out == "x", f"{len(out)} bytes: {out!r}")
    vm.send("\x15", settle=0.8)  # ^U: abandon the line

    # ---- a split, and a pane that knows how wide it is (§3.2) ----
    # `C-a |` arrives at all only because qemu's escape has been moved out of
    # the way (§9.4). A pane is born the size of its box (M7), and $COLUMNS is
    # how the shell in it was told -- the half of §3.2 that Motor has instead of
    # an ioctl.
    vm.send("\x01|", settle=2.0)
    border = [row for row in vm.rows() if "|" in row]
    check("split-draws-a-border", len(border) > 3, repr(vm.rows()[:4]))
    vm.send("echo [$COLUMNS]\r", settle=1.5)
    check("a-pane-is-born-the-size-of-its-box",
          painted(vm, "[39]") or painted(vm, "[40]"),
          repr([row for row in vm.rows() if "[" in row][:4]))

    # ---- detach leaves the session running (§7.3) ----
    # The pane's shells keep running with nothing attached, which is what a
    # server is for -- and on Motor it works only because the client spawned
    # that server *detached*: an ordinary orphan is killed when its parent is
    # reaped (§4.4). Re-attaching finds the same panes, split as they were left.
    vm.send("\x01d", settle=2.0)
    check("detach-gives-the-console-back", painted(vm, "rush:"),
          repr([row for row in vm.rows() if row][-2:]))
    vm.send("/bin/rmux\r", settle=3.0)
    check("attach-finds-the-session-as-it-was",
          painted(vm, "aaa") and painted(vm, "[39]"),
          repr(vm.rows()[:4]))

    # ---- the console changes shape, and nothing says so (§3.2) ----
    # Motor has no size call and no `SIGWINCH`, so a dragged window is a
    # terminal that starts answering the probe differently and nothing else at
    # all. The status line is the last row, so the row it lands on *is* the size
    # rmux believes it has. Last, because a shorter console scrolls the top of a
    # pane into history, and the checks above read what is on screen.
    SHORT = ROWS - 10
    vm.size = (SHORT, COLS)
    vm.pump(3.0)
    check("a-smaller-console-is-noticed", "[0] " in vm.rows()[SHORT - 1],
          repr(vm.rows()[SHORT - 1]))

    # Both halves, because only the second one is the bug this was written for:
    # a console that comes back has a status line rmux painted there before, so
    # the row it *left* is what says the screen was repainted rather than left
    # as it was.
    vm.size = (ROWS, COLS)
    vm.pump(3.0)
    check("a-console-that-comes-back-is-repainted",
          "[0] " in vm.rows()[ROWS - 1] and "[0] " not in vm.rows()[SHORT - 1],
          repr(vm.rows()[SHORT - 1:ROWS]))

    # ---- a resize is not something a pane's program is told (§3.2) ----
    # rmux answers a program's `ESC[6n` and speaks to it at no other time. It
    # used to take one such question as leave to report every later resize --
    # and rush asks at every prompt, so the report went to whatever rush was
    # running by then. `top` reads the `ESC` of it as "quit"
    # (`sysbox/src/commands/top.rs`), so a dragged window killed it.
    #
    # Only this harness can catch it: it wants a real Motor program on a real
    # pipe and a console that changes size under it. `top` repaints once a
    # second, so what is on screen proves nothing and what arrives proves
    # everything -- and here it is also all there is, since top prints more rows
    # than the pane has and its first line has scrolled off by the time anyone
    # looks.
    m = vm.mark()
    vm.send("/bin/top\r", settle=3.0)
    check("top-paints-a-pane", "uptime:" in vm.since(m), repr(vm.rows()[:3]))
    # Two waits, and the first one is the whole test: rmux notices the new size
    # within a second and a killed top dies with it, so a window that *spans*
    # the resize catches the last tick of a dead program and proves nothing.
    # Only what is painted afterwards says top is still there.
    vm.size = (SHORT, COLS)
    vm.pump(3.0)
    m = vm.mark()
    vm.pump(3.0)
    check("a-resize-does-not-quit-a-program-that-never-asked",
          "uptime:" in vm.since(m), repr(vm.since(m)[-200:]))
    vm.send("q", settle=1.5)
    vm.size = (ROWS, COLS)
    vm.pump(3.0)

    # Leave nothing behind: a server that outlives this qemu leaves its port
    # file with it, and the next run is the one that pays (above). This is also
    # the only place the command surface (§7.3) is exercised on the console.
    vm.send("\x01d", settle=2.0)
    m = vm.mark()
    vm.send("/bin/rmux kill-session -t 0\r", settle=2.0)
    check("kill-session-answers-and-the-server-goes",
          "did not answer" not in vm.since(m) and painted(vm, "rush:"),
          repr([row for row in vm.rows() if row][-2:]))

    print()
    print(f"vm-console-check: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    vm.kill()
    sys.exit(1 if FAIL else 0)
