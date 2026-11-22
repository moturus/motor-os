use crate::support::{Scratch, command, compile, success};
use std::fs;

pub fn run() {
    let scratch = Scratch::new("quickjs");
    let root = &scratch.0;
    for (name, text) in SOURCES {
        // The subprocess and mode checks need scratch accessible in either role.
        scratch.write(name, &text.replace("/user/tmp", root.to_str().unwrap()));
    }
    for (source, executable) in [
        ("quickjs-qsort.c", "qsort-check"),
        ("quickjs-libc-process.c", "libc-process"),
        ("quickjs-exepath-buffer.c", "exepath-buffer"),
    ] {
        compile(root, "/user/bin/dev/cc", &["-O2", source, "-o", executable]);
        success(
            &mut command(root, root.join(executable).to_str().unwrap()),
            b"",
        );
    }
    for executable in ["qjs", "/user/bin/dev/qjs"] {
        success(
            command(root, executable).args(["quickjs-exepath.js", "/user/bin/dev/qjs"]),
            b"",
        );
    }
    success(
        command(std::path::Path::new("/user/bin/dev"), "./qjs")
            .arg(root.join("quickjs-exepath.js"))
            .arg("/user/bin/dev/qjs"),
        b"",
    );
    compile(
        root,
        "/user/bin/dev/qjsc",
        &["-e", "-m", "-o", "exepath.c", "quickjs-exepath.js"],
    );
    compile(
        root,
        "/user/bin/dev/cc",
        &[
            "-I/user/lib/quickjs/include",
            "exepath.c",
            "/user/lib/quickjs/lib/libqjs.a",
            "-o",
            "exepath",
        ],
    );
    success(command(root, "./exepath").arg(root.join("exepath")), b"");
    fs::copy(
        root.join("quickjs-exepath.js"),
        root.join("standalone-source.js"),
    )
    .unwrap();
    compile(
        root,
        "/user/bin/dev/qjs",
        &[
            "--compile",
            "standalone-source.js",
            "--out",
            "standalone-app",
        ],
    );
    compile(
        root,
        "/user/bin/dev/qjs",
        &["-c", "standalone-source.js", "-o", "standalone-app"],
    );
    fs::remove_file(root.join("standalone-source.js")).unwrap();
    success(
        command(root, "./standalone-app").arg(root.join("standalone-app")),
        b"",
    );
    fs::rename(root.join("standalone-app"), root.join("standalone moved")).unwrap();
    success(
        command(root, "./standalone moved").arg(root.join("standalone moved")),
        b"",
    );
    compile(
        root,
        "/user/bin/dev/rustc",
        &["--edition=2024", "quickjs-http.rs", "-o", "quickjs-http"],
    );
    for name in ["smoke", "process", "shell-net"] {
        let source = format!("quickjs-{name}.js");
        success(command(root, "/user/bin/dev/qjs").arg(&source), b"");
        compile(
            root,
            "/user/bin/dev/qjsc",
            &["-e", "-m", "-o", &format!("{name}.c"), &source],
        );
        compile(
            root,
            "/user/bin/dev/cc",
            &[
                "-I/user/lib/quickjs/include",
                &format!("{name}.c"),
                "/user/lib/quickjs/lib/libqjs.a",
                "-o",
                name,
            ],
        );
        success(&mut command(root, &format!("./{name}")), b"");
    }
    success(
        command(root, "/user/bin/dev/qjs").arg("quickjs-workers.js"),
        b"",
    );
    compile(
        root,
        "/user/bin/dev/qjsc",
        &["-b", "-m", "-o", "smoke.bin", "quickjs-smoke.js"],
    );
    assert!(fs::metadata(root.join("smoke.bin")).unwrap().len() > 0);
    // The REPL ends on std.exit, and at the end of its input. The time limit
    // turns a REPL that spins there into a failure.
    for input in [&b"print(40 + 2); std.exit(0)\n"[..], b"print(40 + 2)\n"] {
        let repl = success(
            command(root, "/user/bin/timeout")
                .env("XDG_STATE_HOME", root)
                .args(["60", "/user/bin/dev/qjs"]),
            input,
        );
        assert!(
            String::from_utf8(repl.stdout)
                .unwrap()
                .lines()
                .any(|line| line == "42"),
            "{input:?}"
        );
    }
    println!("QuickJS smoke and native compilation: PASS");

    if std::env::var_os("MOTOR_TEST_RELEASE").is_some() {
        let source = std::path::Path::new("/none/dev/quickjs-test262");
        compile(
            source,
            "/user/bin/dev/cc",
            &[
                "-O2",
                "-D_GNU_SOURCE",
                "-I.",
                "run-test262.c",
                "/user/lib/quickjs/lib/libqjs.a",
                "-o",
                "run-test262",
            ],
        );
        let result = success(
            command(source, "/user/bin/timeout").args([
                "1200",
                "./run-test262",
                "-m",
                "-c",
                "test262.conf",
                "-a",
                "-t",
                "3",
            ]),
            b"",
        );
        let log = format!(
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            log.lines()
                .filter(|line| line.starts_with("Result: "))
                .last(),
            Some("Result: 40/82220 errors, 4802 excluded, 5736 skipped"),
            "{log}"
        );
        println!("QuickJS Test262: PASS");
    }
}

const SOURCES: &[(&str, &str)] = &[
    (
        "quickjs-exepath-buffer.c",
        r####"#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <moto_rt.h>

int main(void) {
    char path[4096];
    size_t size = sizeof(path);
    assert(moto_rt_exepath((uint8_t *)path, &size) == 0);
    assert(path[0] == '/' && size == strlen(path));
    assert(size >= strlen("/exepath-buffer"));
    assert(!strcmp(path + size - strlen("/exepath-buffer"), "/exepath-buffer"));

    char tiny[2] = {'x', 'y'};
    size = 1;
    assert(moto_rt_exepath((uint8_t *)tiny, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(size == 1 && tiny[0] == 'x' && tiny[1] == 'y');
    size = 0;
    assert(moto_rt_exepath((uint8_t *)tiny, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(size == 0 && tiny[0] == 'x' && tiny[1] == 'y');
    assert(moto_rt_exepath(NULL, &size) == -MOTO_E_INVALID_ARGUMENT);
    assert(moto_rt_exepath((uint8_t *)tiny, NULL) == -MOTO_E_INVALID_ARGUMENT);
    puts("quickjs executable-path buffers: PASS");
    return 0;
}
"####,
    ),
    (
        "quickjs-exepath.js",
        r####"import * as os from 'qjs:os';

const expected = scriptArgs.at(-1);
if (os.chdir('/') !== 0)
    throw Error('cannot change cwd');
if (!expected || os.exePath() !== expected)
    throw Error(`unexpected executable path: ${os.exePath()}, expected ${expected}`);
print('quickjs executable path: PASS');
"####,
    ),
    (
        "quickjs-http.rs",
        r####"use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for _ in 0..6 {
        let (mut stream, _) = listener.accept()?;
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let mut header_bytes = line.len();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 || line == "\r\n" {
                break;
            }
            header_bytes += line.len();
            assert!(header_bytes < 16 * 1024);
        }
        let (status, body) = match path.as_str() {
            "/binary" => ("200 OK", vec![0, 127, 128, 255]),
            "/missing" => ("404 Not Found", b"missing".to_vec()),
            "/large" => ("200 OK", vec![b'x'; 64 * 1024]),
            _ => ("200 OK", b"Motor QuickJS\n".to_vec()),
        };
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nX-QJS: local\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        stream.write_all(&response)?;
    }
    Ok(())
}
"####,
    ),
    (
        "quickjs-libc-process.c",
        r####"#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <moto_rt.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) {
        char cwd[4096];
        assert(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/user/tmp"));
        assert(getenv("QJS_LIBC_PROBE") && !strcmp(getenv("QJS_LIBC_PROBE"), "native"));
        puts("native libc child");
        return 17;
    }

    char executable[4096], parent_cwd[4096], current_cwd[4096];
    size_t size = sizeof(executable);
    assert(moto_rt_exepath((uint8_t *)executable, &size) == 0);
    assert(getcwd(parent_cwd, sizeof(parent_cwd)));
    char *args[] = {executable, "--child", NULL};
    char *env[] = {"QJS_LIBC_PROBE=native", NULL};
    posix_spawn_file_actions_t actions;
    assert(posix_spawn_file_actions_init(&actions) == 0);
    assert(posix_spawn_file_actions_addchdir_np(&actions, "/user/tmp") == 0);
    assert(posix_spawn_file_actions_addopen(&actions, 1, "quickjs-libc-child.out",
                                          O_WRONLY | O_CREAT | O_TRUNC, 0600) == 0);
    pid_t pid;
    assert(posix_spawn(&pid, executable, &actions, NULL, args, env) == 0);
    assert(posix_spawn_file_actions_destroy(&actions) == 0);
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 17);
    assert(waitpid(pid, &status, 0) == -1 && errno == ECHILD);
    assert(getcwd(current_cwd, sizeof(current_cwd)) && !strcmp(parent_cwd, current_cwd));
    FILE *out = fopen("/user/tmp/quickjs-libc-child.out", "r");
    char line[64];
    assert(out && fgets(line, sizeof(line), out) && !strcmp(line, "native libc child\n"));
    assert(fclose(out) == 0 && unlink("/user/tmp/quickjs-libc-child.out") == 0);

    char *sleep_args[] = {"sysbox", "sleep", "60", NULL};
    assert(posix_spawnp(&pid, "sysbox", NULL, NULL, sleep_args, environ) == 0);
    assert(waitpid(-1, &status, WNOHANG) == 0);
    assert(kill(pid, 0) == 0 && kill(pid, SIGKILL) == 0);
    assert(waitpid(-1, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    assert(kill(pid, 0) == -1 && errno == ESRCH);

    FILE *pipe = popen("printf 'native libc popen'", "r");
    assert(pipe && fgets(line, sizeof(line), pipe) && !strcmp(line, "native libc popen"));
    assert(pclose(pipe) == 0);
    pipe = popen("exit 7", "r");
    assert(pipe && waitpid(-1, &status, 0) > 0);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
    assert(pclose(pipe) == -1 && errno == ECHILD);

    // open() gives a new writable file its execute bits. Other files keep theirs.
    const char *path = "/user/tmp/quickjs-libc-mode";
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0755);
    assert(fd >= 0 && access(path, X_OK) == 0 && access(path, W_OK) == 0);
    assert(write(fd, "x", 1) == 1 && close(fd) == 0 && unlink(path) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0 && access(path, X_OK) == -1 && close(fd) == 0);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    assert(fd >= 0 && access(path, X_OK) == -1);
    // fchmod can widen rw- to rwx, which Motor allows only through r-x.
    assert(fchmod(fd, 0755) == 0 && access(path, X_OK) == 0 && access(path, W_OK) == 0);
    assert(close(fd) == 0 && unlink(path) == 0);
    // A new read-only mode is not applied: the caller may still write to the fd.
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0555);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0 && unlink(path) == 0);
    puts("quickjs libc process APIs: PASS");
    return 0;
}
"####,
    ),
    (
        "quickjs-process-worker.js",
        r####"import * as os from 'qjs:os';
os.Worker.parent.postMessage(os.exec(['/user/bin/dev/qjs', '--std', '-e', 'std.exit(17)'],
                                    {block: false}));
"####,
    ),
    (
        "quickjs-process.js",
        r####"import * as std from 'qjs:std';
import * as os from 'qjs:os';

function check(value) {
    if (!value) throw Error('QuickJS process assertion failed');
}
function rejected(fn) {
    try { fn(); } catch (error) { return error instanceof TypeError; }
    return false;
}
check(os.getpid() > 0);
check(os.exec(['qjs', '--std', '-e', 'std.exit(7)']) === 7);
check(os.exec(['unused', '--std', '-e', 'std.exit(3)'],
              {file: '/user/bin/dev/qjs', usePath: false}) === 3);
check(os.exec(['/user/bin/dev/qjs', '--std', '-e',
               'std.exit(std.getenv("QJS_CHILD") === "motor" ? 0 : 1)'],
              {env: {QJS_CHILD: 'motor'}}) === 0);
const pid = os.exec(['qjs', '--std', '-e', 'std.exit(9)'], {block: false});
check(pid > 0);
const [reaped, status] = os.waitpid(pid, 0);
check(reaped === pid && status === (9 << 8));
check(os.waitpid(pid, 0)[0] === -10); // ECHILD

const cwd = os.getcwd()[0];
if (os.stat('exec-child-dir')[1] !== 0) check(os.mkdir('exec-child-dir', 0o755) === 0);
let file = std.open('exec-input', 'w');
file.puts('input line\n');
check(file.close() === 0);
const input = os.open('exec-input', os.O_RDONLY);
const output = os.open('exec-output', os.O_WRONLY | os.O_CREAT | os.O_TRUNC);
const errors = os.open('exec-errors', os.O_WRONLY | os.O_CREAT | os.O_TRUNC);
check(input >= 0 && output >= 0 && errors >= 0);
check(os.exec(['qjs', '--std', '-e',
               'std.out.puts(os.getcwd()[0] + ":" + std.in.getline()); std.err.puts("stderr");'],
              {cwd: cwd + '/exec-child-dir', stdin: input, stdout: output, stderr: errors}) === 0);
for (const fd of [input, output, errors]) check(os.close(fd) === 0);
check(os.getcwd()[0] === cwd);
check(std.loadFile('exec-output') === cwd + '/exec-child-dir:input line');
check(std.loadFile('exec-errors') === 'stderr');
for (const path of ['exec-input', 'exec-output', 'exec-errors']) check(os.remove(path) === 0);
check(rejected(() => os.exec(['qjs', '-q'], {cwd: '/no-such-qjs-directory'})));
check(rejected(() => os.exec(['qjs', '-q'], {stdout: -1})));
check(rejected(() => os.exec(['qjs', '-q'], {usePath: false})));
for (const options of [{uid: 123}, {gid: 123}, {groups: [123]}])
    check(rejected(() => os.exec(['qjs', '-q'], options)));
check(rejected(() => os.exec(['/user/tmp/quickjs-no-such-executable'])));

// These children stay alive until explicitly killed: WNOHANG is deterministic.
const slow = os.exec(['qjs', '--std', '-e', 'os.setInterval(() => {}, 10000)'], {block: false});
check(os.waitpid(slow, os.WNOHANG).join(',') === '0,0');
check(os.waitpid(-1, os.WNOHANG).join(',') === '0,0');
check(os.kill(slow, 0) === 0);
check(os.kill(slow, os.SIGUSR1) === -38); // ENOSYS, not silently a kill
check(os.kill(slow, 0) === 0);
const fast = os.exec(['qjs', '--std', '-e', 'std.exit(11)'], {block: false});
check(os.waitpid(-1, 0).join(',') === `${fast},${11 << 8}`);
check(os.kill(slow, os.SIGTERM) === 0);
check(os.waitpid(slow, 0).join(',') === `${slow},${os.SIGTERM}`);
check(os.kill(slow, 0) === -3); // ESRCH
check(os.waitpid(-1, os.WNOHANG)[0] === -10);

const held = os.exec(['qjs', '--std', '-e', 'os.setInterval(() => {}, 10000)'], {block: false});
const worker = new os.Worker('./quickjs-process-worker.js');
const posted = new Promise(resolve => { worker.onmessage = ({data}) => {
    worker.onmessage = null;
    resolve(data);
}; });
const [other, otherStatus] = os.waitpid(-1, 0);
check(other === await posted && otherStatus === (17 << 8));
check(os.kill(held, os.SIGKILL) === 0);
check(os.waitpid(-1, 0).join(',') === `${held},9`);
check(os.waitpid(-1, 0)[0] === -10);
const command = std.popen('exit 23', 'r');
check(os.waitpid(-1, 0)[1] === (23 << 8));
check(command.close() === -10); // Already reaped by waitpid, as with POSIX pclose.
check(os.kill(os.getpid(), 0) === 0);

// These follow libc: they stay in the API and report that Motor lacks them.
check(os.pipe() === null);
check(os.dup(1) === -38 && os.dup2(1, 2) === -38); // ENOSYS
check(os.symlink('quickjs-no-target', 'quickjs-no-link') < 0);
check(os.readlink('quickjs-no-link')[1] !== 0);
check(os.lstat('/user/bin/dev/qjs')[1] === 0);
print('quickjs processes: PASS');
"####,
    ),
    (
        "quickjs-qsort.c",
        r####"#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { COUNT = 65536 };

static int compare(const void *a, const void *b) {
    uint32_t left = *(const uint32_t *)a;
    uint32_t right = *(const uint32_t *)b;
    return (left > right) - (left < right);
}

static int compare_context(const void *a, const void *b, void *context) {
    assert(*(const int *)context == -1);
    return -compare(a, b);
}

/* Check ordering and preservation of every value for both public APIs. */
static void check_pattern(uint32_t *values, uint32_t *counts, int pattern, int reverse) {
    memset(counts, 0, COUNT * sizeof(*counts));
    for (uint32_t i = 0; i < COUNT; i++) {
        uint32_t value = i;
        if (pattern == 1) value = COUNT - 1 - i;
        if (pattern == 2) value = 42;
        if (pattern == 3) value = i % 7;
        if (pattern == 4) value = (i * 40503u + 17u) % COUNT;
        values[i] = value;
        counts[value]++;
    }
    int direction = -1;
    if (reverse)
        qsort_r(values, COUNT, sizeof(*values), compare_context, &direction);
    else
        qsort(values, COUNT, sizeof(*values), compare);
    for (size_t i = 0; i < COUNT; i++) {
        assert(values[i] < COUNT && counts[values[i]] > 0);
        counts[values[i]]--;
        if (i > 0)
            assert(reverse ? values[i - 1] >= values[i] : values[i - 1] <= values[i]);
    }
    for (size_t i = 0; i < COUNT; i++)
        assert(counts[i] == 0);
}

static int compare_record(const void *a, const void *b) {
    return memcmp(a, b, 3);
}

int main(void) {
    uint32_t single = 42;
    int direction = -1;
    qsort(&single, 0, sizeof(single), compare);
    qsort(&single, 1, sizeof(single), compare);
    qsort_r(&single, 0, sizeof(single), compare_context, &direction);
    qsort_r(&single, 1, sizeof(single), compare_context, &direction);
    assert(single == 42);

    uint32_t *values = malloc(COUNT * sizeof(*values));
    uint32_t *counts = malloc(COUNT * sizeof(*counts));
    assert(values && counts);
    for (int pattern = 0; pattern < 5; pattern++) {
        check_pattern(values, counts, pattern, 0);
        check_pattern(values, counts, pattern, 1);
    }
    free(counts);
    free(values);

    unsigned char records[][3] = {{2, 3, 4}, {0, 9, 8}, {2, 3, 3}, {1, 7, 6}};
    const unsigned char expected[][3] = {{0, 9, 8}, {1, 7, 6}, {2, 3, 3}, {2, 3, 4}};
    qsort(records, 4, sizeof(records[0]), compare_record);
    assert(memcmp(records, expected, sizeof(records)) == 0);
    puts("quickjs libc qsort: PASS");
    return 0;
}
"####,
    ),
    (
        "quickjs-shell-net.js",
        r####"import * as std from 'qjs:std';
import * as os from 'qjs:os';

function check(value) {
    if (!value) throw Error('QuickJS shell/network assertion failed');
}
std.setenv('QJS_POPEN_VAR', 'Motor shell');
let pipe = std.popen('printf "%s\\n" "$QJS_POPEN_VAR" | cat', 'r');
check(pipe !== null && pipe.fileno() > 2);
// A live pipe is non-seekable; an invalid descriptor must stay EBADF.
check(os.seek(pipe.fileno(), 0, std.SEEK_CUR) === -29); // ESPIPE
check(os.seek(-1, 0, std.SEEK_CUR) === -9); // EBADF
check(pipe.getline() === 'Motor shell');
check(pipe.close() === 0);
std.unsetenv('QJS_POPEN_VAR');
pipe = std.popen('exit 7', 'r');
check(pipe.close() === (7 << 8));
const body = 'streaming\n'.repeat(4096);
pipe = std.popen('cat > quickjs-popen.tmp', 'w');
check(os.seek(pipe.fileno(), 0, std.SEEK_CUR) === -29);
pipe.puts(body);
check(pipe.close() === 0);
check(std.loadFile('quickjs-popen.tmp') === body);
check(os.remove('quickjs-popen.tmp') === 0);
print('quickjs shell pipes: PASS');

const server = std.popen('./quickjs-http', 'r');
const address = server.getline();
check(address !== null && address.startsWith('127.0.0.1:'));
const base = 'http://' + address;
check(std.urlGet(base + '/text') === 'Motor QuickJS\n');
check(Array.from(new Uint8Array(std.urlGet(base + '/binary', {binary: true})))
           .join(',') === '0,127,128,255');
check(std.urlGet(base + '/missing') === null);
const response = std.urlGet(base + '/missing', {full: true});
check(response.status === 404 && response.response === 'missing');
check(response.responseHeaders.includes('X-QJS: local\r\n'));
check(std.urlGet(base + "/quote?q='&x=[]{}") === 'Motor QuickJS\n');
check(std.urlGet(base + '/large').length === 64 * 1024);
check(server.close() === 0);
check(std.urlGet('http://127.0.0.1:0/unavailable') === null);
print('quickjs local networking: PASS');
"####,
    ),
    (
        "quickjs-smoke.js",
        r####"import * as std from 'qjs:std';
import * as os from 'qjs:os';

function check(value) {
    if (!value) throw Error('QuickJS smoke assertion failed');
}
check(os.platform === 'motor');
check(2n ** 64n === 18446744073709551616n);
check(/(?<name>hello)/u.exec('hello').groups.name === 'hello');
check(JSON.parse(JSON.stringify({a: [1, 2]})).a[1] === 2);
check(String.fromCodePoint(0x1f3cd).codePointAt(0) === 0x1f3cd);
check(new Uint32Array(new Uint8Array([42, 0, 0, 0]).buffer)[0] === 42);
check(await Promise.resolve(42) === 42);
check((await import('qjs:os')).platform === 'motor');
const path = 'quickjs-smoke.tmp';
const file = std.open(path, 'w+');
check(file !== null);
file.puts('Motor QuickJS\n');
check(file.seek(0, std.SEEK_SET) === 0);
check(file.getline() === 'Motor QuickJS');
check(file.close() === 0);
check(std.loadFile(path) === 'Motor QuickJS\n');
check(os.stat(path)[1] === 0);
const fd = os.open(path, os.O_RDONLY);
const byte = new Uint8Array(1);
check(os.seek(fd, 0, std.SEEK_END) > 0);
const count = await new Promise((resolve, reject) => {
    const timer = os.setTimeout(() => {
        os.setReadHandler(fd, null);
        reject(Error('read handler lost after EOF'));
    }, 5000);
    os.setReadHandler(fd, () => {
        os.setReadHandler(fd, null);
        os.clearTimeout(timer);
        resolve(os.read(fd, byte.buffer, 0, 1));
    });
    check(os.read(fd, byte.buffer, 0, 1) === 0);
    check(os.seek(fd, 0, std.SEEK_SET) === 0);
});
check(count === 1 && byte[0] === 'M'.charCodeAt(0));
check(os.close(fd) === 0);
check(os.remove(path) === 0);
await os.sleepAsync(1);
await new Promise(resolve => os.setTimeout(resolve, 1));
print('quickjs smoke: PASS');
"####,
    ),
    (
        "quickjs-worker-child.js",
        r####"import * as os from 'qjs:os';

const parent = os.Worker.parent;
parent.postMessage({ready: true});
parent.onmessage = ({data}) => {
    if (data.stop) {
        parent.onmessage = null;
        parent.postMessage({done: true});
    } else {
        Atomics.add(data.shared, 0, 1);
        // A burst leaves messages queued after the native wake is consumed.
        for (let part = 0; part < 4; part++)
            parent.postMessage({seq: data.seq, part, shared: data.shared});
    }
};
"####,
    ),
    (
        "quickjs-workers.js",
        r####"import * as os from 'qjs:os';

const shared = new Int32Array(new SharedArrayBuffer(4));
const jobs = Array.from({length: 4}, async () => {
    const worker = new os.Worker('./quickjs-worker-child.js');
    // Exercise messages queued before a receiving handler is installed.
    await os.sleepAsync(1);
    await new Promise(resolve => {
        let seq = 0, part = 0;
        worker.onmessage = ({data}) => {
            if (data.ready) {
                worker.postMessage({seq, shared});
            } else if (data.done) {
                worker.onmessage = null;
                resolve();
            } else {
                if (data.seq !== seq || data.part !== part ||
                    data.shared.buffer.byteLength !== shared.buffer.byteLength)
                    throw Error('QuickJS worker assertion failed');
                if (++part === 4) {
                    part = 0;
                    if (++seq === 16)
                        worker.postMessage({stop: true});
                    else
                        worker.postMessage({seq, shared});
                }
            }
        };
    });
});
await Promise.all(jobs);
if (Atomics.load(shared, 0) !== 64)
    throw Error('QuickJS worker shared memory assertion failed');
print('quickjs workers: PASS');
"####,
    ),
];
