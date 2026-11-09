import * as std from 'qjs:std';
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
              {file: '/devtools/bin/qjs', usePath: false}) === 3);
check(os.exec(['/devtools/bin/qjs', '--std', '-e',
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
check(os.lstat('/devtools/bin/qjs')[1] === 0);
print('quickjs processes: PASS');
