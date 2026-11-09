import * as std from 'qjs:std';
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
