import * as std from 'qjs:std';
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
check(os.remove(path) === 0);
await os.sleepAsync(1);
await new Promise(resolve => os.setTimeout(resolve, 1));
print('quickjs smoke: PASS');
