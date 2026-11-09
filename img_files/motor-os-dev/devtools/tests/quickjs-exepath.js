import * as os from 'qjs:os';

const expected = scriptArgs.at(-1);
if (os.chdir('/') !== 0)
    throw Error('cannot change cwd');
if (!expected || os.exePath() !== expected)
    throw Error(`unexpected executable path: ${os.exePath()}, expected ${expected}`);
print('quickjs executable path: PASS');
