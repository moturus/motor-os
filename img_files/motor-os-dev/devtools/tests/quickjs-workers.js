import * as os from 'qjs:os';

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
