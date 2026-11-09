import * as os from 'qjs:os';

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
