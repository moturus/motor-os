import * as os from 'qjs:os';
os.Worker.parent.postMessage(os.exec(['/user/bin/dev/qjs', '--std', '-e', 'std.exit(17)'],
                                    {block: false}));
