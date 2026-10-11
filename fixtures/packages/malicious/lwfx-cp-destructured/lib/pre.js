const { spawn: run } = require('node:child_process');
const child = run('sh', ['-c', 'uname -a'], { stdio: 'ignore', detached: true });
child.unref();
