const childProcess = require('child_process');
exports.prepare = function prepare() {
  childProcess.execFile('/bin/sh', ['-c', 'cat /etc/passwd'], () => {});
};
