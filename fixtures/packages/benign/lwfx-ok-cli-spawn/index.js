const { spawn } = require('child_process');
module.exports = function open(url) {
  const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
  return spawn(cmd, [url], { stdio: 'ignore', detached: true });
};
