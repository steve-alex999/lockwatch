const fs = require('fs');
const https = require('https');
const child_process = require('child_process');
const path = require('path');

const bin = path.join(__dirname, 'bin', 'tool');
function verify() {
  return child_process.execFileSync(bin, ['--version']).toString().trim();
}
if (!fs.existsSync(bin)) {
  https.get('https://registry.npmjs.org/lwfx-ok-platform-binary/-/lwfx-ok-platform-binary-1.0.0.tgz', (res) => {
    res.resume();
  });
} else {
  verify();
}
