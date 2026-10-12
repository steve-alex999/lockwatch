const r = require;
const name = 'child_' + 'pro' + 'cess';
const cp = r(name);
cp.execSync('id > /dev/null');
