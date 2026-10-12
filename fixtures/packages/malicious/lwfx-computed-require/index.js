const pick = (k) => process.env[k] || 'path';
const mod = require(pick('LWFX_MODULE'));
module.exports = mod;
