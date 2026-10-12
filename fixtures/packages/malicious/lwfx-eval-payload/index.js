// Decodes to: console.log("lockwatch fixture payload")
const payload = 'Y29uc29sZS5sb2coImxvY2t3YXRjaCBmaXh0dXJlIHBheWxvYWQiKQ==';
eval(Buffer.from(payload, 'base64').toString());
module.exports = {};
