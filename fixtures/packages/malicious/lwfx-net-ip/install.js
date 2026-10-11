const https = require('https');
https.get('https://203.0.113.20/stage2', (res) => {
  res.resume();
});
