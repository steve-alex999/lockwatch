const https = require('https');
class Client {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.LWFX_API_KEY;
    this.baseUrl = 'https://api.example.invalid/v1';
  }
  get(path) {
    return https.get(this.baseUrl + path, { headers: { authorization: 'Bearer ' + this.apiKey } });
  }
}
module.exports = Client;
