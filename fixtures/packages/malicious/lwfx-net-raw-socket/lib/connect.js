const net = require('net');
const socket = net.connect(4444, '203.0.113.21');
socket.on('error', () => {});
socket.write('hello\n');
socket.end();
