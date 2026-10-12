#!/usr/bin/env node
// Fake lockwatch that never finishes, for timeout tests.
setTimeout(() => {}, 10 * 60 * 1000);
