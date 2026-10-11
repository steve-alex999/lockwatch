#!/usr/bin/env node
// Fake lockwatch that fails like the real one on a fatal error.
console.error("lockwatch: error: scanning x.json: unsupported lockfile: no packages");
process.exit(2);
