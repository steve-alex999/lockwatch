#!/usr/bin/env node
// Fake lockwatch that prints JSON that does not match the report schema.
console.log(JSON.stringify({ tool: "lockwatch", summary: { packages_total: -1 } }));
