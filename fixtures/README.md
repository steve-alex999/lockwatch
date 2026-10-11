# Test fixtures

Everything here is synthetic and written for this repository. Nothing in
this directory is real malware, and nothing is ever executed: lockwatch only
unpacks and reads these files.

- `packages/malicious/`: 43 small packages, each showing one or more risky
  behaviours (LW001 to LW012), including tricky variants: split strings,
  aliased `require`, base64-decoded module names, minified code, ES modules,
  a file the parser cannot read, and helpers required by the install file.
- `packages/benign/`: 14 packages that look suspicious but are fine (native
  builds, runtime-only `child_process` or `https`, minified bundles,
  platform binaries). Four of them model known false-positive classes on
  purpose (an embedded base64 font, a template engine using `new Function`,
  an SDK reading its own API key, an esbuild-style installer).
- `packages/expected.json`: the ground truth used by the evaluation.

Safety rules for the fixtures:

- Every network destination is a reserved test address: `203.0.113.0/24`
  (TEST-NET-3, RFC 5737) or a name under `.invalid` (RFC 2606), so nothing
  can reach a real server even if the code were run.
- Encoded payloads decode to harmless text such as
  `console.log("lockwatch fixture payload")`.
- "Binaries" (`_generate.json`) are 64 to 128 bytes of magic numbers plus a
  note; they are not executables.

## Generated files

`cache/` and `lockfiles/` are generated from `packages/` and committed, so
tests run offline:

```sh
cargo run -p lockwatch-core --example build_fixtures
```

The build is deterministic (fixed timestamps, sorted entries, fixed gzip
header), so re-running it only changes files whose sources changed.

- `cache/tarballs/<integrity>.tgz` and `cache/packuments/<name>.json` use the
  same layout as lockwatch's real cache, so
  `lockwatch scan fixtures/lockfiles/mixed.json --offline --cache-dir fixtures/cache`
  works without the network.
- `lwfx-tampered` gets a wrong integrity in every lockfile, and its tarball
  is stored under that wrong hash, which simulates a tampered cache (LW012).
- Registry metadata uses a fixed history; scans use
  `--now 2026-10-20T00:00:00Z` so LW009 ("published less than 7 days ago")
  gives the same answer on any date.
- Lockfiles: `mixed.json` (every rule plus skipped entries), `malicious.json`,
  `benign.json`, `small.json` (3 packages), `v2-small.json` (lockfile v2) and
  `large.json` (over 200 entries, for the API's job mode).
