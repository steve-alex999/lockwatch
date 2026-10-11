// Builds crates/lockwatch-core/data/popular.txt, the popular-package list
// used by rule LW008 (typosquats).
//
// Input: a fixed, hand-picked list of well-known package names
// (scripts/popular-seed.txt). For each name we look up last week's download
// count and write `name<TAB>weekly_downloads`, most downloaded first, with a
// header recording the date and the data source.
//
// Download counts come from the npm downloads API
// (https://api.npmjs.org/downloads/point/last-week/<name>). If that host is
// unreachable, the script falls back to the `downloads.weekly` field of the
// npm registry search API (https://registry.npmjs.org/-/v1/search), which
// reports the same weekly figure. The header says which source was used.
//
// Run with Node 22.18 or later (TypeScript types are stripped natively):
//   node scripts/build_popular.ts
// No dependencies; nothing from the packages is downloaded or executed.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const seedPath = join(root, "scripts", "popular-seed.txt");
const outPath = join(root, "crates", "lockwatch-core", "data", "popular.txt");

type Counts = Map<string, number>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// GET a JSON document, retrying rate limits (429) and server errors with
// exponential backoff (honouring Retry-After when the server sends it).
async function getJson(url: string): Promise<unknown> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, { signal: AbortSignal.timeout(20_000) });
    if (res.ok) return res.json();
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= 6) throw new Error(`HTTP ${res.status} for ${url}`);
    const retryAfter = Number(res.headers.get("retry-after"));
    await sleep(retryAfter > 0 ? retryAfter * 1000 : 2000 * 2 ** attempt);
  }
}

// The downloads API accepts up to 128 unscoped names per request; scoped
// names must be requested one at a time.
async function fromDownloadsApi(names: string[]): Promise<Counts> {
  const counts: Counts = new Map();
  const unscoped = names.filter((n) => !n.startsWith("@"));
  for (let i = 0; i < unscoped.length; i += 100) {
    const batch = unscoped.slice(i, i + 100);
    const body = (await getJson(
      `https://api.npmjs.org/downloads/point/last-week/${batch.join(",")}`,
    )) as Record<string, { downloads: number } | null>;
    for (const [name, value] of Object.entries(body)) {
      if (value) counts.set(name, value.downloads);
    }
  }
  for (const name of names.filter((n) => n.startsWith("@"))) {
    const body = (await getJson(
      `https://api.npmjs.org/downloads/point/last-week/${name}`,
    )) as { downloads: number };
    counts.set(name, body.downloads);
  }
  return counts;
}

type SearchResult = {
  objects: { package: { name: string }; downloads?: { weekly?: number } }[];
};

async function fromSearchApi(names: string[]): Promise<Counts> {
  const counts: Counts = new Map();
  for (const name of names) {
    const url = `https://registry.npmjs.org/-/v1/search?size=20&text=${encodeURIComponent(name)}`;
    try {
      const body = (await getJson(url)) as SearchResult;
      const hit = body.objects.find((o) => o.package.name === name);
      if (hit?.downloads?.weekly !== undefined) counts.set(name, hit.downloads.weekly);
    } catch (err) {
      // For example one-letter names, which the search API rejects (HTTP 400).
      console.error(`skipping ${name}: ${(err as Error).message}`);
    }
    // Be polite to the registry (its search endpoint is rate limited).
    await sleep(1000);
  }
  return counts;
}

async function main(): Promise<void> {
  const names = [
    ...new Set(
      readFileSync(seedPath, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#")),
    ),
  ];

  let source = "npm downloads API, https://api.npmjs.org/downloads/point/last-week";
  let counts: Counts;
  try {
    counts = await fromDownloadsApi(names);
  } catch (err) {
    console.error(`downloads API unavailable (${(err as Error).message}); using search API`);
    source = "npm registry search API, downloads.weekly, https://registry.npmjs.org/-/v1/search";
    counts = await fromSearchApi(names);
  }

  const missing = names.filter((n) => !counts.has(n));
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const today = new Date().toISOString().slice(0, 10);
  const header = [
    "# lockwatch popular package list (used by rule LW008)",
    `# generated: ${today} by scripts/build_popular.ts from scripts/popular-seed.txt`,
    `# source: ${source}`,
    `# packages: ${rows.length} (seed names not found: ${missing.length ? missing.join(", ") : "none"})`,
    "# format: name<TAB>weekly_downloads",
  ];
  const lines = rows.map(([name, n]) => `${name}\t${n}`);
  writeFileSync(outPath, [...header, ...lines, ""].join("\n"));
  console.log(`wrote ${rows.length} packages to ${outPath}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
