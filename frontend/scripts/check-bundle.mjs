import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { join } from "node:path";

const distRoot = join(process.cwd(), "dist");
const manifest = JSON.parse(readFileSync(join(distRoot, ".vite", "manifest.json"), "utf8"));
const gzipKiB = (file) => gzipSync(readFileSync(join(distRoot, file)), { level: 9 }).byteLength / 1024;

function closure(key, visited = new Set()) {
  if (visited.has(key) || !manifest[key]) return visited;
  visited.add(key);
  for (const dependency of manifest[key].imports ?? []) closure(dependency, visited);
  return visited;
}

function closureSize(key) {
  return [...closure(key)]
    .map((item) => manifest[item]?.file)
    .filter((file) => file?.endsWith(".js"))
    .reduce((total, file) => total + gzipKiB(file), 0);
}

const failures = [];
const entry = Object.keys(manifest).find((key) => manifest[key].isEntry);
const authEntry = Object.keys(manifest).find((key) => key.endsWith("/AuthApplication.tsx"));

for (const [label, key, budget] of [
  ["initial application shell", entry, 200],
  ["authentication route closure", authEntry, 200],
]) {
  if (!key) failures.push(`${label}: manifest entry missing`);
  else {
    const size = closureSize(key);
    console.log(`${label}: ${size.toFixed(2)} KiB gzip / ${budget} KiB`);
    if (size > budget) failures.push(`${label}: ${size.toFixed(2)} KiB exceeds ${budget} KiB`);
  }
}

for (const record of Object.values(manifest)) {
  if (!record.file?.endsWith(".js")) continue;
  const size = gzipKiB(record.file);
  if (size > 350) failures.push(`${record.file}: ${size.toFixed(2)} KiB exceeds 350 KiB asset budget`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log("Bundle budgets passed.");
