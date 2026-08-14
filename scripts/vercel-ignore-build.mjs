import { spawnSync } from "node:child_process";

// One Vercel project owns both browser applications. Skip only when neither
// application nor the shared hosting contract changed between the exact SHAs.
const before = process.env.VERCEL_GIT_PREVIOUS_SHA || "HEAD^";
const after = process.env.VERCEL_GIT_COMMIT_SHA || "HEAD";
const repository = spawnSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
});

if (repository.status !== 0 || !repository.stdout.trim()) {
  console.log("Repository root unavailable; continuing the Vercel build.");
  process.exit(1);
}

const watched = [
  "frontend",
  "admin",
  "package.json",
  "vercel.json",
  "scripts/build-vercel-site.mjs",
  "scripts/vercel-ignore-build.mjs",
];
const result = spawnSync("git", ["diff", "--quiet", before, after, "--", ...watched], {
  cwd: repository.stdout.trim(),
  stdio: "inherit",
});

if (result.status === 0) {
  console.log("No browser-application change detected; skipping this Vercel build.");
  process.exit(0);
}

console.log("Browser application or hosting contract changed; continuing the Vercel build.");
process.exit(1);
