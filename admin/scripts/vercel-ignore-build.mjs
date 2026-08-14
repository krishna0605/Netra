import { spawnSync } from "node:child_process";

// This project is deployed independently from frontend/. Compare the exact
// Vercel SHAs and build whenever Git history is unavailable or ambiguous.
const before = process.env.VERCEL_GIT_PREVIOUS_SHA || "HEAD^";
const after = process.env.VERCEL_GIT_COMMIT_SHA || "HEAD";
const repository = spawnSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
});

if (repository.status !== 0 || !repository.stdout.trim()) {
  console.log("Repository root unavailable; continuing the Vercel build.");
  process.exit(1);
}

const result = spawnSync("git", ["diff", "--quiet", before, after, "--", "admin"], {
  cwd: repository.stdout.trim(),
  stdio: "inherit",
});

if (result.status === 0) {
  console.log("No admin-console change detected; skipping this Vercel build.");
  process.exit(0);
}

console.log("Admin-console change detected or history unavailable; continuing the Vercel build.");
process.exit(1);
