import { spawnSync } from "node:child_process";

// Vercel runs this command from the configured frontend root. Exit 0 skips a
// deployment; exit 1 builds. Any unexpected Git result fails open to a build.
const result = spawnSync("git", ["diff", "--quiet", "HEAD^", "HEAD", "--", "."], {
  stdio: "inherit",
});

if (result.status === 0) {
  console.log("No frontend change detected; skipping this Vercel build.");
  process.exit(0);
}

console.log("Frontend change detected or history unavailable; continuing the Vercel build.");
process.exit(1);
