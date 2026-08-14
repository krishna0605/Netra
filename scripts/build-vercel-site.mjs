import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

function run(args, label) {
  const result = spawnSync(npm, args, {
    cwd: root,
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed with exit code ${result.status ?? "unknown"}: ${result.error?.message ?? ""}`);
  }
}

run(["ci", "--prefix", "frontend"], "Investigator dependency install");
run(["run", "build", "--prefix", "frontend"], "Investigator build");
run(["ci", "--prefix", "admin"], "Administration dependency install");
run(["run", "build", "--prefix", "admin"], "Administration build");

const output = resolve(root, "dist");
rmSync(output, { recursive: true, force: true });
cpSync(resolve(root, "frontend", "dist"), output, { recursive: true });
mkdirSync(resolve(output, "workspace"), { recursive: true });
cpSync(resolve(root, "admin", "dist"), resolve(output, "workspace"), { recursive: true });

const releaseId = process.env.VERCEL_GIT_COMMIT_SHA
  ?? execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (!/^[0-9a-f]{40}$/.test(releaseId)) {
  throw new Error("Release identity must be a full Git commit SHA.");
}
writeFileSync(
  resolve(output, "release.json"),
  `${JSON.stringify({
    releaseId,
    environment: process.env.VERCEL_ENV ?? "local",
    builtAt: new Date().toISOString(),
  }, null, 2)}\n`,
  "utf8",
);

console.log(`Built one Vercel artifact for release ${releaseId}: investigator at / and administration at /workspace.`);
