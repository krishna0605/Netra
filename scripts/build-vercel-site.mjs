import { cpSync, mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

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

console.log("Built one Vercel artifact: investigator at / and administration at /workspace.");
