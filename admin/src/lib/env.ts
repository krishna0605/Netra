/**
 * Environment resolution, validated once at module load.
 *
 * The investigator console reads its key with `?? ""`, so a misnamed variable
 * produces an empty string, a null client, and authentication that is silently
 * switched off with no error anywhere. That exact failure is live in this
 * workspace today. This module fails loudly instead.
 */

type EnvProblem = { key: string; detail: string };

function read(key: string): string {
  const value = (import.meta.env as Record<string, string | undefined>)[key];
  return typeof value === "string" ? value.trim() : "";
}

const RETIRED: Record<string, string> = {
  VITE_SUPABASE_ANON_KEY: "VITE_SUPABASE_PUBLISHABLE_KEY",
  VITE_SUPABASE_REALTIME_ENABLED: "(removed entirely — do not reintroduce)",
  SUPABASE_SERVICE_ROLE_KEY: "SUPABASE_SECRET_KEY, and it belongs on the server, never here",
  VITE_SUPABASE_SECRET_KEY: "nothing — a secret key must never carry a VITE_ prefix",
};

function collectProblems(): EnvProblem[] {
  const problems: EnvProblem[] = [];

  if (!read("VITE_SUPABASE_URL")) {
    problems.push({ key: "VITE_SUPABASE_URL", detail: "missing — copy it from frontend/.env.local" });
  }
  if (!read("VITE_SUPABASE_PUBLISHABLE_KEY")) {
    problems.push({
      key: "VITE_SUPABASE_PUBLISHABLE_KEY",
      detail: "missing — this is the name the code reads; older files call it VITE_SUPABASE_ANON_KEY",
    });
  }

  for (const [retired, replacement] of Object.entries(RETIRED)) {
    if (read(retired)) problems.push({ key: retired, detail: `retired — use ${replacement}` });
  }

  return problems;
}

const problems = collectProblems();

if (problems.length > 0) {
  const lines = problems.map((problem) => `  · ${problem.key} — ${problem.detail}`).join("\n");
  const message = `Netra admin console — environment is not usable.\n\n${lines}\n\nSee admin/.env.example.`;
  // Surfaced in the console and thrown, so a broken environment cannot be
  // mistaken for a working one that happens to have no data.
  console.error(message);
  throw new Error(message);
}

export const SUPABASE_URL = read("VITE_SUPABASE_URL");
export const SUPABASE_PUBLISHABLE_KEY = read("VITE_SUPABASE_PUBLISHABLE_KEY");
export const API_BASE_URL = read("VITE_API_BASE_URL") || "/api";
export const DEPLOYMENT_PROFILE = read("VITE_DEPLOYMENT_PROFILE") || "local";
export const IS_LOCAL = DEPLOYMENT_PROFILE === "local";
