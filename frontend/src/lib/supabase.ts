import { createClient } from "@supabase/supabase-js";

export const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL ?? "";
export const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY ?? "";
export const SUPABASE_AUTH_ENABLED = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);
export const SUPABASE_REALTIME_ENABLED = import.meta.env.VITE_SUPABASE_REALTIME_ENABLED === "1";

export const supabase = SUPABASE_AUTH_ENABLED ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

async function withAuthTimeout<T>(operation: Promise<T>, fallback: T, timeoutMs = 5000): Promise<T> {
  return Promise.race([
    operation,
    new Promise<T>((resolve) => {
      window.setTimeout(() => resolve(fallback), timeoutMs);
    }),
  ]);
}

export async function refreshStoredSupabaseSession() {
  if (!supabase) return null;
  const { data } = await withAuthTimeout(supabase.auth.getSession(), { data: { session: null }, error: null });
  const session = data.session;
  if (!session?.access_token) {
    window.localStorage.removeItem("netra-supabase-access-token");
    return null;
  }

  const { data: userData, error } = await withAuthTimeout(
    supabase.auth.getUser(session.access_token),
    { data: { user: null }, error: null } as unknown as Awaited<ReturnType<typeof supabase.auth.getUser>>,
  );
  if (error || !userData.user) {
    window.localStorage.removeItem("netra-supabase-access-token");
    return null;
  }

  if (session.access_token) {
    window.localStorage.setItem("netra-supabase-access-token", session.access_token);
  }
  return session;
}
