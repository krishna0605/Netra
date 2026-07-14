import { createClient } from "@supabase/supabase-js";

export const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL ?? "";
export const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY ?? "";
export const SUPABASE_AUTH_ENABLED = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);
export const SUPABASE_REALTIME_ENABLED = import.meta.env.VITE_SUPABASE_REALTIME_ENABLED === "1";

type SessionStorageReader = Pick<Storage, "getItem">;

export function readStoredAccessToken(
  storage: SessionStorageReader,
  supabaseUrl = SUPABASE_URL,
  nowSeconds = Math.floor(Date.now() / 1000),
) {
  if (!supabaseUrl) return "";
  try {
    const projectRef = new URL(supabaseUrl).hostname.split(".")[0];
    if (!projectRef) return "";
    const raw = storage.getItem(`sb-${projectRef}-auth-token`);
    if (!raw) return "";
    const session = JSON.parse(raw) as { access_token?: unknown; expires_at?: unknown };
    if (typeof session.access_token !== "string" || !session.access_token) return "";
    if (typeof session.expires_at === "number" && session.expires_at <= nowSeconds) return "";
    return session.access_token;
  } catch {
    return "";
  }
}

let currentAccessToken = typeof window === "undefined" ? "" : readStoredAccessToken(window.sessionStorage);
let sessionRefreshPromise: ReturnType<typeof refreshStoredSupabaseSession> | null = null;

export const supabase = SUPABASE_AUTH_ENABLED
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        storage: window.sessionStorage,
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
      },
    })
  : null;

export function getCurrentAccessToken() {
  return currentAccessToken;
}

export function setCurrentAccessToken(token?: string | null) {
  currentAccessToken = token ?? "";
}

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
    setCurrentAccessToken();
    return null;
  }

  const { data: userData, error } = await withAuthTimeout(
    supabase.auth.getUser(session.access_token),
    { data: { user: null }, error: null } as unknown as Awaited<ReturnType<typeof supabase.auth.getUser>>,
  );
  if (error || !userData.user) {
    setCurrentAccessToken();
    return null;
  }

  setCurrentAccessToken(session.access_token);
  return session;
}

export async function ensureCurrentAccessToken() {
  if (currentAccessToken) return currentAccessToken;
  if (!supabase) return "";
  if (!sessionRefreshPromise) {
    sessionRefreshPromise = refreshStoredSupabaseSession().finally(() => {
      sessionRefreshPromise = null;
    });
  }
  const session = await sessionRefreshPromise;
  return session?.access_token ?? "";
}
