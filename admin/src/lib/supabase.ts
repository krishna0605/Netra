import { createClient } from "@supabase/supabase-js";

import { SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL } from "./env";

/**
 * The admin console's Supabase client.
 *
 * Deliberately different from the investigator console's, which sets
 * `persistSession: true` and therefore keeps its session in localStorage.
 *
 * Both consoles share an origin, so they share localStorage. Keeping the
 * administrative session out of it means a script-injection flaw in the
 * investigator console has nothing to steal — the session simply is not there
 * to read. The cost is that a refresh ends the admin session, which for a
 * console that can reset credentials is correct behaviour rather than a
 * regression.
 *
 * `storageKey` is distinct as a second line of defence: even if persistence
 * were ever switched on by mistake, the two sessions could not collide.
 */
export const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: true,
    detectSessionInUrl: false,
    storageKey: "sb-netra-admin",
    flowType: "pkce",
  },
  global: {
    headers: { "X-Netra-Surface": "admin" },
  },
});

/** Bearer token for API calls, or null when there is no live session. */
export async function currentAccessToken(): Promise<string | null> {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}
