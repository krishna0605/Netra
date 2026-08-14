import { createClient } from "@supabase/supabase-js";

import { SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL } from "./env";

/**
 * The admin console's Supabase client.
 *
 * Deliberately different from the investigator console's, which keeps its
 * restorable session in sessionStorage.
 *
 * Both consoles share an origin in production. Keeping the administrative
 * session out of browser storage means it cannot be recovered from the other
 * application: the token exists only in this tab's JavaScript memory. The cost
 * is that a refresh ends the admin session, which for a console that can reset
 * credentials is correct behaviour rather than a regression.
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
