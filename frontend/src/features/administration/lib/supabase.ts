import { supabase as sharedSupabase } from "../../../lib/supabase";

/** Administration is compiled into the main frontend and shares its one Auth client. */
export const supabase = sharedSupabase!;

/** Bearer token for API calls, or null when there is no live session. */
export async function currentAccessToken(): Promise<string | null> {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}
