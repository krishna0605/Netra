import type { ActivityEvent, AdminUser } from "../data/types";

/**
 * Figures computed from the data rather than carried as constants.
 *
 * Where there is nothing to compute from, these return null and the caller
 * omits the element. A sparkline invented from a placeholder is worse than no
 * sparkline: it reads as evidence.
 */

const DAY = 864e5;

/** Daily counts over the trailing week, oldest first. */
export function dailyCounts(events: ActivityEvent[], predicate: (event: ActivityEvent) => boolean, days = 7): number[] | null {
  const matching = events.filter(predicate);
  if (matching.length === 0) return null;

  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);

  const buckets = Array.from({ length: days }, () => 0);
  for (const event of matching) {
    // Compare midnights, not instants. Subtracting a mid-afternoon timestamp
    // from this morning's midnight gives a negative span, which floors to -1
    // and pushes today's events off the end of the array — so the most recent
    // day, the one that matters most, silently reads as zero.
    const eventDay = new Date(Date.parse(event.at));
    eventDay.setHours(0, 0, 0, 0);

    const age = Math.round((startOfToday.getTime() - eventDay.getTime()) / DAY);
    const index = days - 1 - age;
    if (index >= 0 && index < days) buckets[index] += 1;
  }

  // A flat line at zero is not a trend, it is noise pretending to be one.
  return buckets.some((value) => value > 0) ? buckets : null;
}

/** Running total of accounts by join date, oldest first. */
export function joinTrend(users: AdminUser[], days = 7): number[] | null {
  if (users.length === 0) return null;

  const startOfToday = new Date();
  startOfToday.setHours(0, 0, 0, 0);

  const buckets = Array.from({ length: days }, (_, index) => {
    const cutoff = startOfToday.getTime() - (days - 1 - index) * DAY + DAY;
    return users.filter((user) => user.status === "active" && Date.parse(user.joinedAt) < cutoff).length;
  });

  return buckets.some((value, index) => index > 0 && value !== buckets[0]) ? buckets : null;
}

/** Who accounts for the most denials, and how many. */
export function topDeniedActor(events: ActivityEvent[]): { name: string; count: number } | null {
  const tally = new Map<string, number>();
  for (const event of events) {
    if (event.result !== "denied" || !event.actor) continue;
    tally.set(event.actor, (tally.get(event.actor) ?? 0) + 1);
  }
  if (tally.size === 0) return null;

  const [name, count] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0];
  return { name, count };
}

export function joinedSince(users: AdminUser[], days: number): number {
  const cutoff = Date.now() - days * DAY;
  return users.filter((user) => Date.parse(user.joinedAt) >= cutoff).length;
}

/** Invitations sent long enough ago that they lapse today. */
export function invitationsExpiringToday(users: AdminUser[], validForDays = 7): number {
  const now = Date.now();
  return users.filter((user) => {
    if (user.status !== "invited") return false;
    const expiresAt = Date.parse(user.joinedAt) + validForDays * DAY;
    return expiresAt >= now && expiresAt - now <= DAY;
  }).length;
}

export function dormantAccounts(users: AdminUser[], days = 90): number {
  const cutoff = Date.now() - days * DAY;
  return users.filter(
    (user) => user.status === "active" && user.lastActivityAt !== null && Date.parse(user.lastActivityAt) < cutoff,
  ).length;
}
