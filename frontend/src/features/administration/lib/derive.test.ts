import { describe, expect, it } from "vitest";

import { dailyCounts, dormantAccounts, invitationsExpiringToday, topDeniedActor } from "./derive";
import type { ActivityEvent, AdminUser } from "../data/types";

const DAY = 864e5;

function event(partial: Partial<ActivityEvent>): ActivityEvent {
  return {
    id: Math.random().toString(36),
    at: new Date().toISOString(),
    actor: "A. Mehta",
    actorEmail: "a.mehta@gcc.gov.in",
    role: "Analyst",
    action: "permission:export",
    target: "Case",
    result: "denied",
    source: "AccessLog",
    chainIndex: null,
    ...partial,
  };
}

function user(partial: Partial<AdminUser>): AdminUser {
  return {
    id: 1,
    email: "someone@gcc.gov.in",
    name: "Someone",
    roleSlug: "analyst",
    isOwner: false,
    status: "active",
    mfa: "verified",
    department: "Cell",
    supabaseId: "",
    joinedAt: new Date().toISOString(),
    lastSignInAt: null,
    lastActivityAt: null,
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: [],
    caseMemberships: [],
    ...partial,
  };
}

describe("dailyCounts", () => {
  it("returns null when nothing matches, so the caller omits the sparkline", () => {
    expect(dailyCounts([event({ result: "allowed" })], (e) => e.result === "denied")).toBeNull();
  });

  it("returns null when every bucket is zero rather than drawing a flat line", () => {
    // Older than the window: matches the predicate but falls outside every bucket.
    const old = event({ at: new Date(Date.now() - 40 * DAY).toISOString() });
    expect(dailyCounts([old], (e) => e.result === "denied")).toBeNull();
  });

  it("buckets by day with today last", () => {
    const counts = dailyCounts(
      [event({}), event({}), event({ at: new Date(Date.now() - 2 * DAY).toISOString() })],
      (e) => e.result === "denied",
    );

    expect(counts).not.toBeNull();
    expect(counts).toHaveLength(7);
    expect(counts?.at(-1)).toBe(2);
    expect(counts?.at(-3)).toBe(1);
  });
});

describe("topDeniedActor", () => {
  it("ignores allowed events", () => {
    expect(topDeniedActor([event({ result: "allowed", actor: "K. Desai" })])).toBeNull();
  });

  it("returns whoever has the most denials", () => {
    const events = [
      event({ actor: "A. Mehta" }),
      event({ actor: "A. Mehta" }),
      event({ actor: "K. Desai" }),
      event({ actor: "K. Desai", result: "allowed" }),
    ];
    expect(topDeniedActor(events)).toEqual({ name: "A. Mehta", count: 2 });
  });
});

describe("invitationsExpiringToday", () => {
  it("counts only invitations lapsing within the next day", () => {
    const users = [
      user({ id: 1, status: "invited", joinedAt: new Date(Date.now() - 6.5 * DAY).toISOString() }),
      user({ id: 2, status: "invited", joinedAt: new Date(Date.now() - 1 * DAY).toISOString() }),
      user({ id: 3, status: "active", joinedAt: new Date(Date.now() - 6.5 * DAY).toISOString() }),
    ];
    expect(invitationsExpiringToday(users)).toBe(1);
  });

  it("does not count invitations that already lapsed", () => {
    const users = [user({ status: "invited", joinedAt: new Date(Date.now() - 30 * DAY).toISOString() })];
    expect(invitationsExpiringToday(users)).toBe(0);
  });
});

describe("dormantAccounts", () => {
  it("ignores accounts that never signed in, since they are pending rather than dormant", () => {
    expect(dormantAccounts([user({ lastActivityAt: null })])).toBe(0);
  });

  it("counts active accounts quiet for longer than the window", () => {
    const users = [
      user({ id: 1, lastActivityAt: new Date(Date.now() - 120 * DAY).toISOString() }),
      user({ id: 2, lastActivityAt: new Date(Date.now() - 3 * DAY).toISOString() }),
      user({ id: 3, status: "deactivated", lastActivityAt: new Date(Date.now() - 120 * DAY).toISOString() }),
    ];
    expect(dormantAccounts(users)).toBe(1);
  });
});
