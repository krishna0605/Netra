import type { Page, Route } from "@playwright/test";

type Role = "Admin" | "Investigator";
type Aal = "aal1" | "aal2";

const userId = "11111111-1111-4111-8111-111111111111";
const organizationId = "d1a04e58-9de1-5ed9-82d0-68b836ef3e10";
const routeRef = "22222222-2222-4222-8222-222222222222";

function base64Url(value: object) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function accessToken(aal: Aal) {
  const now = Math.floor(Date.now() / 1000);
  return `${base64Url({ alg: "ES256", typ: "JWT", kid: "browser-test" })}.${base64Url({
    sub: userId,
    email: "officer@example.test",
    role: "authenticated",
    aud: "authenticated",
    iss: "https://netra-auth.test/auth/v1",
    aal,
    iat: now,
    exp: now + 3600,
  })}.browser-test-signature`;
}

function factor(verified: boolean) {
  return {
    id: "factor-test-001",
    factor_type: "totp",
    friendly_name: "Netra test authenticator",
    status: verified ? "verified" : "unverified",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

function session(aal: Aal, verifiedFactor: boolean) {
  return {
    access_token: accessToken(aal),
    refresh_token: "browser-test-refresh-token",
    expires_in: 3600,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    token_type: "bearer",
    user: {
      id: userId,
      aud: "authenticated",
      role: "authenticated",
      email: "officer@example.test",
      app_metadata: { provider: "email", providers: ["email"] },
      user_metadata: {},
      factors: verifiedFactor ? [factor(true)] : [],
      created_at: new Date().toISOString(),
    },
  };
}

function profile(role: Role, aal: Aal, enrollmentRequired: boolean) {
  const moduleAccess = { enabled: true, visible: true, reason: "Available in the browser fixture." };
  return {
    user: "Synthetic Officer",
    department: "Netra Test Organization",
    role,
    aal,
    mfaPolicy: "admin_required",
    mfaEnrollmentRequired: enrollmentRequired,
    privilegedAdminReady: role === "Admin" && aal === "aal2",
    organization: { id: organizationId, name: "Netra", slug: "netra" },
    capabilities: { sse: { key: "sse", implemented: true, enabled: false, state: "disabled", reason: "Disabled in browser fixtures." } },
    deployment: {
      profile: "browser-test",
      hostCaptureEnabled: false,
      replayEnabled: false,
      sensorCaptureEnabled: false,
      modules: {
        lab: moduleAccess,
        sensors: moduleAccess,
        schedules: moduleAccess,
        integrations: moduleAccess,
        retention: moduleAccess,
        system: moduleAccess,
      },
    },
  };
}

const caseRecord = {
  id: "CASE-SYNTHETIC-001",
  routeRef,
  title: "Synthetic authorized investigation",
  investigator: "Synthetic Officer",
  department: "Netra Test Organization",
  status: "open",
  priority: "Standard",
  flags: ["synthetic"],
  notes: [],
  history: [],
  analysisStatus: { state: "completed", progress: 100, step: "completed", steps: [] },
};

const workspace = {
  case: caseRecord,
  evidence: null,
  summary: { packets: 1, sessions: 1, protocolsDecoded: 1, payloadFindings: 0, alerts: 0, anomalies: 0, topAttackClass: "Normal Baseline", riskLevel: "low", toolStatus: {}, zeek: null },
  suspiciousActivity: { alerts: [], anomalies: [], communicationMap: { nodes: [], edges: [] } },
  trafficEvidence: { packetsPreview: [], sessionsPreview: [], protocols: [], payloadClues: [], communicationMap: { nodes: [], edges: [] } },
  charts: { timeline: [], protocols: [] },
};

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

export async function installNetraFixture(page: Page, options: { role: Role; aal: Aal; verifiedFactor: boolean; enrollmentRequired?: boolean }) {
  const storedSession = session(options.aal, options.verifiedFactor);
  let authMeRequests = 0;
  await page.addInitScript((value) => {
    window.sessionStorage.setItem("sb-netra-auth-auth-token", JSON.stringify(value));
  }, storedSession);

  await page.route("https://netra-auth.test/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/auth/v1/user")) {
      await fulfillJson(route, storedSession.user);
      return;
    }
    if (url.pathname.endsWith("/auth/v1/factors") && route.request().method() === "POST") {
      await fulfillJson(route, { ...factor(false), totp: { qr_code: "data:image/svg+xml;base64,PHN2Zy8+", secret: "SYNTHETICTOTPSECRET", uri: "otpauth://totp/Netra:test" } });
      return;
    }
    if (url.pathname.includes("/challenge")) {
      await fulfillJson(route, { id: "challenge-test-001", expires_at: Math.floor(Date.now() / 1000) + 60 });
      return;
    }
    if (url.pathname.includes("/verify")) {
      await fulfillJson(route, { ...session("aal2", true), access_token: accessToken("aal2") });
      return;
    }
    if (url.pathname.includes("/logout")) {
      await fulfillJson(route, {});
      return;
    }
    await fulfillJson(route, { message: "Unrecognized mocked Auth route" }, 404);
  });

  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api/, "");
    if (path === "/auth/me") {
      authMeRequests += 1;
      await fulfillJson(route, profile(options.role, options.aal, options.enrollmentRequired ?? false));
      return;
    }
    if (path === "/cases") {
      await fulfillJson(route, { results: [caseRecord] });
      return;
    }
    if (path === `/workspaces/${routeRef}`) {
      await fulfillJson(route, { workspace });
      return;
    }
    if (path === "/users") {
      await fulfillJson(route, { users: [], results: [], nextCursor: null, authMetadataStatus: "available" });
      return;
    }
    if (path.startsWith("/events/stream")) {
      await route.fulfill({ status: 204, body: "" });
      return;
    }
    await fulfillJson(route, { results: [] });
  });
  return { authMeRequests: () => authMeRequests };
}

export const fixtureRoutes = {
  cases: "/app/v/14e61a2b-40b2-4c73-bd5c-d75b832322ad",
  analysis: "/app/v/7cab94c3-622f-46b0-b3e4-7e8ea6df0831",
  activity: "/app/v/1310f49a-114e-4c91-ae05-587c23f65dc9",
  evidence: "/app/v/1b438ac1-72e9-4413-a28d-cc87ea35ab54",
  reports: "/app/v/dca32a39-8348-4f14-b62a-fdba9987e234",
  settings: "/app/v/4c1bed57-4a3b-4c98-a7ee-778b5500eb91",
  admin: "/app/admin/users",
};
