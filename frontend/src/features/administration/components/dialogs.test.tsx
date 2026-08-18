import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { AddUserDialog } from "./AddUserDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { AuthContext, type AuthValue } from "../features/auth/AuthContext";
import { DirectoryProvider } from "../data/store";
import { GrantPermissionDialog } from "./GrantPermissionDialog";
import { PasswordDialog } from "./PasswordDialog";
import { currentDirectory, resetDirectory } from "../data/client";
import { supabase } from "../lib/supabase";
import { USERS } from "../data/mock";

/**
 * These cover one property: a dialog that can do something irreversible must
 * not let you do it until every condition is met. That gate is the last thing
 * standing between a mis-click and a real change, and it is invisible when it
 * silently stops working.
 */

const user = USERS[2];

function withProvider(node: React.ReactNode) {
  // Both providers, because the dialogs now step up through the auth context
  // before they write. A dialog rendered without it would throw, which is the
  // correct behaviour — a confirmation that cannot re-prove the authenticator
  // must not offer to do the thing.
  const auth: AuthValue = {
    stage: "active",
    profile: { userId: "admin-1", email: "admin@gcc.gov.in", displayName: "Admin", role: "Administrator", organizationName: "GCC", isOwner: false, isAdministrative: true },
    verifiedAt: null,
    error: "",
    busy: false,
    signIn: async () => undefined,
    verifyCode: async () => undefined,
    stepUp: async (code) => {
      const { data, error } = await supabase.auth.mfa.listFactors();
      const factor = data?.totp?.find((item) => item.status === "verified") ?? data?.totp?.[0];
      if (error || !factor) return "No authenticator is enrolled on this account.";
      const result = await supabase.auth.mfa.challengeAndVerify({ factorId: factor.id, code });
      return result.error ? "That code was not accepted. Codes expire after 30 seconds." : "";
    },
    chooseAdministration: () => undefined,
    returnToChooser: () => undefined,
    signOut: async () => undefined,
    clearError: () => undefined,
    isStepUpFresh: () => false,
  };
  return render(<AuthContext.Provider value={auth}><DirectoryProvider>{node}</DirectoryProvider></AuthContext.Provider>);
}

function typeInto(element: HTMLElement, value: string) {
  fireEvent.change(element, { target: { value } });
}

beforeEach(() => {
  resetDirectory();
  vi.clearAllMocks();

  // The dialogs reach the network now. Stubbed here so these stay tests of the
  // dialogs rather than of the transport, which has its own.
  // The authenticator is proved against Supabase before every write now.
  vi.spyOn(supabase.auth.mfa, "listFactors").mockResolvedValue({
    data: { totp: [{ id: "factor-1", status: "verified" }], all: [], phone: [] },
    error: null,
  } as unknown as Awaited<ReturnType<typeof supabase.auth.mfa.listFactors>>);
  vi.spyOn(supabase.auth.mfa, "challengeAndVerify").mockResolvedValue({
    data: {},
    error: null,
  } as unknown as Awaited<ReturnType<typeof supabase.auth.mfa.challengeAndVerify>>);
  vi.spyOn(supabase.auth, "signOut").mockResolvedValue({ error: null } as never);
  vi.spyOn(supabase.auth, "getSession").mockResolvedValue({
    data: { session: { access_token: "test-token" } },
    error: null,
  } as unknown as Awaited<ReturnType<typeof supabase.auth.getSession>>);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      String(url).endsWith("/admin/v1/directory")
        ? new Response(JSON.stringify(currentDirectory()), { status: 200 })
        : new Response(
            JSON.stringify({
              user: { id: 41, email: "a.patel@gcc.gov.in", name: "A. Patel", roleSlug: "viewer", department: "Cell", status: "active" },
              password: "ServerChose#9wQz",
            }),
            { status: 200 },
          ),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("ConfirmDialog", () => {
  const consequences = ["They are signed out immediately.", "Nothing is deleted."];

  it("keeps the action disabled until reason and code are both satisfied", () => {
    withProvider(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Deactivate account"
        consequences={consequences}
        confirmLabel="Deactivate"
        onConfirm={async () => {}}
      />,
    );

    const confirm = screen.getByRole("button", { name: "Deactivate" });
    expect(confirm).toBeDisabled();

    typeInto(screen.getByLabelText("Reason"), "Left the department last week.");
    expect(confirm).toBeDisabled();

    typeInto(screen.getByLabelText("Confirm with your authenticator"), "123456");
    expect(confirm).toBeEnabled();
  });

  it("rejects a reason too short to be worth reading", () => {
    withProvider(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Deactivate account"
        consequences={consequences}
        confirmLabel="Deactivate"
        onConfirm={async () => {}}
      />,
    );

    typeInto(screen.getByLabelText("Reason"), "no");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "123456");
    expect(screen.getByRole("button", { name: "Deactivate" })).toBeDisabled();
  });

  it("requires the exact confirmation phrase when one is demanded", () => {
    withProvider(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Transfer"
        consequences={consequences}
        confirmLabel="Transfer"
        typeToConfirm="Gujarat Cyber Crime Cell"
        onConfirm={async () => {}}
      />,
    );

    const confirm = screen.getByRole("button", { name: "Transfer" });
    typeInto(screen.getByLabelText("Reason"), "Handing over at end of posting.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "123456");
    expect(confirm).toBeDisabled();

    typeInto(screen.getByLabelText(/Type/), "Gujarat Cyber Crime");
    expect(confirm).toBeDisabled();

    typeInto(screen.getByLabelText(/Type/), "Gujarat Cyber Crime Cell");
    expect(confirm).toBeEnabled();
  });

  it("stays open and shows why when the action fails", async () => {
    withProvider(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Deactivate account"
        consequences={consequences}
        confirmLabel="Deactivate"
        onConfirm={async () => {
          throw new Error("The owner cannot be deactivated.");
        }}
      />,
    );

    typeInto(screen.getByLabelText("Reason"), "Left the department last week.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "123456");
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));

    // Closing over a failed write would discard the typed reason and imply
    // the action succeeded.
    expect(await screen.findByRole("alert")).toHaveTextContent("The owner cannot be deactivated.");
    expect(screen.getByLabelText("Reason")).toHaveValue("Left the department last week.");
  });

  it("accepts only digits in the authenticator field", () => {
    withProvider(
      <ConfirmDialog
        open
        onOpenChange={() => {}}
        title="Deactivate account"
        consequences={consequences}
        confirmLabel="Deactivate"
        onConfirm={async () => {}}
      />,
    );

    const code = screen.getByLabelText("Confirm with your authenticator");
    typeInto(code, "12ab34cd56");
    expect(code).toHaveValue("123456");
  });
});

describe("PasswordDialog", () => {
  it("will not submit without a strong password, a reason and a code", () => {
    withProvider(<PasswordDialog user={user} open onOpenChange={() => {}} />);

    const submit = screen.getByRole("button", { name: "Set password" });
    // A password is generated on open, so that condition already holds.
    expect(submit).toBeDisabled();

    typeInto(screen.getByLabelText("Reason"), "Credential reported as shared.");
    expect(submit).toBeDisabled();

    typeInto(screen.getByLabelText("Confirm with your authenticator"), "774120");
    expect(submit).toBeEnabled();
  });

  it("does not let an administrator choose another user's password", () => {
    withProvider(<PasswordDialog user={user} open onOpenChange={() => {}} />);
    expect(screen.queryByLabelText("New password")).not.toBeInTheDocument();
    expect(screen.getByText(/cannot view the current password or choose a permanent replacement/i)).toBeInTheDocument();
  });

  it("shows the password once after it is set, and says what else happened", async () => {
    withProvider(<PasswordDialog user={user} open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("Reason"), "Credential reported as shared.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "774120");
    fireEvent.click(screen.getByRole("button", { name: "Set password" }));

    await waitFor(() => expect(screen.getByText("Password replaced")).toBeInTheDocument());
    // What the server applied, not what the dialog proposed. The server may
    // have generated its own, and handing over the wrong one gives an officer
    // a credential that does not work.
    expect(screen.getByText("ServerChose#9wQz")).toBeInTheDocument();
    expect(screen.getByText(/Every existing session has been ended/)).toBeInTheDocument();
  });

  it("states that sessions end rather than offering it as a choice", () => {
    // It used to be a checkbox. The server now always revokes, so a control
    // implying otherwise would describe behaviour that does not exist.
    withProvider(<PasswordDialog user={user} open onOpenChange={() => {}} />);

    expect(screen.queryByLabelText(/End every session/)).toBeNull();
    expect(screen.getByText(/Every session this account has open will end/)).toBeInTheDocument();
  });
});

describe("GrantPermissionDialog", () => {
  it("will not submit until a permission is chosen", () => {
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);
    const submit = screen.getByRole("button", { name: "Grant permission" });
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "482913");
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: /^Grant view/ }));
    expect(submit).toBeEnabled();
  });

  it("will not submit without the authenticator, because the server will refuse it", () => {
    // The code is proved against Supabase before the write. Leaving it out
    // means the token carries no recent factor and the operation is refused
    // for staleness — better to stop here than to fail after the fact.
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /^Grant view/ }));

    expect(screen.getByRole("button", { name: "Grant permission" })).toBeDisabled();
  });

  it("demands a written reason for a high-risk permission", () => {
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);

    // operations is classified high-risk; view is not.
    fireEvent.click(screen.getByRole("button", { name: /^Grant operations/ }));
    const submit = screen.getByRole("button", { name: "Grant permission" });
    expect(submit).toBeDisabled();

    typeInto(screen.getByLabelText(/Reason/), "Needed for the sensor rollout this week.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "482913");
    expect(submit).toBeEnabled();
  });

  it("warns when a grant is given no expiry", () => {
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("Expires after"), "0");
    expect(screen.getByText(/has to be withdrawn by hand/)).toBeInTheDocument();
  });
});

describe("AddUserDialog delivery", () => {
  /**
   * An invitation is a link and nothing else. Where mail is not reaching the
   * officer it leaves an account nobody can enter, so the dialog has to offer
   * the path that does not depend on delivery — and has to open on it, because
   * the failure is silent from the operator's side.
   */
  it("opens with a generated password already filled in", () => {
    withProvider(<AddUserDialog open onOpenChange={() => {}} />);

    expect(screen.getByRole("radio", { name: /Auto-generate/ })).toBeChecked();
    // Pre-filled so the common case is one click, and long enough to pass the
    // floor the server enforces.
    expect((screen.getByLabelText("Password") as HTMLInputElement).value.length).toBeGreaterThanOrEqual(12);
  });

  it("refuses to submit a weak password the operator typed", () => {
    withProvider(<AddUserDialog open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("Full name"), "K. Vyas");
    typeInto(screen.getByLabelText("Official email"), "k.vyas@gcc.gov.in");
    typeInto(screen.getByLabelText(/^Reason/), "Onboarding for the demonstration.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "482913");

    fireEvent.click(screen.getByRole("radio", { name: /Set one myself/ }));
    typeInto(screen.getByLabelText("Password"), "password");

    expect(screen.getByRole("button", { name: "Create account" })).toBeDisabled();
    expect(screen.getByText(/three character types/)).toBeInTheDocument();

    typeInto(screen.getByLabelText("Password"), "Handover-Credential-42");
    expect(screen.getByRole("button", { name: "Create account" })).toBeEnabled();
  });

  it("states the reason floor instead of only disabling the button", () => {
    withProvider(<AddUserDialog open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("Full name"), "K. Vyas");
    typeInto(screen.getByLabelText("Official email"), "k.vyas@gcc.gov.in");
    typeInto(screen.getByLabelText(/^Reason/), "too short");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "482913");

    expect(screen.getByRole("button", { name: "Create account" })).toBeDisabled();
    expect(screen.getByText(/at least 10 characters/)).toBeInTheDocument();

    typeInto(screen.getByLabelText(/^Reason/), "Onboarding for the demonstration.");
    expect(screen.getByRole("button", { name: "Create account" })).toBeEnabled();
  });
});
