import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ConfirmDialog } from "./ConfirmDialog";
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
  return render(<DirectoryProvider>{node}</DirectoryProvider>);
}

function typeInto(element: HTMLElement, value: string) {
  fireEvent.change(element, { target: { value } });
}

beforeEach(() => {
  resetDirectory();
  vi.clearAllMocks();

  // The dialogs reach the network now. Stubbed here so these stay tests of the
  // dialogs rather than of the transport, which has its own.
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
    render(
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
    render(
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
    render(
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
    render(
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
    render(
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

  it("blocks a weak password even when everything else is filled in", () => {
    withProvider(<PasswordDialog user={user} open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("New password"), "abc");
    typeInto(screen.getByLabelText("Reason"), "Credential reported as shared.");
    typeInto(screen.getByLabelText("Confirm with your authenticator"), "774120");

    expect(screen.getByRole("button", { name: "Set password" })).toBeDisabled();
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
    expect(screen.getByRole("button", { name: "Grant permission" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: /^Grant view/ }));
    expect(screen.getByRole("button", { name: "Grant permission" })).toBeEnabled();
  });

  it("demands a written reason for a high-risk permission", () => {
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);

    // operations is classified high-risk; view is not.
    fireEvent.click(screen.getByRole("button", { name: /^Grant operations/ }));
    const submit = screen.getByRole("button", { name: "Grant permission" });
    expect(submit).toBeDisabled();

    typeInto(screen.getByLabelText(/Reason/), "Needed for the sensor rollout this week.");
    expect(submit).toBeEnabled();
  });

  it("warns when a grant is given no expiry", () => {
    withProvider(<GrantPermissionDialog user={user} open onOpenChange={() => {}} />);

    typeInto(screen.getByLabelText("Expires after"), "0");
    expect(screen.getByText(/has to be withdrawn by hand/)).toBeInTheDocument();
  });
});
