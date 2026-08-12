import { AuthLayout } from "./AuthLayout";
import { Button } from "../../components/ui/primitives";
import { useAuth } from "./AuthContext";

/**
 * Shown when an account authenticates successfully but holds no administrative
 * role. Says nothing about what exists or what the account would need — it is
 * the same message whether the workspace is real, empty, or forbidden.
 */
export function NotPermittedPage() {
  const { signOut } = useAuth();

  return (
    <AuthLayout title="Not available" subtitle="This workspace is not available for your account.">
      <div className="flex flex-col gap-4">
        <p className="text-[13.5px] leading-relaxed text-sand-muted">
          If you believe this is a mistake, contact your department administrator.
        </p>
        <Button variant="outline" onClick={() => void signOut()} className="w-full">
          Sign out
        </Button>
      </div>
    </AuthLayout>
  );
}
