import { AuthLayout } from "./AuthLayout";
import { Button } from "../../components/ui/primitives";
import { useAuth } from "./AuthContext";
import { useT } from "../../i18n";

/**
 * Shown when an account authenticates successfully but holds no administrative
 * role. Says nothing about what exists or what the account would need — it is
 * the same message whether the workspace is real, empty, or forbidden.
 */
export function NotPermittedPage() {
  const { signOut } = useAuth();
  const t = useT();

  return (
    <AuthLayout title={t("notAvailable")} subtitle={t("notAvailableSubtitle")}>
      <div className="flex flex-col gap-4">
        <p className="text-[13.5px] leading-relaxed text-sand-muted">
          {t("notAvailableBody")}
        </p>
        <Button variant="outline" onClick={() => void signOut()} className="w-full">
          {t("signOut")}
        </Button>
      </div>
    </AuthLayout>
  );
}
