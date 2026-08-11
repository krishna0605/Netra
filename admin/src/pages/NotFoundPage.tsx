import { Link } from "react-router-dom";

import { Button } from "../components/ui/primitives";
import { PageBody, PageHeader } from "../components/common";

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" summary="That route does not exist in the admin console." />
      <PageBody>
        <Button asChild variant="outline" className="self-start">
          <Link to="/">Back to overview</Link>
        </Button>
      </PageBody>
    </>
  );
}
