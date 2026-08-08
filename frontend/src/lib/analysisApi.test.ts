import { describe, expect, it } from "vitest";

import { findingStatusPath } from "./analysisApi";


describe("findingStatusPath", () => {
  it("places workspace and job scope in the canonical URL", () => {
    expect(
      findingStatusPath(
        { routeRef: "b9d9cd4a-4fea-44fd-849f-bcbe3cf81b8b", jobId: "job/one" },
        "detections",
        "finding one",
      ),
    ).toBe(
      "/workspaces/b9d9cd4a-4fea-44fd-849f-bcbe3cf81b8b/analysis/jobs/job%2Fone/detections/finding%20one/status",
    );
  });
});
