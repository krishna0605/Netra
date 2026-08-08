export type AnalysisScopeRef = {
  routeRef: string;
  jobId: string;
};

export function apiErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== "object" || !("error" in payload)) return fallback;
  const error = (payload as { error?: unknown }).error;
  if (typeof error === "string" && error.trim()) return error;
  if (error && typeof error === "object" && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message;
  }
  return fallback;
}

export function findingStatusPath(
  scope: AnalysisScopeRef,
  findingType: "alerts" | "detections",
  findingId: string,
): string {
  const routeRef = encodeURIComponent(scope.routeRef);
  const jobId = encodeURIComponent(scope.jobId);
  const resourceId = encodeURIComponent(findingId);
  return `/workspaces/${routeRef}/analysis/jobs/${jobId}/${findingType}/${resourceId}/status`;
}
