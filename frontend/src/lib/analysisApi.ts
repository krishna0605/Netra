export type AnalysisScopeRef = {
  routeRef: string;
  jobId: string;
};

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
