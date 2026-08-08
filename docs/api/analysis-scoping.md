# Analysis API scoping and compatibility

## Canonical scope

Every granular analysis request identifies both the visible workspace and the selected processing job:

```text
/api/workspaces/{routeRef}/analysis/jobs/{jobId}/{resource}
```

The server resolves `routeRef` through the authenticated actor's visible cases, then resolves `jobId` with `case=resolved_case`. Resource IDs are searched only inside that job's analysis document. Clients cannot establish authorization using a case ID in a mutation body.

Read routes accept GET only. Alert and detection status routes accept PATCH only with this body:

```json
{
  "status": "confirmed"
}
```

Allowed status values are `reviewing`, `confirmed`, and `dismissed`.

## Errors

Errors use a stable envelope with `code`, `message`, and `requestId`. Unauthorized and nonexistent workspace/job/resource combinations deliberately return the same `404 analysis_resource_not_found`. Incomplete jobs return `409 analysis_not_ready`; malformed completed-job analysis returns `409 analysis_data_unavailable`.

## Compatibility routes

Legacy granular paths remain for one observation release. They require both query parameters:

```text
?caseRef={routeRef}&jobId={jobId}
```

They call the same resolver and canonical handler, and return `Deprecation`, `Warning`, and migration `Link` headers. Missing scope returns `400 analysis_scope_required`. Compatibility calls are logged by route name without resource content.

Compatibility removal requires evidence of zero legacy calls during the later observation phase. There is no global-latest-job fallback for administrators or other roles.
