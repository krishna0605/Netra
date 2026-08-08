from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.core.exceptions import ValidationError

from apps.forensics.models import Case, ProcessingJob
from common.audit import Actor, actor_from_request, visible_cases_for_actor


@dataclass(frozen=True)
class AnalysisScope:
    actor: Actor
    case: Case
    job: ProcessingJob
    analysis: dict[str, Any]


class AnalysisScopeProblem(Exception):
    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code = code
        self.status = status


def resolve_analysis_scope(request, route_ref, job_id: str) -> AnalysisScope:
    actor = actor_from_request(request)
    try:
        case = visible_cases_for_actor(actor).filter(route_ref=route_ref).first()
    except (TypeError, ValueError, ValidationError):
        case = None
    if not case:
        raise AnalysisScopeProblem("analysis_resource_not_found", 404)

    job = ProcessingJob.objects.filter(pk=str(job_id), case=case).first()
    if not job:
        raise AnalysisScopeProblem("analysis_resource_not_found", 404)
    if job.status != ProcessingJob.Status.COMPLETED:
        raise AnalysisScopeProblem("analysis_not_ready", 409)

    analysis = (job.stats or {}).get("analysis")
    if not isinstance(analysis, dict):
        raise AnalysisScopeProblem("analysis_data_unavailable", 409)
    return AnalysisScope(actor=actor, case=case, job=job, analysis=analysis)


def find_analysis_row(scope: AnalysisScope, collection: str, resource_id: str) -> dict[str, Any] | None:
    rows = scope.analysis.get(collection, [])
    if not isinstance(rows, list):
        return None
    return next((row for row in rows if isinstance(row, dict) and str(row.get("id")) == str(resource_id)), None)
