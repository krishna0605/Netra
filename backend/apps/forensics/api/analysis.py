from __future__ import annotations

import json
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import analysis_not_found, api_error
from apps.forensics.services.analysis_scope import AnalysisScope, AnalysisScopeProblem, find_analysis_row, resolve_analysis_scope
from common.audit import can, log_access
from common.persistence import FindingUpdateProblem, update_scoped_finding_status


logger = logging.getLogger(__name__)


def _scope_or_error(request, route_ref, job_id):
    try:
        return resolve_analysis_scope(request, route_ref, job_id)
    except AnalysisScopeProblem as exc:
        messages = {
            "analysis_not_ready": "The selected analysis job has not completed.",
            "analysis_data_unavailable": "The selected analysis data is unavailable.",
        }
        return api_error(
            request,
            exc.code,
            messages.get(exc.code, "The requested analysis resource was not found."),
            status=exc.status,
        )


def _rows(scope: AnalysisScope, key: str) -> list[dict]:
    value = scope.analysis.get(key, [])
    return value if isinstance(value, list) else []


def _filtered(rows: list[dict], request, mapping: dict[str, str]) -> list[dict]:
    result = rows
    for query_name, field_name in mapping.items():
        expected = request.GET.get(query_name)
        if expected not in (None, "", "all"):
            result = [row for row in result if str(row.get(field_name, "")).lower() == expected.lower()]
    return result


def _paged(rows: list[dict], request) -> dict:
    try:
        limit = max(1, min(500, int(request.GET.get("limit", "100"))))
        offset = max(0, int(request.GET.get("offset", "0")))
    except ValueError:
        limit, offset = 100, 0
    next_offset = offset + limit if offset + limit < len(rows) else None
    return {
        "count": len(rows),
        "limit": limit,
        "offset": offset,
        "nextOffset": next_offset,
        "results": rows[offset : offset + limit],
    }


def _resource_response(request, route_ref, job_id, collection: str, resource_id: str):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    row = find_analysis_row(scope, collection, resource_id)
    return JsonResponse(row) if row else analysis_not_found(request)


@require_http_methods(["GET"])
def summary(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    summary_data = scope.analysis.get("summary") if isinstance(scope.analysis.get("summary"), dict) else {}
    return JsonResponse(
        summary_data
        | {
            "case": scope.analysis.get("case"),
            "evidence": scope.analysis.get("evidence"),
            "zeek": scope.analysis.get("zeek", summary_data.get("zeek")),
            "topAttackClass": scope.analysis.get("topAttackClass", summary_data.get("topAttackClass", "Normal Baseline")),
            "riskLevel": scope.analysis.get("riskLevel", summary_data.get("riskLevel", "low")),
            "toolStatus": scope.analysis.get("toolStatus", summary_data.get("toolStatus", {})),
        }
    )


@require_http_methods(["GET"])
def traffic_timeline(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    return scope if isinstance(scope, JsonResponse) else JsonResponse({"results": _rows(scope, "trafficTimeline")})


@require_http_methods(["GET"])
def protocol_distribution(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    return scope if isinstance(scope, JsonResponse) else JsonResponse({"results": _rows(scope, "protocolChartData")})


@require_http_methods(["GET"])
def alerts(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = _filtered(_rows(scope, "alerts"), request, {"severity": "severity", "attackClass": "attackClass", "status": "status"})
    return JsonResponse({"results": rows})


@require_http_methods(["GET"])
def packets(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = _filtered(
        _rows(scope, "packets"),
        request,
        {"sourceIp": "sourceIp", "destinationIp": "destinationIp", "protocol": "protocol", "sessionId": "sessionId", "severity": "severity"},
    )
    return JsonResponse(_paged(rows, request))


@require_http_methods(["GET"])
def packet_detail(request, route_ref, job_id, packet_id):
    return _resource_response(request, route_ref, job_id, "packets", packet_id)


@require_http_methods(["GET"])
def sessions(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = _filtered(_rows(scope, "sessions"), request, {"source": "source", "destination": "destination", "protocol": "protocol"})
    return JsonResponse(_paged(rows, request))


@require_http_methods(["GET"])
def session_detail(request, route_ref, job_id, session_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    row = find_analysis_row(scope, "sessions", session_id)
    if not row:
        return analysis_not_found(request)
    return JsonResponse(row | {"reconstruction": f"{row.get('packetCount', 0)} packet(s) reconstructed from uploaded PCAP metadata."})


@require_http_methods(["GET"])
def session_timeline(request, route_ref, job_id, session_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    row = find_analysis_row(scope, "sessions", session_id)
    if not row:
        return analysis_not_found(request)
    return JsonResponse(
        {
            "sessionId": session_id,
            "results": [
                {"time": row.get("startTime"), "event": "Session started"},
                {"time": row.get("endTime"), "event": "Session ended"},
            ],
        }
    )


@require_http_methods(["GET"])
def decoder(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    return JsonResponse(
        {
            "encryptedTrafficPolicy": "Encrypted content is not decrypted; metadata patterns are analyzed.",
            "results": _rows(scope, "decodedProtocols"),
            "zeek": scope.analysis.get("zeek", {}),
        }
    )


@require_http_methods(["GET"])
def decoder_protocol(request, route_ref, job_id, protocol):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = [row for row in _rows(scope, "decodedProtocols") if protocol.lower() in str(row.get("protocol", "")).lower()]
    return JsonResponse({"protocol": protocol, "results": rows})


@require_http_methods(["GET"])
def payloads(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = _filtered(_rows(scope, "payloadFindings"), request, {"protocol": "protocol", "risk": "risk"})
    return JsonResponse({"results": rows})


@require_http_methods(["GET"])
def payload_detail(request, route_ref, job_id, finding_id):
    return _resource_response(request, route_ref, job_id, "payloadFindings", finding_id)


@require_http_methods(["GET"])
def detections(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    rows = _rows(scope, "detectionMatches")
    category = request.GET.get("category")
    if category and category != "all":
        rows = [row for row in rows if category.lower() in str(row.get("category", "")).lower() or category.lower() in str(row.get("ruleName", "")).lower()]
    return JsonResponse({"results": rows})


@require_http_methods(["GET"])
def anomalies(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    return scope if isinstance(scope, JsonResponse) else JsonResponse({"results": _rows(scope, "anomalies")})


@require_http_methods(["GET"])
def anomaly_baseline(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    return JsonResponse(
        {
            "results": [
                {"metric": row.get("behaviour"), "baseline": row.get("baseline"), "observed": row.get("observed"), "confidence": row.get("confidence")}
                for row in _rows(scope, "anomalies")
            ]
        }
    )


@require_http_methods(["GET"])
def anomaly_risk_timeline(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    return JsonResponse({"results": [{"time": row.get("time"), "risk": min(100, row.get("alerts", 0) * 20)} for row in _rows(scope, "trafficTimeline")]})


@require_http_methods(["GET"])
def graph(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    return scope if isinstance(scope, JsonResponse) else JsonResponse(scope.analysis.get("graph", {"nodes": [], "edges": []}))


@require_http_methods(["GET"])
def graph_node(request, route_ref, job_id, node_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    graph_data = scope.analysis.get("graph") if isinstance(scope.analysis.get("graph"), dict) else {}
    node = next((row for row in graph_data.get("nodes", []) if str(row.get("id")) == str(node_id)), None)
    if not node:
        return analysis_not_found(request)
    related_alerts = [alert for alert in _rows(scope, "alerts") if alert.get("id") in node.get("alertIds", [])]
    return JsonResponse({"id": node_id, "riskScore": node.get("risk", 0), "node": node, "relatedAlerts": related_alerts})


@require_http_methods(["GET"])
def graph_attack_path(request, route_ref, job_id):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    graph_data = scope.analysis.get("graph") if isinstance(scope.analysis.get("graph"), dict) else {"edges": []}
    edges = graph_data.get("edges", [])
    path = [edges[0].get("source"), edges[0].get("target")] if edges else []
    return JsonResponse({"path": path})


def _finding_status(request, route_ref, job_id, finding_id: str, finding_type: str):
    scope = _scope_or_error(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    try:
        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return api_error(request, "invalid_request_body", "A valid JSON request body is required.", status=400)
    status_value = str(payload.get("status") or "").strip().lower()
    if status_value not in {"reviewing", "confirmed", "dismissed"}:
        return api_error(
            request,
            "invalid_finding_status",
            "Status must be reviewing, confirmed, or dismissed.",
            status=400,
        )
    permission = "confirm" if status_value in {"confirmed", "dismissed"} else "review"
    if not can(scope.actor, permission):
        log_access(
            scope.actor,
            f"permission:{permission}",
            case=scope.case,
            resource_type="Alert" if finding_type == "alert" else "DetectionMatch",
            resource_id=finding_id,
            result="denied",
        )
        return api_error(request, "permission_denied", "Permission denied.", status=403)
    try:
        updated = update_scoped_finding_status(
            case=scope.case,
            job=scope.job,
            finding_type=finding_type,
            finding_id=finding_id,
            status=status_value,
            actor=scope.actor,
        )
    except FindingUpdateProblem as exc:
        messages = {
            "analysis_data_unavailable": "The selected analysis data is unavailable.",
            "analysis_consistency_error": "The selected finding is inconsistent and was not changed.",
        }
        return api_error(
            request,
            exc.code,
            messages.get(exc.code, "The requested analysis resource was not found."),
            status=exc.status,
        )
    return JsonResponse(updated)


@csrf_exempt
@require_http_methods(["PATCH"])
def alert_status(request, route_ref, job_id, alert_id):
    return _finding_status(request, route_ref, job_id, alert_id, "alert")


@csrf_exempt
@require_http_methods(["PATCH"])
def detection_status(request, route_ref, job_id, match_id):
    return _finding_status(request, route_ref, job_id, match_id, "detection")


def legacy_scope(request):
    route_ref = (request.GET.get("caseRef") or "").strip()
    job_id = (request.GET.get("jobId") or "").strip()
    if not route_ref or not job_id:
        return api_error(
            request,
            "analysis_scope_required",
            "A workspace reference and analysis job are required.",
            status=400,
        )
    return route_ref, job_id


def deprecated(response: JsonResponse, route_name: str) -> JsonResponse:
    logger.info("Legacy analysis API used: %s", route_name)
    response["Deprecation"] = "true"
    response["Warning"] = '299 - "Use workspace/job-scoped analysis API"'
    response["Link"] = '</docs/api/analysis-scoping>; rel="deprecation"'
    return response


def legacy(request, canonical, route_name: str, **resource_kwargs):
    scope = legacy_scope(request)
    if isinstance(scope, JsonResponse):
        return scope
    route_ref, job_id = scope
    return deprecated(canonical(request, route_ref, job_id, **resource_kwargs), route_name)


def legacy_summary(request):
    return legacy(request, summary, "dashboard.summary")


def legacy_traffic_timeline(request):
    return legacy(request, traffic_timeline, "dashboard.traffic_timeline")


def legacy_protocol_distribution(request):
    return legacy(request, protocol_distribution, "dashboard.protocol_distribution")


def legacy_alerts(request):
    return legacy(request, alerts, "alerts.list")


def legacy_packets(request):
    return legacy(request, packets, "packets.list")


def legacy_packet_detail(request, packet_id):
    return legacy(request, packet_detail, "packets.detail", packet_id=packet_id)


def legacy_sessions(request):
    return legacy(request, sessions, "sessions.list")


def legacy_session_detail(request, session_id):
    return legacy(request, session_detail, "sessions.detail", session_id=session_id)


def legacy_session_timeline(request, session_id):
    return legacy(request, session_timeline, "sessions.timeline", session_id=session_id)


def legacy_decoder(request):
    return legacy(request, decoder, "decoder.summary")


def legacy_decoder_protocol(request, protocol):
    return legacy(request, decoder_protocol, "decoder.protocol", protocol=protocol)


def legacy_payloads(request):
    return legacy(request, payloads, "payloads.list")


def legacy_payload_detail(request, finding_id):
    return legacy(request, payload_detail, "payloads.detail", finding_id=finding_id)


def legacy_detections(request):
    return legacy(request, detections, "detections.list")


def legacy_anomalies(request):
    return legacy(request, anomalies, "anomalies.list")


def legacy_anomaly_baseline(request):
    return legacy(request, anomaly_baseline, "anomalies.baseline")


def legacy_anomaly_risk_timeline(request):
    return legacy(request, anomaly_risk_timeline, "anomalies.risk_timeline")


def legacy_graph(request):
    return legacy(request, graph, "graph")


def legacy_graph_node(request, node_id):
    return legacy(request, graph_node, "graph.node", node_id=node_id)


def legacy_graph_attack_path(request):
    return legacy(request, graph_attack_path, "graph.attack_path")


@csrf_exempt
@require_http_methods(["PATCH"])
def legacy_alert_status(request, alert_id):
    return legacy(request, alert_status, "alerts.status", alert_id=alert_id)


@csrf_exempt
@require_http_methods(["PATCH"])
def legacy_detection_status(request, match_id):
    return legacy(request, detection_status, "detections.status", match_id=match_id)
