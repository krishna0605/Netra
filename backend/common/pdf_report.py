from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _text(value: Any, fallback: str = "-") -> str:
    if value is None:
        return fallback
    rendered = str(value).strip()
    return rendered if rendered else fallback


def _para(value: Any, style: ParagraphStyle) -> Paragraph:
    escaped = _text(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(escaped, style)


def _table(rows: list[list[Any]], widths: list[float], styles: dict[str, ParagraphStyle]) -> Table:
    converted = []
    for row_index, row in enumerate(rows):
        cell_style = styles["HeaderCell"] if row_index == 0 else styles["Cell"]
        converted.append([cell if hasattr(cell, "wrap") else _para(cell, cell_style) for cell in row])
    table = Table(converted, colWidths=widths, hAlign="LEFT", repeatRows=1 if len(rows) > 1 else 0)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f9fafb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _section(title: str, body: list[Any], styles: dict[str, ParagraphStyle]) -> KeepTogether:
    return KeepTogether([Paragraph(title, styles["SectionTitle"]), Spacer(1, 4), *body, Spacer(1, 10)])


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6b7280"))
    canvas.drawString(18 * mm, 12 * mm, "Netra Forensic Report - generated from persisted case evidence")
    canvas.drawRightString(192 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_report_pdf(analysis: dict[str, Any], language: str, legal: dict[str, Any], custody: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"Netra forensic report {_text(analysis.get('caseId'))}",
        author="Netra Network Forensics",
    )

    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("NetraTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=colors.HexColor("#111827"), spaceAfter=8),
        "Subtitle": ParagraphStyle("NetraSubtitle", parent=base["BodyText"], fontSize=10, leading=14, textColor=colors.HexColor("#4b5563")),
        "SectionTitle": ParagraphStyle("NetraSectionTitle", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=colors.HexColor("#b64322"), spaceBefore=8),
        "Body": ParagraphStyle("NetraBody", parent=base["BodyText"], fontSize=9.5, leading=14, textColor=colors.HexColor("#1f2937")),
        "Cell": ParagraphStyle("NetraCell", parent=base["BodyText"], fontSize=8.2, leading=10.5, textColor=colors.HexColor("#111827")),
        "HeaderCell": ParagraphStyle("NetraHeaderCell", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.2, leading=10.5, textColor=colors.white),
        "Small": ParagraphStyle("NetraSmall", parent=base["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#6b7280")),
        "Right": ParagraphStyle("NetraRight", parent=base["BodyText"], alignment=TA_RIGHT, fontSize=8.5, leading=11, textColor=colors.HexColor("#6b7280")),
    }

    evidence = analysis.get("evidence") or {}
    summary = analysis.get("summary") or {}
    alerts = analysis.get("alerts") or []
    anomalies = analysis.get("anomalies") or []
    zeek = analysis.get("zeek") or {}
    normalization = analysis.get("normalization") or evidence.get("normalization") or {}
    tool_status = analysis.get("toolStatus") or {}
    payloads = analysis.get("payloadFindings") or []
    sessions = analysis.get("sessions") or []
    decoded = analysis.get("decodedProtocols") or []
    legal_items = legal.get("items") or []
    custody_events = (analysis.get("custodyLedger") or {}).get("events") or []

    story: list[Any] = []
    story.append(Paragraph("Netra Forensic Network Investigation Report", styles["Title"]))
    story.append(Paragraph(f"Case {_text(analysis.get('caseId'))} | Language {_text(language)} | Risk {_text(analysis.get('riskLevel', 'low')).upper()}", styles["Subtitle"]))
    story.append(Spacer(1, 10))

    story.append(
        _table(
            [
                ["Top Finding", "Risk", "Packets", "Sessions", "Alerts", "Anomalies"],
                [
                    _text(analysis.get("topAttackClass"), "Normal Baseline"),
                    _text(analysis.get("riskLevel"), "low").upper(),
                    _text(summary.get("packets", 0)),
                    _text(summary.get("sessions", 0)),
                    _text(summary.get("alerts", len(alerts))),
                    _text(summary.get("anomalies", len(anomalies))),
                ],
            ],
            [46 * mm, 22 * mm, 22 * mm, 24 * mm, 22 * mm, 24 * mm],
            styles,
        )
    )
    story.append(Spacer(1, 10))

    story.append(
        _section(
            "Executive Summary",
            [
                _para(
                    f"Netra analyzed packet evidence for case {_text(analysis.get('caseId'))}. "
                    f"The highest-level classification is {_text(analysis.get('topAttackClass'), 'Normal Baseline')} with {_text(analysis.get('riskLevel'), 'low')} risk. "
                    "This report is generated from persisted evidence, detection results, anomaly records, protocol summaries, and custody ledger entries.",
                    styles["Body"],
                )
            ],
            styles,
        )
    )

    story.append(
        _section(
            "Evidence Metadata And Integrity",
            [
                _table(
                    [
                        ["Field", "Value"],
                        ["Evidence file", _text(evidence.get("filename"))],
                        ["Evidence ID", _text(evidence.get("id"))],
                        ["Plain SHA-256", _text(evidence.get("plaintextSha256") or evidence.get("sha256"))],
                        ["Encrypted SHA-256", _text(evidence.get("encryptedSha256"))],
                        ["Manifest hash", _text(evidence.get("manifestHash"))],
                        ["Encryption key ID", _text(evidence.get("keyId"))],
                        ["Storage URI", _text(evidence.get("storageUri") or evidence.get("storedPath"))],
                    ],
                    [42 * mm, 126 * mm],
                    styles,
                )
            ],
            styles,
        )
    )

    story.append(
        _section(
            "Evidence Normalization",
            [
                _table(
                    [
                        ["Field", "Value"],
                        ["Selected type", _text(normalization.get("selectedType"))],
                        ["Detected type", _text(normalization.get("detectedType"))],
                        ["Normalized type", _text(normalization.get("normalizedType"))],
                        ["Confidence", f"{_text(normalization.get('confidence'), '0')}%"],
                        ["Parser used", _text(normalization.get("parser"))],
                        ["Validation", "passed" if normalization.get("valid") else "failed"],
                        ["Signals", ", ".join(normalization.get("signals") or (normalization.get("features") or {}).get("sampleSignals", [])) or "-"],
                    ],
                    [42 * mm, 126 * mm],
                    styles,
                )
            ],
            styles,
        )
    )

    alert_rows = [["Severity", "Attack class", "Source", "Destination", "Confidence"]]
    for alert in alerts[:12]:
        alert_rows.append([alert.get("severity"), alert.get("attackClass"), alert.get("sourceIp"), alert.get("destination"), f"{alert.get('confidence', 0)}%"])
    if len(alert_rows) == 1:
        alert_rows.append(["none", "No suspicious alert generated", "-", "-", "-"])
    story.append(_section("Suspicious Activity And Threat Detection", [_table(alert_rows, [22 * mm, 42 * mm, 32 * mm, 44 * mm, 28 * mm], styles)], styles))

    anomaly_items = [
        ListItem(_para(f"{item.get('entity')}: {item.get('observed')} vs {item.get('baseline')} ({item.get('confidence', 0)}% confidence)", styles["Body"]))
        for item in anomalies[:8]
    ] or [ListItem(_para("No high-confidence anomaly was recorded for this case.", styles["Body"]))]
    story.append(
        _section(
            "Experimental ML-Assisted Anomaly Summary",
            [
                _para("This experimental model supports investigator triage only. Its output is not a standalone forensic or legal conclusion.", styles["Small"]),
                Spacer(1, 4),
                ListFlowable(anomaly_items, bulletType="bullet", leftIndent=12),
            ],
            styles,
        )
    )

    protocol_rows = [["Protocol", "Sessions", "Packets", "Risk", "Decoded summary"]]
    for item in decoded[:10]:
        protocol_rows.append([item.get("protocol"), item.get("sessions") or item.get("sessionCount") or "-", item.get("packets") or item.get("packetCount") or "-", item.get("risk") or item.get("severity") or "-", item.get("decodedSummary") or item.get("summary") or "-"])
    if len(protocol_rows) == 1:
        protocol_rows.append(["-", "-", "-", "-", "No decoded protocol evidence available."])
    story.append(_section("Protocol Decoding And DPI Metadata", [_table(protocol_rows, [22 * mm, 22 * mm, 22 * mm, 20 * mm, 82 * mm], styles)], styles))

    payload_rows = [["Type", "Protocol", "Risk", "Finding"]]
    for item in payloads[:8]:
        payload_rows.append([item.get("payloadType"), item.get("protocol"), item.get("risk"), item.get("description") or item.get("matchedPattern") or "-"])
    if len(payload_rows) == 1:
        payload_rows.append(["Metadata review", "-", "low", "No high-risk payload clue was recorded."])
    story.append(_section("Payload Inspection Clues", [_table(payload_rows, [42 * mm, 22 * mm, 20 * mm, 84 * mm], styles)], styles))

    session_rows = [["Source", "Destination", "Protocol", "Packets", "Risk"]]
    for item in sessions[:10]:
        session_rows.append([item.get("source"), item.get("destination"), item.get("protocol"), item.get("packetCount"), item.get("riskScore")])
    if len(session_rows) == 1:
        session_rows.append(["-", "-", "-", "-", "-"])
    story.append(_section("Traffic Flow Summary", [_table(session_rows, [42 * mm, 48 * mm, 24 * mm, 24 * mm, 30 * mm], styles)], styles))

    zeek_summary = zeek.get("summary") or {}
    story.append(
        _section(
            "Tooling And Zeek Analysis",
            [
                _table(
                    [
                        ["Tool / Source", "Status"],
                        ["tshark", _text(tool_status.get("tshark"), "available")],
                        ["Zeek", _text(zeek.get("status"), "unknown")],
                        ["Zeek summary", ", ".join(f"{key}: {value}" for key, value in zeek_summary.items()) or "-"],
                        ["Zeek logs", ", ".join(zeek.get("logs") or []) or "-"],
                    ],
                    [42 * mm, 126 * mm],
                    styles,
                )
            ],
            styles,
        )
    )

    custody_rows = [["Time", "Actor", "Action", "Hash status"]]
    for event in custody_events[:14]:
        custody_rows.append([event.get("createdAt") or event.get("timestamp"), event.get("actorLabel") or event.get("actor"), event.get("action"), event.get("eventHash") or event.get("hash")])
    if len(custody_rows) == 1:
        custody_rows.append(["-", "-", "No custody ledger events available", "-"])
    story.append(
        _section(
            "Chain Of Custody",
            [
                _para(f"Ledger verified: {custody.get('verified', False)} | Events: {custody.get('eventCount', 0)} | Latest hash: {_text(custody.get('latestHash'))}", styles["Body"]),
                _table(custody_rows, [30 * mm, 34 * mm, 54 * mm, 50 * mm], styles),
            ],
            styles,
        )
    )

    legal_rows = [["Control", "Status", "Detail"]]
    for item in legal_items:
        legal_rows.append([item.get("name"), item.get("status"), item.get("detail")])
    if len(legal_rows) == 1:
        legal_rows.append(["Legal review", "pending", "Checklist data was not available when this report was generated."])
    story.append(_section("Legal Review Checklist", [_table(legal_rows, [42 * mm, 28 * mm, 98 * mm], styles)], styles))

    recommendations = [
        "Correlate suspicious network activity with endpoint, authentication, firewall, and server logs.",
        "Preserve original PCAP, manifest, generated report, and exports by hash.",
        "Do not treat PCAP-only evidence as proof of user attribution without corroborating host evidence.",
    ]
    story.append(_section("Recommended Next Steps", [ListFlowable([ListItem(_para(item, styles["Body"])) for item in recommendations], bulletType="1", leftIndent=16)], styles))
    story.append(Paragraph("Limitations: Netra does not decrypt TLS payloads. DPI findings are metadata-derived unless plaintext protocol data is visible in the PCAP.", styles["Small"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
