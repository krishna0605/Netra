from __future__ import annotations

import csv
import json
import mimetypes
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import BinaryIO

from common.vault import PCAP_MAGIC


AUTO_TYPES = {"", "Auto", "Auto-detect", "Auto Detect", "auto", "auto-detect"}
SUPPORTED_TYPES = {"PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"}
ALLOWED_EXTENSIONS_BY_TYPE = {
    "PCAP": {".pcap", ".pcapng"},
    "Firewall Logs": {".log", ".txt", ".csv", ".json", ".ndjson"},
    "DNS Logs": {".log", ".txt", ".csv", ".json", ".ndjson"},
    "TLS Metadata": {".log", ".txt", ".csv", ".json", ".ndjson"},
    "Mixed Evidence": {".zip", ".json", ".csv"},
}
ALL_ALLOWED_EXTENSIONS = sorted({extension for extensions in ALLOWED_EXTENSIONS_BY_TYPE.values() for extension in extensions})
TEXT_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".ndjson"}


@dataclass(frozen=True)
class EvidenceNormalizationResult:
    selected_type: str
    detected_type: str
    normalized_type: str
    valid: bool
    confidence: int
    reason: str
    parser: str
    features: dict
    code: str = ""
    extension_allowed: bool = True
    allowed_extensions: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "selectedType": self.selected_type,
            "detectedType": self.detected_type,
            "normalizedType": self.normalized_type,
            "valid": self.valid,
            "extensionAllowed": self.extension_allowed,
            "allowedExtensions": list(self.allowed_extensions),
            "confidence": self.confidence,
            "reason": self.reason,
            "parser": self.parser,
            "features": self.features,
            "signals": self.features.get("sampleSignals", []),
            "recommendedType": self.normalized_type,
            "validForSelectedType": self.valid,
            "message": self.reason,
        }


def normalize_evidence_upload(upload: BinaryIO, selected_evidence_type: str | None = None) -> EvidenceNormalizationResult:
    selected = _clean_selected_type(selected_evidence_type)
    safe_name = Path(getattr(upload, "name", "evidence")).name
    extension = Path(safe_name).suffix.lower()
    sample = _read_sample(upload)
    head = sample[:4]
    mime_guess = mimetypes.guess_type(safe_name)[0] or ""
    signals: list[str] = []
    magic_type = ""
    selected_allowed_extensions = _allowed_extensions(selected)
    globally_allowed = extension in ALL_ALLOWED_EXTENSIONS
    extension_allowed = extension in selected_allowed_extensions or (head in PCAP_MAGIC and globally_allowed)

    if not globally_allowed:
        return _unsupported_extension_result(selected, extension, mime_guess)
    if not extension_allowed:
        return _unsupported_extension_result(selected, extension, mime_guess)

    if head in PCAP_MAGIC:
        magic_type = "pcapng" if head == b"\x0a\x0d\x0d\x0a" else "pcap"
        signals.append(f"magic:{magic_type}")
        if extension:
            signals.append(f"extension:{extension}")
        return _result(selected, "PCAP", True, 99, f"File extension {extension or '(none)'} and {magic_type.upper()} magic bytes indicate PCAP evidence.", "pcap", extension, mime_guess, magic_type, signals, extension_allowed=extension_allowed, allowed_extensions=selected_allowed_extensions)

    if extension in {".pcap", ".pcapng"}:
        signals.append(f"extension:{extension}")
        return _result(selected, "Unknown", False, 35, "The filename suggests PCAP evidence, but the magic bytes are not valid PCAP/PCAPNG.", "unknown", extension, mime_guess, "invalid-pcap", signals, code="invalid_pcap", extension_allowed=extension_allowed, allowed_extensions=selected_allowed_extensions)

    text = _decode_text_sample(sample)
    log_scores = _score_text_evidence(text, extension)
    for evidence_type, score in log_scores.items():
        if score:
            signals.append(f"{_signal_name(evidence_type)}:{score}")
    detected = _detected_from_scores(log_scores, extension)
    if detected == "Unknown":
        return _result(selected, "Unknown", False, 15, "Netra could not identify this evidence file from extension, magic bytes, or sample content.", "unknown", extension, mime_guess, "", signals, code="evidence_type_unrecognized", extension_allowed=extension_allowed, allowed_extensions=selected_allowed_extensions)

    confidence = min(95, 55 + (log_scores.get(detected, 0) * 8))
    parser = {
        "Firewall Logs": "firewall-log",
        "DNS Logs": "dns-log",
        "TLS Metadata": "tls-metadata",
        "Mixed Evidence": "mixed-evidence",
    }.get(detected, "unknown")
    return _result(selected, detected, True, confidence, f"Sample content contains signals consistent with {detected}.", parser, extension, mime_guess, "", signals, extension_allowed=extension_allowed, allowed_extensions=selected_allowed_extensions)


def _result(selected: str, detected: str, structurally_valid: bool, confidence: int, reason: str, parser: str, extension: str, mime_guess: str, magic_type: str, signals: list[str], code: str = "", extension_allowed: bool = True, allowed_extensions: tuple[str, ...] | None = None) -> EvidenceNormalizationResult:
    normalized = detected if detected != "Unknown" else selected if selected not in AUTO_TYPES else "Unknown"
    selected_is_auto = selected in AUTO_TYPES
    selected_matches = selected_is_auto or selected == normalized
    valid = structurally_valid and detected != "Unknown" and selected_matches
    if code:
        valid = False
    if structurally_valid and detected != "Unknown" and not selected_matches:
        code = "evidence_type_mismatch"
        reason = f"Selected evidence type {selected} does not match detected {detected}. {reason}"
    return EvidenceNormalizationResult(
        selected_type="Auto-detect" if selected_is_auto else selected,
        detected_type=detected,
        normalized_type=normalized,
        valid=valid,
        confidence=confidence,
        reason=reason,
        parser=parser,
        code=code,
        extension_allowed=extension_allowed,
        allowed_extensions=tuple(allowed_extensions or _allowed_extensions(selected)),
        features={
            "extension": extension,
            "mimeGuess": mime_guess,
            "magicType": magic_type,
            "lineFormat": _line_format(extension),
            "sampleSignals": signals,
        },
    )


def _clean_selected_type(selected: str | None) -> str:
    value = (selected or "Auto-detect").strip()
    return value if value in SUPPORTED_TYPES or value in AUTO_TYPES else "Auto-detect"


def _allowed_extensions(selected: str) -> tuple[str, ...]:
    if selected in AUTO_TYPES:
        return tuple(ALL_ALLOWED_EXTENSIONS)
    return tuple(sorted(ALLOWED_EXTENSIONS_BY_TYPE.get(selected, ALL_ALLOWED_EXTENSIONS)))


def _unsupported_extension_result(selected: str, extension: str, mime_guess: str) -> EvidenceNormalizationResult:
    selected_label = "Auto-detect" if selected in AUTO_TYPES else selected
    allowed = _allowed_extensions(selected)
    extension_label = extension or "(none)"
    return EvidenceNormalizationResult(
        selected_type=selected_label,
        detected_type="Unknown",
        normalized_type="Unknown",
        valid=False,
        confidence=0,
        reason=f"Unsupported evidence file type {extension_label}. Allowed for {selected_label}: {', '.join(allowed)}.",
        parser="none",
        code="unsupported_evidence_extension",
        extension_allowed=False,
        allowed_extensions=allowed,
        features={
            "extension": extension,
            "mimeGuess": mime_guess,
            "magicType": "",
            "lineFormat": None,
            "sampleSignals": [f"unsupported-extension:{extension_label}"],
        },
    )


def _read_sample(upload: BinaryIO, size: int = 16384) -> bytes:
    position = upload.tell() if hasattr(upload, "tell") else None
    sample = upload.read(size)
    if position is not None:
        upload.seek(position)
    return sample or b""


def _decode_text_sample(sample: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return sample.decode(encoding, errors="ignore").lower()
        except Exception:
            continue
    return ""


def _score_text_evidence(text: str, extension: str) -> dict[str, int]:
    scores = {"Firewall Logs": 0, "DNS Logs": 0, "TLS Metadata": 0}
    if not text:
        return scores
    if extension in TEXT_EXTENSIONS:
        for key in scores:
            scores[key] += 1
    fields = _extract_field_names(text, extension)
    joined_fields = " ".join(fields)
    searchable = f"{text[:4000]} {joined_fields}"

    firewall_tokens = ["src_ip", "source_ip", "dst_ip", "destination_ip", "action", "deny", "denied", "allow", "allowed", "rule", "firewall", "policy"]
    dns_tokens = ["qname", "query", "dns", "rrtype", "rcode", "query_name", "domain", "answer", "record_type"]
    tls_tokens = ["sni", "ja3", "ja3s", "tls_version", "cipher", "cert_subject", "cert_issuer", "server_name", "handshake"]
    scores["Firewall Logs"] += sum(1 for token in firewall_tokens if token in searchable)
    scores["DNS Logs"] += sum(1 for token in dns_tokens if token in searchable)
    scores["TLS Metadata"] += sum(1 for token in tls_tokens if token in searchable)
    return scores


def _extract_field_names(text: str, extension: str) -> list[str]:
    try:
        if extension == ".json":
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return list(parsed.keys())
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                return list(parsed[0].keys())
        if extension == ".csv":
            reader = csv.reader(StringIO(text))
            return [item.strip().lower() for item in next(reader, [])]
    except Exception:
        return []
    return []


def _detected_from_scores(scores: dict[str, int], extension: str) -> str:
    active = [key for key, value in scores.items() if value >= 3]
    if extension == ".zip" or len(active) >= 2:
        return "Mixed Evidence"
    if not active:
        return "Unknown"
    return max(active, key=lambda key: scores[key])


def _signal_name(evidence_type: str) -> str:
    return evidence_type.lower().replace(" ", "-")


def _line_format(extension: str) -> str | None:
    return {
        ".csv": "csv",
        ".json": "json",
        ".log": "text-log",
        ".txt": "text",
        ".zip": "archive",
    }.get(extension)
