"""Ghostwire DFIR Triage & Evidence Chain of Custody (Module D).

Provides:
- Read-only file & host artifact acquisition (never alters original evidence)
- Magic-byte file type identification & SHA-256 integrity hashing
- Formal chain-of-custody ledger per evidence item
- Case management (analyst notes, decisions, chronological timelines)
- Tamper-evident JSON case bundle export & verification + Markdown reports
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from schema.event_schema import SecurityEvent


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def identify_magic_type(header: bytes) -> str:
    """Identify basic file type from magic bytes without executing anything."""
    if header.startswith(b"\x7fELF"):
        return "elf_executable"
    if header[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "macho_binary"
    if header.startswith(b"MZ"):
        return "pe_executable"
    if header.startswith(b"PK\x03\x04"):
        return "zip_archive"
    if header.startswith(b"%PDF-"):
        return "pdf_document"
    if header.startswith(b"#!"):
        return "script_shebang"
    return "data_or_text"


@dataclass
class CustodyEntry:
    timestamp: str
    actor: str
    action: str  # "acquired", "verified", "exported"
    notes: str = ""


@dataclass
class EvidenceItem:
    evidence_id: str
    source_path: str
    sha256: str
    size_bytes: int
    file_mode: str
    mtime_iso: str
    magic_type: str
    acquired_at: str
    collector: str
    custody_chain: List[CustodyEntry] = field(default_factory=list)


@dataclass
class AnalystNote:
    note_id: str
    timestamp: str
    author: str
    content: str
    decision: Optional[str] = None  # e.g., "true_positive", "benign", "escalate"


@dataclass
class IncidentCase:
    case_id: str
    title: str
    asset_id: str
    created_at: str
    status: str = "open"  # "open", "contained", "closed"
    evidence: List[EvidenceItem] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[AnalystNote] = field(default_factory=list)


def acquire_file_evidence(
    file_path: str,
    collector: str = "ghostwire_dfir",
    notes: str = "Read-only forensic acquisition",
) -> EvidenceItem:
    """Acquire metadata & SHA-256 digest of a file strictly read-only."""
    real_path = os.path.abspath(file_path)
    if not os.path.isfile(real_path):
        raise FileNotFoundError(f"Evidence target does not exist or is not a file: {real_path}")

    st = os.stat(real_path)
    h = hashlib.sha256()
    header = b""
    with open(real_path, "rb") as f:
        chunk = f.read(65536)
        header = chunk[:16]
        while chunk:
            h.update(chunk)
            chunk = f.read(65536)

    now = _utc_now()
    mtime_iso = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    ev_id = f"evd-{uuid.uuid4().hex[:12]}"
    return EvidenceItem(
        evidence_id=ev_id,
        source_path=real_path,
        sha256=h.hexdigest(),
        size_bytes=st.st_size,
        file_mode=oct(stat.S_IMODE(st.st_mode)),
        mtime_iso=mtime_iso,
        magic_type=identify_magic_type(header),
        acquired_at=now,
        collector=collector,
        custody_chain=[
            CustodyEntry(timestamp=now, actor=collector, action="acquired", notes=notes)
        ],
    )


def verify_evidence_integrity(item: EvidenceItem) -> bool:
    """Re-hash the original file read-only and append a custody verification record."""
    if not os.path.isfile(item.source_path):
        return False
    h = hashlib.sha256()
    with open(item.source_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    matched = h.hexdigest() == item.sha256
    item.custody_chain.append(
        CustodyEntry(
            timestamp=_utc_now(),
            actor="ghostwire_dfir",
            action="verified",
            notes=f"Integrity check {'PASSED' if matched else 'FAILED'}",
        )
    )
    return matched


def add_event_to_case(case: IncidentCase, event: SecurityEvent) -> None:
    case.events.append(event.to_dict())
    case.events.sort(key=lambda e: str(e.get("timestamp", "")))


def add_analyst_note(
    case: IncidentCase,
    author: str,
    content: str,
    decision: Optional[str] = None,
) -> AnalystNote:
    note = AnalystNote(
        note_id=f"note-{uuid.uuid4().hex[:8]}",
        timestamp=_utc_now(),
        author=author,
        content=content,
        decision=decision,
    )
    case.notes.append(note)
    return note


def export_case_bundle(case: IncidentCase, out_path: str) -> str:
    """Export a tamper-evident JSON case bundle with a manifest SHA-256 digest."""
    body = asdict(case)
    canonical = json.dumps(body, sort_keys=True).encode("utf-8")
    manifest_sha256 = hashlib.sha256(canonical).hexdigest()
    bundle = {
        "bundle_version": "1.0.0",
        "exported_at": _utc_now(),
        "manifest_sha256": manifest_sha256,
        "case": body,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    return manifest_sha256


def verify_case_bundle(bundle_path: str) -> bool:
    """Verify that an exported DFIR case bundle has not been tampered with."""
    with open(bundle_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    expected = bundle.get("manifest_sha256")
    case_body = bundle.get("case")
    if not expected or not isinstance(case_body, dict):
        return False
    actual = hashlib.sha256(json.dumps(case_body, sort_keys=True).encode("utf-8")).hexdigest()
    return actual == expected


def render_incident_report_markdown(case: IncidentCase) -> str:
    """Generate a reproducible Markdown DFIR incident report separating facts from notes."""
    lines = [
        f"# Incident Report: {case.title} ({case.case_id})",
        "",
        f"- **Asset ID:** `{case.asset_id}`",
        f"- **Status:** `{case.status}`",
        f"- **Created:** `{case.created_at}`",
        "",
        "## 1. Acquired Evidence (Facts & Provenance)",
        "",
    ]
    if not case.evidence:
        lines.append("_No file evidence acquired._")
    else:
        for ev in case.evidence:
            lines.append(
                f"- `{ev.evidence_id}` | `{ev.source_path}` | `{ev.magic_type}` | `{ev.size_bytes} B` | SHA-256: `{ev.sha256}`"
            )
    lines.extend(["", "## 2. Chronological Event Timeline", ""])
    for ev in case.events:
        lines.append(
            f"- `{ev.get('timestamp')}` | `{ev.get('event_category')}.{ev.get('event_action')}` | severity=`{ev.get('severity')}` | synthetic=`{ev.get('provenance', {}).get('is_synthetic')}`"
        )
    lines.extend(["", "## 3. Analyst Notes & Decisions", ""])
    for n in case.notes:
        dec = f" [Decision: `{n.decision}`]" if n.decision else ""
        lines.append(f"- `{n.timestamp}` (**{n.author}**){dec}: {n.content}")
    return "\n".join(lines) + "\n"
