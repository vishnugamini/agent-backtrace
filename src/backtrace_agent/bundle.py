from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from .analysis import analyze_run, render_markdown_summary
from .core import Run
from .report import render_html


def _zip_info(name: str) -> ZipInfo:
    info = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


def write_evidence_bundle(
    run: Run,
    destination: str | Path,
    *,
    comparison: dict | None = None,
    quality_gate: dict | None = None,
) -> Path:
    """Write a deterministic, sanitized review bundle without the raw trace."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    analysis = analyze_run(run)
    export = {"run": run.as_dict(), "analysis": analysis, "comparison": comparison, "quality_gate": quality_gate}
    payloads = {
        "report.html": render_html(run, comparison, quality_gate).encode("utf-8"),
        "normalized.json": json.dumps(export, indent=2, ensure_ascii=False).encode("utf-8"),
        "summary.md": render_markdown_summary(run, comparison, quality_gate).encode("utf-8"),
    }
    manifest = {
        "format": "backtrace-evidence-bundle-v1",
        "run": {"name": run.name, "session_id": run.session_id, "source": run.source},
        "raw_trace_included": False,
        "privacy_protections": analysis["privacy"]["total_findings"],
        "files": {
            name: {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
            for name, content in payloads.items()
        },
    }
    payloads["manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    with ZipFile(destination, "w") as archive:
        for name, content in payloads.items():
            archive.writestr(_zip_info(name), content)
    return destination
