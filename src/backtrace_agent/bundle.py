from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile, ZipInfo

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


def verify_evidence_bundle(path: str | Path) -> dict:
    """Verify bundle structure, declared sizes, and SHA-256 hashes without extraction."""
    path = Path(path)
    errors: list[str] = []
    verified = 0
    expected_names = {"report.html", "normalized.json", "summary.md", "manifest.json"}
    try:
        with ZipFile(path) as archive:
            name_list = archive.namelist()
            names = set(name_list)
            if names != expected_names or len(name_list) != len(expected_names):
                errors.append(f"Expected exactly one of each {sorted(expected_names)}; found {sorted(name_list)}.")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("format") != "backtrace-evidence-bundle-v1":
                errors.append("Unsupported or missing bundle format.")
            if manifest.get("raw_trace_included") is not False:
                errors.append("Manifest does not explicitly exclude the raw trace.")
            declared = manifest.get("files")
            if not isinstance(declared, dict) or set(declared) != expected_names - {"manifest.json"}:
                errors.append("Manifest payload list is incomplete or unexpected.")
                declared = declared if isinstance(declared, dict) else {}
            for name in sorted(expected_names - {"manifest.json"}):
                if name not in names or name not in declared:
                    continue
                content = archive.read(name)
                evidence = declared[name]
                actual_hash = hashlib.sha256(content).hexdigest()
                if evidence.get("sha256") != actual_hash:
                    errors.append(f"SHA-256 mismatch for {name}.")
                elif evidence.get("bytes") != len(content):
                    errors.append(f"Byte-size mismatch for {name}.")
                else:
                    verified += 1
    except (OSError, BadZipFile, KeyError, json.JSONDecodeError, TypeError, AttributeError) as exc:
        errors.append(f"Could not verify bundle: {exc}")
    return {"valid": not errors, "files_verified": verified, "errors": errors}
