from __future__ import annotations

from xml.etree import ElementTree as ET

from .core import Run


def render_junit_xml(run: Run, quality_gate: dict) -> str:
    """Render quality-gate checks as a portable JUnit test suite."""
    checks = quality_gate.get("checks") or []
    tests = len(checks) or 1
    failures = sum(not check["passed"] for check in checks)
    suite = ET.Element("testsuite", {
        "name": "Backtrace quality gate",
        "tests": str(tests),
        "failures": str(failures),
        "errors": "0",
        "skipped": "0" if checks else "1",
        "time": f"{run.duration_ms / 1000:.3f}",
    })
    properties = ET.SubElement(suite, "properties")
    ET.SubElement(properties, "property", {"name": "run", "value": run.name})
    ET.SubElement(properties, "property", {"name": "session_id", "value": run.session_id or "unknown"})
    if quality_gate.get("policy_source"):
        ET.SubElement(properties, "property", {"name": "policy", "value": quality_gate["policy_source"]})
    if not checks:
        case = ET.SubElement(suite, "testcase", {"classname": "backtrace.quality", "name": "No quality gates configured"})
        ET.SubElement(case, "skipped", {"message": "No quality policy or gate flags were supplied."})
    for check in checks:
        case = ET.SubElement(suite, "testcase", {"classname": "backtrace.quality", "name": check["label"]})
        if not check["passed"]:
            failure = ET.SubElement(case, "failure", {
                "message": f"Actual {check['actual']}; expected {check['expected']}",
                "type": check["key"],
            })
            failure.text = check["detail"]
    output = ET.SubElement(suite, "system-out")
    output.text = f"Run: {run.name}\nSource: {run.source}\nResult: {'PASS' if quality_gate.get('passed') else 'FAIL'}"
    ET.indent(suite)
    return ET.tostring(suite, encoding="unicode", xml_declaration=True)
