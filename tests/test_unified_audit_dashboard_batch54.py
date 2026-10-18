import json
import pytest

from reporting.unified_audit_dashboard import (
    DashboardError,
    build_unified_dashboard,
    create_unified_dashboard,
    render_unified_dashboard_markdown,
)


def sample():
    return (
        {"source_findings": 23, "duplicate_finding_ids": 0, "issue_count": 3,
         "subaudit_summaries": {"quality": {"issue_count": 0},
                                "evidence": {"issue_count": 3}}},
        {"source_findings": 23, "findings_requiring_review": 2,
         "recommendation_count": 3},
        {"items": [{"title": "Review"}], "severity_counts": {"LOW": 4}},
    )


def test_dashboard_summarizes_all_inputs():
    c, e, r = sample()
    d = build_unified_dashboard(c, e, r)
    assert d["status"] == "REVIEW_REQUIRED"
    assert d["summary"]["source_findings"] == 23
    assert d["summary"]["consistency_issues"] == 3
    assert d["summary"]["evidence_recommendations"] == 3
    assert d["summary"]["remediation_plan_items"] == 1


def test_zero_issue_inputs_do_not_claim_system_is_secure():
    d = build_unified_dashboard(
        {"issue_count": 0}, {"recommendation_count": 0, "findings_requiring_review": 0},
        {"items": []},
    )
    assert d["status"] == "NO_ISSUES_FLAGGED_BY_INPUT_REPORTS"
    assert "does not prove" in d["interpretation_note"]


def test_inputs_are_not_mutated():
    c, e, r = sample()
    before = json.dumps([c, e, r], sort_keys=True)
    build_unified_dashboard(c, e, r)
    assert json.dumps([c, e, r], sort_keys=True) == before


def test_markdown_contains_summary_and_safety_note():
    c, e, r = sample()
    md = render_unified_dashboard_markdown(build_unified_dashboard(c, e, r))
    assert "# LPE-Audit Unified Audit Dashboard" in md
    assert "Consistency issues: 3" in md
    assert "Automatic remediation: No" in md


def test_invalid_report_root_rejected():
    with pytest.raises(DashboardError):
        build_unified_dashboard([], {}, {})


def test_file_generation_and_input_preservation(tmp_path):
    c, e, r = sample()
    paths = []
    for name, obj in (("c.json", c), ("e.json", e), ("r.json", r)):
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        paths.append((p, p.read_bytes()))
    jp, mp = tmp_path / "dashboard.json", tmp_path / "dashboard.md"
    result = create_unified_dashboard(
        paths[0][0], paths[1][0], paths[2][0], jp, mp
    )
    assert json.loads(jp.read_text(encoding="utf-8")) == result
    assert mp.read_text(encoding="utf-8").endswith("\n")
    assert all(p.read_bytes() == before for p, before in paths)


def test_refuses_to_overwrite_input(tmp_path):
    c, e, r = sample()
    files = []
    for name, obj in (("c.json", c), ("e.json", e), ("r.json", r)):
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        files.append(p)
    with pytest.raises(DashboardError):
        create_unified_dashboard(files[0], files[1], files[2], files[0], tmp_path / "out.md")


def test_refuses_to_overwrite_existing_output(tmp_path):
    c, e, r = sample()
    files = []
    for name, obj in (("c.json", c), ("e.json", e), ("r.json", r)):
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        files.append(p)
    out = tmp_path / "dashboard.json"
    out.write_text("preserve", encoding="utf-8")
    with pytest.raises(DashboardError):
        create_unified_dashboard(files[0], files[1], files[2], out, tmp_path / "out.md")
    assert out.read_text(encoding="utf-8") == "preserve"


def test_missing_input_report_rejected(tmp_path):
    c, e, r = sample()
    epath, rpath = tmp_path / "e.json", tmp_path / "r.json"
    epath.write_text(json.dumps(e), encoding="utf-8")
    rpath.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(DashboardError):
        create_unified_dashboard(tmp_path / "missing.json", epath, rpath,
                                 tmp_path / "out.json", tmp_path / "out.md")


def test_output_paths_must_differ(tmp_path):
    c, e, r = sample()
    files = []
    for name, obj in (("c.json", c), ("e.json", e), ("r.json", r)):
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        files.append(p)
    out = tmp_path / "same.out"
    with pytest.raises(DashboardError):
        create_unified_dashboard(*files, out, out)



def test_batch48_real_schema_uses_checklist_and_nested_summary():
    c = {"source_findings": 23, "issue_count": 3}
    e = {"findings_requiring_review": 2, "recommendation_count": 3}
    r = {
        "summary": {
            "total_items": 23,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 21,
            "info": 2,
        },
        "checklist": [{"title": f"Finding {i}"} for i in range(23)],
    }
    dashboard = build_unified_dashboard(c, e, r)
    assert dashboard["summary"]["remediation_plan_items"] == 23
    assert dashboard["summary"]["remediation_severity_counts"] == {
        "critical": 0, "high": 0, "medium": 0, "low": 21, "info": 2
    }
