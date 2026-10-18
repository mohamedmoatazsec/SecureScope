import pytest

from securescope.findings import Confidence, Finding, Severity, meets_threshold, sort_findings
from securescope.scoring import grade, score, summarize


def make(id="X", severity=Severity.LOW, target="https://a.test/", **evidence):
    return Finding(
        id=id,
        title=id,
        severity=severity,
        description="d",
        remediation="r",
        check="t",
        evidence=evidence,
        target=target,
    )


def test_severity_parse_and_rank():
    assert Severity.parse(" High ") is Severity.HIGH
    assert (
        Severity.CRITICAL.rank
        < Severity.HIGH.rank
        < Severity.MEDIUM.rank
        < Severity.LOW.rank
        < Severity.INFO.rank
    )
    with pytest.raises(ValueError):
        Severity.parse("urgent")


def test_threshold():
    assert meets_threshold(make(severity=Severity.HIGH), Severity.HIGH)
    assert meets_threshold(make(severity=Severity.CRITICAL), Severity.HIGH)
    assert not meets_threshold(make(severity=Severity.MEDIUM), Severity.HIGH)


def test_sorting_is_by_severity_then_check_and_id():
    findings = [
        make("b", Severity.LOW),
        make("a", Severity.HIGH),
        make("c", Severity.CRITICAL),
        make("a", Severity.LOW),
    ]
    assert [f.id for f in sort_findings(findings)] == ["c", "a", "a", "b"]


def test_fingerprint_depends_on_id_target_and_location_keys():
    assert make("A").fingerprint() == make("A").fingerprint()
    assert make("A").fingerprint() != make("B").fingerprint()
    assert make("A").fingerprint() != make("A", target="https://b.test/").fingerprint()
    assert make("A", name="x").fingerprint() != make("A", name="y").fingerprint()
    assert make("A", directive="script-src").fingerprint() != make("A", directive="base-uri").fingerprint()
    # evidence that is not identity (a header value) does not change the fingerprint
    assert make("A", name="x", value="1").fingerprint() == make("A", name="x", value="2").fingerprint()


def test_round_trip_through_dict():
    original = make("ID", Severity.MEDIUM, name="n", value="v")
    original.confidence = Confidence.TENTATIVE
    original.cwe = 79
    original.references = ["https://example.test/ref"]
    restored = Finding.from_dict(original.to_dict())
    assert restored == original
    assert restored.fingerprint() == original.fingerprint()


def test_score_and_grade():
    assert score([]) == 100 and grade(100) == "A+"
    assert (
        grade(90) == "A" and grade(89) == "B" and grade(65) == "C" and grade(50) == "D" and grade(49) == "F"
    )
    assert score([make(severity=Severity.INFO)] * 50) == 100
    assert score([make(severity=Severity.HIGH), make(severity=Severity.MEDIUM)]) == 70
    assert score([make(severity=Severity.CRITICAL)] * 3) == 0


def test_summarize_counts():
    summary = summarize(
        [make(severity=Severity.HIGH), make(severity=Severity.LOW), make(severity=Severity.LOW)]
    )
    assert summary["counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}
    assert summary["total"] == 3
    assert summary["grade"] == "C"
