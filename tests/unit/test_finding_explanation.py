"""Unit tests for the per-finding AI explanation model and fallback
template system (SRS Ch9 §4 and §6).

These tests verify the data shape and the deterministic-render
invariant, but do NOT exercise the live Gemini call. The integration
test in tests/integration/test_ai_analysis_flow.py covers the live path.
"""

from __future__ import annotations

import pytest

from src.domain.scanning.analysis.fallback_templates import (
    GENERIC_FALLBACK,
    build_fallback_explanation,
    get_template,
    known_categories,
)
from src.domain.scanning.analysis.finding_explanation import (
    Claim,
    EvidenceReference,
    ExplanationStatus,
    FindingExplanation,
    Remediation,
    render_explanation_text,
)


def test_render_explanation_text_joins_claims_with_space() -> None:
    """The prose is a view over the claims array, never the other way."""
    claims = (
        Claim(text="Header X is absent."),
        Claim(text="This weakens clickjacking defenses."),
    )
    rendered = render_explanation_text(claims)
    assert rendered == "Header X is absent. This weakens clickjacking defenses."


def test_render_explanation_text_empty_claims_has_honest_message() -> None:
    """Zero claims → an honest, no-evidence message rather than empty string."""
    rendered = render_explanation_text(())
    assert "No evidence-validated claims" in rendered


def test_finding_explanation_to_dict_is_stable() -> None:
    """A canonical FindingExplanation must serialize to a stable shape."""
    explanation = FindingExplanation(
        finding_id="abc123",
        claims=(Claim(text="HSTS is absent.", references=(EvidenceReference("ev-1"),)),),
        explanation_text="HSTS is absent.",
        severity_rationale="Standard missing-header severity.",
        remediation=Remediation(
            summary="Add HSTS.",
            steps=("Step one.", "Step two."),
        ),
        validation_status=ExplanationStatus.VALIDATED,
        prompt_template_version="v1",
        model_name="gemini-test",
        model_version="1",
        provider="test",
    )
    serialized = explanation.to_dict()
    assert serialized["finding_id"] == "abc123"
    assert serialized["validation_status"] == "validated"
    assert serialized["model"]["provider"] == "test"
    assert serialized["model"]["nondeterministic"] is True
    assert serialized["claims"][0]["references"][0]["evidence_id"] == "ev-1"


def test_finding_explanation_serialize_is_deterministic() -> None:
    """Re-serializing equal objects must produce identical bytes."""
    a = FindingExplanation(
        finding_id="f1",
        claims=(Claim(text="C"),),
        explanation_text="C",
        severity_rationale="r",
        remediation=Remediation(summary="s"),
        validation_status=ExplanationStatus.VALIDATED,
        prompt_template_version="v1",
        model_name="m",
        model_version="1",
        provider="p",
    )
    b = FindingExplanation(
        finding_id="f1",
        claims=(Claim(text="C"),),
        explanation_text="C",
        severity_rationale="r",
        remediation=Remediation(summary="s"),
        validation_status=ExplanationStatus.VALIDATED,
        prompt_template_version="v1",
        model_name="m",
        model_version="1",
        provider="p",
    )
    assert a.serialize() == b.serialize()


def test_fallback_template_registered_for_known_categories() -> None:
    """The five categories the engine currently emits each have a template."""
    for code in (
        "MISSING_SECURITY_HEADER",
        "WEAK_CIPHER",
        "OUTDATED_TLS",
        "KNOWN_CVE",
        "EXPOSED_ADMIN_PANEL",
    ):
        template = get_template(code)
        assert template.claims, f"empty claims for {code}"
        assert template.remediation.summary, f"empty remediation for {code}"


def test_fallback_template_falls_back_to_generic_for_unknown_category() -> None:
    """An unmapped category receives the generic template (no crash)."""
    template = get_template("DEFINITELY_NOT_REAL_CATEGORY")
    assert template is GENERIC_FALLBACK


def test_build_fallback_explanation_uses_fallback_status() -> None:
    """The result must be visibly labeled FALLBACK_USED, not VALIDATED."""
    explanation = build_fallback_explanation(
        finding_id="fid",
        category_code="MISSING_SECURITY_HEADER",
    )
    assert explanation.validation_status == ExplanationStatus.FALLBACK_USED
    assert explanation.provider == "template"
    assert explanation.is_nondeterministic is False
    assert explanation.finding_id == "fid"


def test_build_fallback_explanation_does_not_invent_evidence_ids() -> None:
    """Fallback claims never reference evidence rows (no fabrication)."""
    explanation = build_fallback_explanation(
        finding_id="fid",
        category_code="MISSING_SECURITY_HEADER",
    )
    for claim in explanation.claims:
        assert claim.references == ()


def test_known_categories_returns_immutable_view() -> None:
    """Diagnostic helper exposes the registered templates without mutation risk."""
    categories = known_categories()
    assert "MISSING_SECURITY_HEADER" in categories
    with pytest.raises(TypeError):
        categories["NEW"] = None  # type: ignore[index]
