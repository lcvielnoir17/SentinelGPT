"""Deterministic fallback explanation templates (SRS Ch9 §6).

When the AI provider is unavailable, times out, or produces output that
fails validation, the explanation must degrade to a known-safe, human-
reviewed template — NEVER an error, NEVER an unvalidated AI snippet.

Every template is keyed by the canonical persisted finding-category code
(the value ``scan_finding.category_id`` resolves to, after the engine-
category → canonical mapping in ``scan_service._map_category``). The
template is a tuple of:

* ``claims``     — the deterministic, evidence-free assertions a human
                    reviewer has already signed off on. They reference
                    NO evidence rows; the validator counts them as
                    INFERRED.
* ``rationale``  — why the canonical severity is appropriate.
* ``remediation``— the standard remediation text.

Adding a new category is a code change in this module plus a
``FindingCategory`` row in the seed migration; both must be reviewed
together so the template and the persisted taxonomy can never drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

from src.domain.scanning.analysis.finding_explanation import (
    Claim,
    ExplanationStatus,
    FindingExplanation,
    Remediation,
)
from src.domain.scanning.findings import bound_evidence


@dataclass(frozen=True)
class FallbackTemplate:
    """The deterministic content the AI layer falls back to."""

    claims: tuple[Claim, ...]
    rationale: str
    remediation: Remediation


_GENERIC_RATIONALE = (
    "Severity reflects the deterministic impact category assigned by the "
    "scanner; this fallback explanation is template-based because the AI "
    "service was unavailable at explanation time."
)


_TEMPLATES: dict[str, FallbackTemplate] = {
    "MISSING_SECURITY_HEADER": FallbackTemplate(
        claims=(
            Claim(
                text=(
                    "The response did not include a security header the "
                    "browser relies on to enforce an expected security "
                    "policy."
                )
            ),
        ),
        rationale=_GENERIC_RATIONALE,
        remediation=Remediation(
            summary="Add the recommended HTTP response header.",
            steps=(
                "Identify the missing header in the finding evidence.",
                "Configure your web server or application to send the header on every response.",
                "Verify the header is present using an external request and re-run the scan.",
            ),
        ),
    ),
    "WEAK_CIPHER": FallbackTemplate(
        claims=(
            Claim(
                text=(
                    "The TLS configuration accepted a cipher or protocol "
                    "version that is no longer considered secure."
                )
            ),
        ),
        rationale=_GENERIC_RATIONALE,
        remediation=Remediation(
            summary="Disable the weak cipher or protocol on the TLS endpoint.",
            steps=(
                "Identify the weak cipher suite or protocol version in the evidence.",
                "Reconfigure the TLS endpoint to disable the weak option.",
                "Re-test the endpoint with an external scanner to confirm only strong options remain.",
            ),
        ),
    ),
    "OUTDATED_TLS": FallbackTemplate(
        claims=(
            Claim(
                text=(
                    "The TLS endpoint accepted a protocol version (for "
                    "example TLS 1.0 or 1.1) that has been deprecated."
                )
            ),
        ),
        rationale=_GENERIC_RATIONALE,
        remediation=Remediation(
            summary="Restrict the TLS endpoint to TLS 1.2 and TLS 1.3 only.",
            steps=(
                "Update the TLS configuration to disable deprecated protocol versions.",
                "Confirm the change with a TLS-scanning tool and re-run the scan.",
            ),
        ),
    ),
    "KNOWN_CVE": FallbackTemplate(
        claims=(
            Claim(
                text=(
                    "The finding references a known CVE; consult the linked "
                    "advisory for authoritative impact and remediation "
                    "guidance."
                )
            ),
        ),
        rationale=_GENERIC_RATIONALE,
        remediation=Remediation(
            summary="Apply the vendor fix or mitigation from the CVE advisory.",
            steps=(
                "Open the CVE advisory referenced in the evidence.",
                "Apply the vendor-supplied patch or documented workaround.",
                "Re-run the scan to confirm the finding is gone.",
            ),
        ),
    ),
    "EXPOSED_ADMIN_PANEL": FallbackTemplate(
        claims=(
            Claim(
                text=(
                    "An administrative interface is reachable at a path "
                    "that should not be publicly exposed."
                )
            ),
        ),
        rationale=_GENERIC_RATIONALE,
        remediation=Remediation(
            summary="Restrict access to the administrative interface.",
            steps=(
                "Place the admin path behind a VPN, IP allow-list, or single-sign-on gateway.",
                "Audit the existing access log for unexpected connections.",
                "Re-run the scan to confirm the path is no longer reachable from the public internet.",
            ),
        ),
    ),
}


GENERIC_FALLBACK = FallbackTemplate(
    claims=(
        Claim(
            text=(
                "A scanner detected an issue whose AI explanation could not "
                "be produced at this time."
            )
        ),
    ),
    rationale=_GENERIC_RATIONALE,
    remediation=Remediation(
        summary="Review the finding evidence directly and apply a manual fix.",
        steps=(
            "Read the finding's evidence field for the raw scanner observation.",
            "Consult your internal security checklist for the matching category.",
            "Re-run the scan after the fix to confirm resolution.",
        ),
    ),
)


def get_template(category_code: str) -> FallbackTemplate:
    """Return the template for one canonical category, falling back to generic."""
    return _TEMPLATES.get(category_code.upper(), GENERIC_FALLBACK)


def build_fallback_explanation(
    *,
    finding_id: str,
    category_code: str,
    model_name: str = "template-fallback",
    model_version: str = "1",
    provider: str = "template",
    prompt_template_version: str = "fallback.v1",
) -> FindingExplanation:
    """Construct a fully-formed ``FindingExplanation`` for a fallback path.

    The result has ``validation_status = FALLBACK_USED`` so the UI can
    visibly label it. Claims reference no evidence rows by construction —
    the validator never has to check fallback claims against the
    evidence set because fallback paths bypass the AI entirely.
    """
    template = get_template(category_code)
    return FindingExplanation(
        finding_id=finding_id,
        claims=template.claims,
        explanation_text=" ".join(bound_evidence(c.text) for c in template.claims).strip(),
        severity_rationale=bound_evidence(template.rationale),
        remediation=template.remediation,
        validation_status=ExplanationStatus.FALLBACK_USED,
        prompt_template_version=prompt_template_version,
        model_name=model_name,
        model_version=model_version,
        provider=provider,
        is_nondeterministic=False,
    )


def known_categories() -> Mapping[str, FallbackTemplate]:
    """Read-only view of the registered templates (for diagnostics)."""
    return MappingProxyType(_TEMPLATES)


__all__ = [
    "GENERIC_FALLBACK",
    "FallbackTemplate",
    "build_fallback_explanation",
    "get_template",
    "known_categories",
]
