"""Deterministic compliance catalog: frameworks, controls, mappings (M9).

Versioned static seed — deliberately NOT database tables (STEP 19):

* mappings are developer-curated and identical for every user, so
  there is no ownership to scope and no per-user state to persist;
* ``MAPPING_VERSION`` stamps every assessment and report section, so a
  historical result always explains which mapping produced it;
* changing the mapping is a reviewed code change (bump the version),
  never a silent row edit — history cannot be rewritten quietly.

Framework choice (STEP 2/10): three widely-used frameworks, each with
a SMALL curated control subset covering exactly what SentinelGPT
detects (security headers, TLS, cookies/session handling, server
disclosure, known CVEs, DNS posture). A small accurate mapping beats
a huge inaccurate one; each control maps only to canonical
finding-category codes persisted on ``scan_finding`` rows.

Text provenance (STEP 20): control titles and descriptions below are
short SentinelGPT paraphrases for orientation — NOT official
framework text, and the dataset does NOT claim to be a complete
implementation of any framework. The ``source`` field names the
issuing body and version so auditors can consult the originals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAPPING_VERSION = "sgpt.compliance-map.v1"

# Control assessment states (STEP 5/9). The vocabulary is deliberately
# gap-oriented: NOTHING here means "compliant". In particular,
# NO_RELEVANT_FINDINGS only says no mapped-category finding was
# observed in scope — absence of evidence, never evidence of absence.
GAP_INDICATOR = "GAP_INDICATOR"
EVIDENCE_AVAILABLE = "EVIDENCE_AVAILABLE"
NO_RELEVANT_FINDINGS = "NO_RELEVANT_FINDINGS"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

STATUSES = (
    GAP_INDICATOR,
    EVIDENCE_AVAILABLE,
    NO_RELEVANT_FINDINGS,
    INSUFFICIENT_EVIDENCE,
)

# Lifecycle states that still indicate an open gap (anything not
# deterministically resolved counts, including unknown — an observed
# finding without a resolution row is evidence of a gap, not of a fix).
OPEN_LIFECYCLES = frozenset({"NEW", "PERSISTENT", "REGRESSED"})


@dataclass(frozen=True)
class ComplianceControl:
    """One curated control within a framework."""

    control_id: str
    title: str
    description: str


@dataclass(frozen=True)
class ComplianceFramework:
    """One framework: identity, source, controls, category mappings."""

    framework_id: str
    name: str
    version: str
    source: str
    active: bool
    controls: tuple[ComplianceControl, ...] = ()
    # canonical finding-category code -> control ids it is relevant to.
    mappings: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # control id -> one-sentence curated relevance rationale.
    rationales: dict[str, str] = field(default_factory=dict)


def _pci_dss() -> ComplianceFramework:
    controls = (
        ComplianceControl(
            control_id="2.2",
            title="System configuration standards",
            description=(
                "Systems should follow documented configuration standards "
                "with unnecessary functionality removed or disabled."
            ),
        ),
        ComplianceControl(
            control_id="4.2",
            title="Strong cryptography in transit",
            description=(
                "Sensitive data in transit should be protected with strong "
                "cryptography; deprecated protocols and weak ciphers avoided."
            ),
        ),
        ComplianceControl(
            control_id="6.3",
            title="Security vulnerabilities are identified and addressed",
            description=(
                "Known vulnerabilities in system components should be "
                "identified and remediated in a timely manner."
            ),
        ),
    )
    return ComplianceFramework(
        framework_id="pci-dss",
        name="PCI DSS",
        version="4.0",
        source="PCI Security Standards Council",
        active=True,
        controls=controls,
        mappings={
            "MISSING_SECURITY_HEADER": ("2.2",),
            "EXPOSED_ADMIN_PANEL": ("2.2",),
            "OUTDATED_TLS": ("4.2",),
            "WEAK_CIPHER": ("4.2",),
            "KNOWN_CVE": ("6.3",),
        },
        rationales={
            "2.2": "Missing headers and exposed panels indicate configuration hardening gaps.",
            "4.2": "Deprecated TLS versions and weak ciphers weaken transport protection.",
            "6.3": "CVE matches are known vulnerabilities awaiting remediation.",
        },
    )


def _iso_27001() -> ComplianceFramework:
    controls = (
        ComplianceControl(
            control_id="A.8.8",
            title="Management of technical vulnerabilities",
            description=(
                "Technical vulnerabilities should be identified and addressed "
                "before they can be exploited."
            ),
        ),
        ComplianceControl(
            control_id="A.8.9",
            title="Configuration management",
            description=(
                "Configurations, including security settings, should be "
                "established, documented, and controlled."
            ),
        ),
        ComplianceControl(
            control_id="A.8.20",
            title="Networks security",
            description=(
                "Networks should be secured, including the services and protocols they expose."
            ),
        ),
    )
    return ComplianceFramework(
        framework_id="iso-27001",
        name="ISO/IEC 27001",
        version="2022",
        source="ISO/IEC (Annex A controls)",
        active=True,
        controls=controls,
        mappings={
            "KNOWN_CVE": ("A.8.8",),
            "MISSING_SECURITY_HEADER": ("A.8.9",),
            "EXPOSED_ADMIN_PANEL": ("A.8.9",),
            "OUTDATED_TLS": ("A.8.20",),
            "WEAK_CIPHER": ("A.8.20",),
            "DNS_MISCONFIGURATION": ("A.8.20",),
        },
        rationales={
            "A.8.8": "CVE matches are technical vulnerabilities to manage.",
            "A.8.9": "Header and panel findings indicate configuration weaknesses.",
            "A.8.20": "TLS, cipher, and DNS findings concern network-exposed services.",
        },
    )


def _soc_2() -> ComplianceFramework:
    controls = (
        ComplianceControl(
            control_id="CC6.1",
            title="Logical access security",
            description=(
                "Access to system boundaries should be restricted to "
                "authorized parties through logical access controls."
            ),
        ),
        ComplianceControl(
            control_id="CC6.6",
            title="Encryption of data in transmission",
            description=(
                "Data transmitted over networks should be protected against "
                "interception with encryption."
            ),
        ),
        ComplianceControl(
            control_id="CC7.1",
            title="Detection and monitoring",
            description=(
                "Anomalies and vulnerabilities that could affect objectives "
                "should be detected through monitoring procedures."
            ),
        ),
    )
    return ComplianceFramework(
        framework_id="soc-2",
        name="SOC 2 Trust Services Criteria",
        version="2017 (2022 revision)",
        source="AICPA",
        active=True,
        controls=controls,
        mappings={
            "EXPOSED_ADMIN_PANEL": ("CC6.1",),
            "MISSING_SECURITY_HEADER": ("CC6.1",),
            "OUTDATED_TLS": ("CC6.6",),
            "WEAK_CIPHER": ("CC6.6",),
            "KNOWN_CVE": ("CC7.1",),
            "DNS_MISCONFIGURATION": ("CC7.1",),
        },
        rationales={
            "CC6.1": "Exposed panels and missing hardening headers touch access boundaries.",
            "CC6.6": "TLS and cipher findings concern transmission protection.",
            "CC7.1": "CVE and DNS findings are anomalies monitoring should surface.",
        },
    )


_FRAMEWORKS: tuple[ComplianceFramework, ...] = (_pci_dss(), _iso_27001(), _soc_2())

BY_ID: dict[str, ComplianceFramework] = {f.framework_id: f for f in _FRAMEWORKS}


def list_frameworks(*, active_only: bool = True) -> list[ComplianceFramework]:
    """All frameworks, stable id order (deterministic for API output)."""
    frameworks = [f for f in _FRAMEWORKS if f.active or not active_only]
    return sorted(frameworks, key=lambda f: f.framework_id)


def get_framework(framework_id: str) -> ComplianceFramework | None:
    """One framework by id (None maps to 404 upstream)."""
    return BY_ID.get(framework_id)


def controls_for_category(framework: ComplianceFramework, category: str | None) -> tuple[str, ...]:
    """Control ids relevant to one canonical finding category (empty if none)."""
    if not category:
        return ()
    return framework.mappings.get(category, ())


__all__ = [
    "MAPPING_VERSION",
    "GAP_INDICATOR",
    "EVIDENCE_AVAILABLE",
    "NO_RELEVANT_FINDINGS",
    "INSUFFICIENT_EVIDENCE",
    "STATUSES",
    "OPEN_LIFECYCLES",
    "ComplianceControl",
    "ComplianceFramework",
    "list_frameworks",
    "get_framework",
    "controls_for_category",
]
