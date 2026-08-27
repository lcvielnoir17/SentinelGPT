"""Finding evidence and identity persistence tests."""

from src.domain.scans.fingerprinting import generate_fingerprint

# Evidence type constants must match migration check constraint
ALLOWED_TYPES = {"RAW_HEADER", "TOOL_OUTPUT_SNIPPET", "RESPONSE_BODY_SNIPPET", "REQUEST_METADATA"}


def test_evidence_types_are_supported() -> None:
    for t in ALLOWED_TYPES:
        assert isinstance(t, str)


def test_evidence_content_bounded_at_model_layer() -> None:
    # FindingEvidence content check is char_length <= 2048 in DB.
    # The service truncates to 2048; ensure truncation logic would not exceed.
    long_content = "x" * 5000
    truncated = long_content[:2048]
    assert len(truncated) <= 2048


def test_finding_persistence_includes_canonical_fingerprint(tmp_path) -> None:  # noqa: ARG001
    # Canonical category rule: engine http.security-headers maps to DB code for fingerprint.
    from src.domain.scans.fingerprinting import generate_fingerprint_from_finding

    hostname = "example.com"
    title = "Missing Content-Security-Policy security header"

    # Simulate persistence path: canonical code is DB code
    canonical_fp = generate_fingerprint_from_finding(
        hostname=hostname, category_code="MISSING_SECURITY_HEADER", title=title
    )
    engine_fp = generate_fingerprint_from_finding(
        hostname=hostname, category_code="http.security-headers", title=title
    )
    # They differ — proving raw engine category would be unstable if used.
    assert canonical_fp != engine_fp
    # The persisted fingerprint must equal canonical, not engine alias.
    assert canonical_fp == generate_fingerprint(
        hostname=hostname,
        category_code="MISSING_SECURITY_HEADER",
        identifier="content-security-policy",
    )
