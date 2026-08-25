"""Network I/O adapters for scanning (DNS resolution; ADR-0002/0003).

This package intentionally contains real network capability. It is the
designated infrastructure zone for it: the domain layer
(``src/domain/scanning``) and the engine abstractions remain network-inert,
enforced by ``tests/unit/test_scanner_boundary_static.py``.
"""
