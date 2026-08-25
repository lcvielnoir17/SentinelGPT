"""Scanner engine boundary (ADR-0002).

The engine abstraction exists so future phases have a defined seam, but NO
engine implementation is provided and none may execute in this phase. Any
execution attempt raises ``ScannerExecutionBlockedError`` (501
SCANNER_EXECUTION_BLOCKED) before any network activity is possible.
"""
