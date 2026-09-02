"""Conversational security-analyst domain (ADR-0011).

Owns the conversation aggregate: domain models, the storage protocol, and
the orchestration service that assembles scan/finding context, enforces
per-user isolation, and drives the multi-turn Gemini analyst.
"""
