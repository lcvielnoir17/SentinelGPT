"""Firestore infrastructure adapters (ADR-0011).

Production conversation persistence lives in
:mod:`.conversation_store`; :mod:`.memory_store` provides the local
development / test double with identical behavior and no durability.
"""
