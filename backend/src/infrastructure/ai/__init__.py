"""AI provider boundary (ADR-0008).

The ONLY place in SentinelGPT allowed to talk to an external AI API.
Adapters implement the domain ``EvidenceAnalyzer`` protocol, translate
vendor SDK failures into the typed failure model, and receive NOTHING but
serialized evidence — no scanner context, no network handles for targets,
no EngineServices.

The Gemini SDK is permitted here explicitly; every other network/process
token stays forbidden by the static security guard's AI-zone rule.
"""
