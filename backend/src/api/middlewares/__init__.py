"""API Middlewares package for SentinelGPT."""

from src.api.middlewares.error_handlers import register_exception_handlers

__all__ = ["register_exception_handlers"]
