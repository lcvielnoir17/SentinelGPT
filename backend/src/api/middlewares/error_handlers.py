"""Centralized exception handlers mapping every error to the SRS envelope.

Response shape (SRS Chapter 5, Section 14 / Chapter 3, Section 10):
    { "error": { "code": "...", "message": "...", "requestId": "..." } }

No stack traces or internal details ever reach the client (Chapter 2,
Section 11). Domain exceptions are translated here so route handlers contain
no try/except boilerplate (Chapter 6, Section 9).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.domain.errors import DomainError

# SRS Chapter 5, Section 14 — status-to-code mapping for framework errors.
_HTTP_ERROR_CODES: dict[int, str] = {
    status.HTTP_400_BAD_REQUEST: "VALIDATION_ERROR",
    status.HTTP_401_UNAUTHORIZED: "UNAUTHENTICATED",
    status.HTTP_403_FORBIDDEN: "FORBIDDEN",
    status.HTTP_404_NOT_FOUND: "NOT_FOUND",
    status.HTTP_405_METHOD_NOT_ALLOWED: "NOT_FOUND",
    status.HTTP_409_CONFLICT: "CONFLICT",
    status.HTTP_422_UNPROCESSABLE_CONTENT: "VALIDATION_ERROR",
    status.HTTP_429_TOO_MANY_REQUESTS: "RATE_LIMITED",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "INTERNAL_ERROR",
    status.HTTP_503_SERVICE_UNAVAILABLE: "SCAN_CAPACITY_EXCEEDED",
}

_GENERIC_ERROR_MESSAGE = "The request could not be processed."


def _request_id(request: Request) -> str:
    """Reuse the correlation id bound by the request-logging middleware."""
    return getattr(request.state, "request_id", None) or str(uuid.uuid4())


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "requestId": _request_id(request),
        }
    }
    response_headers = {"X-Request-ID": _request_id(request)}
    if headers:
        response_headers.update(headers)
    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers=response_headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach all centralized handlers to the application instance."""

    @app.exception_handler(DomainError)
    async def handle_domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return _error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        # Malformed body/params -> 400 VALIDATION_ERROR per the SRS catalog.
        return _error_response(
            request,
            status_code=status.HTTP_400_BAD_REQUEST,
            code="VALIDATION_ERROR",
            message=_GENERIC_ERROR_MESSAGE,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _HTTP_ERROR_CODES.get(exc.status_code, "INTERNAL_ERROR")
        message = str(exc.detail) if isinstance(exc.detail, str) else _GENERIC_ERROR_MESSAGE
        headers = getattr(exc, "headers", None)
        return _error_response(
            request,
            status_code=exc.status_code,
            code=code,
            message=message,
            headers=headers,
        )
