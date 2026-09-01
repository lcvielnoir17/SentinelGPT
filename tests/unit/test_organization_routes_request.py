"""Regression tests for organization route request/response models (P1-1).

The public API contract documents camelCase request fields (e.g. ``userId``).
The previous implementation only set ``serialization_alias``, so the
documented request body was rejected with 422. This suite pins the
contract: ``AddMemberRequest`` accepts ``userId`` as primary input while
continuing to accept ``user_id`` for backward compatibility, and
serialization still emits ``userId``.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from src.api.routes.organization_routes import AddMemberRequest


def test_add_member_accepts_camelcase_user_id() -> None:
    """The documented request body shape must validate."""
    user_id = uuid.uuid4()
    payload = {"userId": str(user_id), "role": "MEMBER"}
    request = AddMemberRequest.model_validate(payload)
    assert request.user_id == user_id
    assert request.role == "MEMBER"


def test_add_member_also_accepts_snake_case_user_id() -> None:
    """Backward compatibility: snake_case input continues to validate."""
    user_id = uuid.uuid4()
    payload = {"user_id": str(user_id), "role": "ADMIN"}
    request = AddMemberRequest.model_validate(payload)
    assert request.user_id == user_id
    assert request.role == "ADMIN"


def test_add_member_rejects_invalid_uuid_in_camelcase_input() -> None:
    """A malformed userId is still rejected with a validation error."""
    with pytest.raises(ValidationError):
        AddMemberRequest.model_validate({"userId": "not-a-uuid", "role": "MEMBER"})


def test_add_member_rejects_invalid_role_pattern() -> None:
    """The role pattern is enforced regardless of the field alias used."""
    with pytest.raises(ValidationError):
        AddMemberRequest.model_validate({"userId": str(uuid.uuid4()), "role": "GUEST"})


def test_add_member_serialization_emits_camelcase_user_id() -> None:
    """Output contract: the response body still emits ``userId``.

    FastAPI's ``serialize_response`` defaults to ``by_alias=True``, which
    means ``serialization_alias`` is the value the client sees on the wire.
    """
    user_id = uuid.uuid4()
    request = AddMemberRequest.model_validate({"userId": str(user_id), "role": "MEMBER"})
    dumped = request.model_dump(by_alias=True)
    assert "userId" in dumped
    assert dumped["userId"] == user_id
    assert dumped["role"] == "MEMBER"


def test_camelcase_preferred_over_snake_case_when_both_supplied() -> None:
    """When both keys are present, the first alias choice wins (userId)."""
    primary = uuid.uuid4()
    request = AddMemberRequest.model_validate(
        {"userId": str(primary), "user_id": str(uuid.uuid4()), "role": "ADMIN"}
    )
    assert request.user_id == primary
