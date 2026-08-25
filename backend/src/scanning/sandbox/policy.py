"""Sandbox egress policy: the binding-derived allow-list (ADR-0003).

The ONLY way to obtain a policy is :meth:`SandboxEgressPolicy.for_binding`,
which freezes the validated address set of one
:class:`~src.domain.scanning.binding.ValidatedTargetBinding`. Direct
construction raises: callers — including future API/service layers — cannot
hand a sandbox an arbitrary destination list that did not pass the scan-time
IP policy.

Immutability is enforced structurally: attribute assignment raises after
construction, and the exposed views are tuples. (As with all in-process
objects, a determined caller could reach through ``object.__setattr__``;
the authoritative containment boundary remains the sandbox runtime itself.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.domain.errors import EgressDeniedError

if TYPE_CHECKING:
    from src.domain.scanning.binding import ValidatedTargetBinding
    from src.domain.scanning.ip_policy import IPAddress


class SandboxEgressPolicy:
    """Immutable, binding-derived destination allow-list for one sandbox."""

    __slots__ = ("_addresses", "_hostname", "_sealed")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError(
            "SandboxEgressPolicy cannot be constructed directly; "
            "use SandboxEgressPolicy.for_binding(binding)"
        )

    @classmethod
    def for_binding(cls, binding: ValidatedTargetBinding) -> SandboxEgressPolicy:
        """Derive the allow-list from an already-validated binding."""
        if not binding.addresses:
            # Fail closed: a binding without addresses authorizes nothing,
            # and a sandbox must never be stood up with an empty rule set
            # masquerading as "validated".
            raise EgressDeniedError()
        instance = object.__new__(cls)
        object.__setattr__(instance, "_hostname", binding.hostname)
        object.__setattr__(instance, "_addresses", tuple(binding.addresses))
        object.__setattr__(instance, "_sealed", True)
        return instance

    @property
    def hostname(self) -> str:
        """The validated target hostname the list was derived from."""
        return self._hostname  # type: ignore[attr-defined,no-any-return]

    @property
    def allowed_addresses(self) -> tuple[IPAddress, ...]:
        """Every destination the sandbox will permit, in validated order."""
        return self._addresses  # type: ignore[attr-defined,no-any-return]

    @property
    def allowed_v4(self) -> tuple[IPAddress, ...]:
        return tuple(a for a in self.allowed_addresses if a.version == 4)

    @property
    def allowed_v6(self) -> tuple[IPAddress, ...]:
        return tuple(a for a in self.allowed_addresses if a.version == 6)

    @property
    def requires_ipv6_rules(self) -> bool:
        return bool(self.allowed_v6)

    def authorize(self, address: IPAddress) -> bool:
        """True only for addresses carried by the source binding."""
        return address in self._addresses  # type: ignore[attr-defined]

    def require_authorized(self, address: IPAddress) -> IPAddress:
        """Return the address if authorized; otherwise fail closed."""
        if not self.authorize(address):
            raise EgressDeniedError()
        return address

    def __setattr__(self, name: str, value: object) -> None:
        sealed = getattr(self, "_sealed", False)
        if sealed or name not in ("_hostname", "_addresses", "_sealed"):
            raise AttributeError("SandboxEgressPolicy is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("SandboxEgressPolicy is immutable")

    def __repr__(self) -> str:
        addresses = ", ".join(str(a) for a in self.allowed_addresses)
        return f"SandboxEgressPolicy(hostname={self.hostname!r}, addresses=[{addresses}])"
