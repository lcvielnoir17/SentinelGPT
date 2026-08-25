"""Platform DNS resolution adapter implementing the scan resolver contract.

This module is the ONLY sanctioned DNS I/O point for scanning (Phase 2):
it performs fresh ``getaddrinfo`` lookups through the operating-system
resolver and adapts the result into the domain's typed outcome model.

Placement is deliberate:

* ``src/domain/scanning/`` stays network-inert (ADR-0002, enforced by the
  static guard test);
* the IP policy is NOT duplicated here — the adapter returns every address
  it observed and leaves admission decisions entirely to
  :mod:`src.domain.scanning.ip_policy` consumers;
* results are never cached. Every call resolves afresh so validation-time
  and connection-time observations can never silently diverge behind a
  stale answer (DNS-rebinding defense, ADR-0001/0002).

Failure classification follows platform error codes: POSIX reports ``EAI_*``
constants while Windows reports ``WSA*`` codes; both families are mapped
onto the same three coarse kinds. Unknown failures degrade to the transient
class — the domain layer converts every failure into a controlled
``TargetUnresolvedError`` regardless.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from src.domain.scanning.resolver import (
    ResolutionFailure,
    ResolutionFailureKind,
    ResolutionSuccess,
)

if TYPE_CHECKING:
    from src.domain.scanning.ip_policy import IPAddress
    from src.domain.scanning.resolver import ResolutionOutcome

# A single getaddrinfo record: (family, type, proto, canonname, sockaddr).
# ``sockaddr`` shape varies by family (v4: (ip, port); v6: (ip, port,
# flowinfo, scope_id)), hence the loosely typed payload.
GetAddrInfoRecord = tuple[int, int, int, str, tuple[Any, ...]]
GetAddrInfoFn = Callable[..., Sequence[GetAddrInfoRecord]]

# Error numbers per failure kind, unioned across platforms because the
# available constants differ between POSIX (EAI_*) and Windows (WSA*).
_NAME_NOT_FOUND_ERRNOS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "WSAHOST_NOT_FOUND", None),
    )
    if code is not None
)
_NO_RECORDS_ERRNOS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_NODATA", None),
        getattr(socket, "WSANO_DATA", None),
    )
    if code is not None
)
_TRANSIENT_ERRNOS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_AGAIN", None),
        getattr(socket, "WSATRY_AGAIN", None),
    )
    if code is not None
)

_RELEVANT_FAMILIES = (socket.AF_INET, socket.AF_INET6)


def _classify_gaierror(errno: int) -> ResolutionFailureKind:
    """Map a resolver errno onto the coarse failure taxonomy."""
    # Windows collapses EAI_NONAME and EAI_NODATA onto the same WSA code
    # (11001), so name-not-found MUST be tested first; a resolved name with
    # zero usable A/AAAA records is still caught by the explicit post-success
    # record-count failure below.
    if errno in _NAME_NOT_FOUND_ERRNOS:
        return ResolutionFailureKind.NAME_NOT_FOUND
    if errno in _NO_RECORDS_ERRNOS:
        return ResolutionFailureKind.NO_RECORDS
    return ResolutionFailureKind.TRANSIENT_ERROR


class PlatformDnsResolver:
    """Fresh, complete A+AAAA resolution via the OS resolver.

    Implements :class:`src.domain.scanning.resolver.HostnameResolver`.
    The underlying lookup callable is injectable so unit tests stay fully
    hermetic; production uses :func:`socket.getaddrinfo` directly.
    """

    def __init__(self, getaddrinfo: GetAddrInfoFn | None = None) -> None:
        self._getaddrinfo: GetAddrInfoFn = getaddrinfo or socket.getaddrinfo

    def resolve_all(self, hostname: str) -> ResolutionOutcome:
        """Resolve now and return every A/AAAA address, deduplicated."""
        name = hostname.strip()
        if not name:
            return ResolutionFailure(
                name,
                ResolutionFailureKind.NAME_NOT_FOUND,
                detail="empty hostname",
            )
        try:
            records = self._getaddrinfo(
                name,
                None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            errno = getattr(exc, "errno", None)
            kind = (
                _classify_gaierror(int(errno))
                if errno is not None
                else ResolutionFailureKind.TRANSIENT_ERROR
            )
            return ResolutionFailure(name, kind, detail=str(exc))

        addresses: set[IPAddress] = set()
        for family, _socktype, _proto, _canonname, sockaddr in records:
            if family not in _RELEVANT_FAMILIES:
                continue
            addresses.add(ipaddress.ip_address(sockaddr[0]))

        if not addresses:
            # A successful lookup with zero usable records is an explicit
            # failure, never an empty authorization set.
            return ResolutionFailure(name, ResolutionFailureKind.NO_RECORDS)

        ordered = tuple(sorted(addresses, key=lambda a: (a.version, int(a))))
        return ResolutionSuccess(hostname=name, addresses=ordered)


if TYPE_CHECKING:
    # Compile-time proof that the adapter satisfies the domain contract.
    from src.domain.scanning.resolver import HostnameResolver

    _conforms: HostnameResolver = PlatformDnsResolver()
