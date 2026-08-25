"""Scan-time security boundary components (ADR-0001/0002).

Pure, network-free domain logic: IP policy evaluation, resolution outcome
contracts, validated target bindings, egress authorization, and redirect
revalidation policy. All actual DNS/network I/O lives behind injected
interfaces (see ``resolver.HostnameResolver``); nothing here performs I/O.
"""
