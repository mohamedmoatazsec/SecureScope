"""Check registry. Order matters only for presentation: it is the order in reports."""

from __future__ import annotations

from securescope.checks.base import Check, ScanContext
from securescope.checks.cookies import CookiesCheck
from securescope.checks.cors import CORSCheck
from securescope.checks.csp import CSPCheck
from securescope.checks.disclosure import DisclosureCheck
from securescope.checks.headers import HeadersCheck
from securescope.checks.methods import MethodsCheck
from securescope.checks.recon import (
    DNSCheck,
    PortsCheck,
    RobotsCheck,
    SecurityTxtCheck,
    SubdomainsCheck,
    TechnologyCheck,
    WhoisCheck,
)
from securescope.checks.tls import TLSCheck

ALL_CHECKS: list[type[Check]] = [
    TLSCheck,
    HeadersCheck,
    CSPCheck,
    CookiesCheck,
    CORSCheck,
    MethodsCheck,
    DisclosureCheck,
    SecurityTxtCheck,
    RobotsCheck,
    TechnologyCheck,
    DNSCheck,
    WhoisCheck,
    SubdomainsCheck,
    PortsCheck,
]

CHECK_IDS = [check.id for check in ALL_CHECKS]

__all__ = ["ALL_CHECKS", "CHECK_IDS", "Check", "ScanContext"]
