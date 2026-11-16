"""Shared types for checks: the scan context they read and the base class."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests

from securescope.config import ScanConfig
from securescope.findings import CheckResult, Confidence, Finding, Severity
from securescope.http import ScanSession


@dataclass
class ScanContext:
    """What every check gets: the target, a configured session and the first response."""

    target: str
    session: ScanSession
    config: ScanConfig
    response: requests.Response | None = None
    fetch_error: str | None = None
    hops: list[dict[str, Any]] = field(default_factory=list)
    redirect_blocked: dict[str, str] | None = None  # {"location", "reason"} when a redirect was refused
    body_truncated: bool = False

    @property
    def parts(self):
        return urlsplit(self.target)

    @property
    def hostname(self) -> str:
        return self.parts.hostname or ""

    @property
    def scheme(self) -> str:
        return self.parts.scheme

    @property
    def port(self) -> int:
        if self.parts.port:
            return self.parts.port
        return 443 if self.scheme == "https" else 80

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.parts.netloc}"


class Check:
    """Base class. Subclasses set `id`/`name` and implement `run`.

    `run` must never raise for network problems: catch them and set
    `CheckResult.error`, so one flaky check does not take the scan down.
    """

    id: str = ""
    name: str = ""

    def run(self, ctx: ScanContext) -> CheckResult:  # pragma: no cover - interface
        raise NotImplementedError

    def result(self) -> CheckResult:
        return CheckResult(id=self.id, name=self.name)

    def finding(
        self,
        ctx: ScanContext,
        id: str,
        title: str,
        severity: Severity,
        description: str,
        remediation: str,
        *,
        confidence: Confidence = Confidence.CERTAIN,
        evidence: dict[str, Any] | None = None,
        references: list[str] | None = None,
        cwe: int | None = None,
    ) -> Finding:
        return Finding(
            id=id,
            title=title,
            severity=severity,
            description=description,
            remediation=remediation,
            check=self.id,
            confidence=confidence,
            evidence=evidence or {},
            references=references or [],
            cwe=cwe,
            target=ctx.target,
        )


def header_map(headers) -> dict[str, str]:
    """Lower-cased copy of a header mapping so lookups are case-insensitive."""
    return {str(k).lower(): str(v) for k, v in headers.items()}
