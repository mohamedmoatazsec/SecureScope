"""Scan orchestration: fetch the target once, run every enabled check, assemble the result."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import requests

from securescope import __version__
from securescope.checks import ALL_CHECKS, ScanContext
from securescope.config import ScanConfig, normalize_url
from securescope.findings import CheckResult, Finding, sort_findings
from securescope.http import RedirectBlocked, ScanSession, read_body
from securescope.scoring import summarize


@dataclass
class ScanResult:
    target: str
    started: str
    duration: float
    reachable: bool
    checks: list[CheckResult] = field(default_factory=list)
    error: str | None = None

    @property
    def findings(self) -> list[Finding]:
        return sort_findings([f for check in self.checks for f in check.findings])

    @property
    def summary(self) -> dict[str, Any]:
        return summarize(self.findings)

    def check(self, check_id: str) -> CheckResult | None:
        return next((c for c in self.checks if c.id == check_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started": self.started,
            "duration_seconds": round(self.duration, 2),
            "reachable": self.reachable,
            "error": self.error,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class Report:
    targets: list[ScanResult]
    generated: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    tool: str = "SecureScope"
    version: str = __version__
    diff: dict[str, Any] | None = None

    @property
    def findings(self) -> list[Finding]:
        return sort_findings([f for target in self.targets for f in target.findings])

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema": "https://github.com/mohamedmoatazsec/SecureScope/blob/main/docs/report.schema.json",
            "tool": self.tool,
            "version": self.version,
            "generated": self.generated,
            "summary": summarize(self.findings),
            "targets": [t.to_dict() for t in self.targets],
        }
        if self.diff is not None:
            data["diff"] = self.diff
        return data


@dataclass
class Fetched:
    response: requests.Response | None = None
    error: str | None = None
    hops: list[dict[str, Any]] = field(default_factory=list)
    redirect_blocked: dict[str, str] | None = None
    truncated: bool = False


def fetch_target(session: ScanSession, target: str) -> Fetched:
    """GET the target with the hardened fetch; a refused redirect still yields the last response."""
    try:
        response = session.get(target)
    except RedirectBlocked as exc:
        last = exc.response
        hops = list(getattr(last, "securescope_hops", []) or [])
        if last is not None:
            read_body(last, 0)
            last.history = []
        return Fetched(
            response=last,
            hops=hops,
            redirect_blocked={"location": exc.location, "reason": str(exc.args[0])},
        )
    except requests.RequestException as exc:
        return Fetched(error=str(exc))
    return Fetched(
        response=response,
        hops=list(getattr(response, "securescope_hops", []) or []),
        truncated=bool(getattr(response, "securescope_truncated", False)),
    )


def scan_target(
    target: str,
    config: ScanConfig | None = None,
    progress: Callable[[str, CheckResult], None] | None = None,
) -> ScanResult:
    """Scan one target. Never raises for network problems; see ScanResult.error."""
    config = config or ScanConfig()
    target = normalize_url(target)
    started = datetime.now(timezone.utc)
    clock = time.monotonic()

    with ScanSession(config) as session:
        fetched = fetch_target(session, target)
        ctx = ScanContext(
            target=target,
            session=session,
            config=config,
            response=fetched.response,
            fetch_error=fetched.error,
            hops=fetched.hops,
            redirect_blocked=fetched.redirect_blocked,
            body_truncated=fetched.truncated,
        )
        result = ScanResult(
            target=target,
            started=started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            duration=0.0,
            reachable=fetched.response is not None,
            error=fetched.error,
        )

        for check_cls in ALL_CHECKS:
            if not config.wants(check_cls.id):
                continue
            check = check_cls()
            try:
                check_result = check.run(ctx)
            except Exception as exc:  # a bug in one check must not kill the scan
                check_result = CheckResult(id=check.id, name=check.name, error=f"{type(exc).__name__}: {exc}")
            result.checks.append(check_result)
            if progress:
                progress(target, check_result)

    result.duration = time.monotonic() - clock
    return result


def scan_targets(
    targets: list[str],
    config: ScanConfig | None = None,
    concurrency: int = 4,
    progress: Callable[[str, CheckResult], None] | None = None,
) -> Report:
    """Scan several targets, a few at a time, and bundle the results into one report."""
    config = config or ScanConfig()
    unique = list(dict.fromkeys(normalize_url(t) for t in targets))
    if len(unique) == 1 or concurrency <= 1:
        results = [scan_target(t, config, progress) for t in unique]
    else:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(unique))) as pool:
            results = list(pool.map(lambda t: scan_target(t, config, progress), unique))
    return Report(targets=results)
