"""Core vulnerability scanning engine."""

from __future__ import annotations

import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib import error, request

DEFAULT_PORTS = [22, 80, 443, 3306, 8080, 8443, 8000, 8888, 9000]


@dataclass
class Finding:
    """Represents a security finding."""

    id: str
    severity: str
    title: str
    description: str
    port: int | None = None
    service: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


@dataclass
class ScanResult:
    """Represents the results of a scan."""

    target: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "services": self.services,
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_at": self.scanned_at,
        }


class VulnerabilityScanner:
    """Performs lightweight scanning of hosts for common exposure points."""

    def __init__(self, timeout: float = 1.0):
        """Initialize scanner with connection timeout.

        Args:
            timeout: Socket connection timeout in seconds.
        """
        self.timeout = timeout

    @staticmethod
    def normalize_ports(ports: Iterable[int] | str | None) -> list[int]:
        """Parse and normalize port specification.

        Args:
            ports: Ports specification (None, comma-separated string, or iterable).
                   Supports ranges like "80-85" and individual ports.

        Returns:
            Sorted list of unique ports.

        Raises:
            ValueError: If port specification is invalid.
        """
        if ports is None:
            return DEFAULT_PORTS[:]

        if isinstance(ports, str):
            chunks = [c.strip() for c in ports.split(",") if c.strip()]
            values: list[int] = []
            for chunk in chunks:
                if "-" in chunk:
                    parts = [p.strip() for p in chunk.split("-", 1)]
                    if len(parts) != 2:
                        raise ValueError(f"Invalid port range: {chunk!r}")
                    try:
                        start, end = int(parts[0]), int(parts[1])
                    except ValueError as e:
                        raise ValueError(f"Invalid port range: {chunk!r}") from e
                    if start > end:
                        start, end = end, start
                    values.extend(range(start, end + 1))
                else:
                    try:
                        values.append(int(chunk))
                    except ValueError as e:
                        raise ValueError(f"Invalid port: {chunk!r}") from e
            return sorted(set(values))

        return sorted(set(int(p) for p in ports))

    @staticmethod
    def _resolve_target(target: str) -> str:
        """Resolve and validate target hostname.

        Args:
            target: Target hostname or IP address.

        Returns:
            Normalized target string.

        Raises:
            ValueError: If target is empty or invalid.
        """
        if not target or not target.strip():
            raise ValueError("Target must not be empty.")
        return target.strip()

    def scan_ports(self, target: str, ports: Iterable[int] | str | None = None) -> dict[int, str]:
        """Scan ports and detect services.

        Args:
            target: Target hostname or IP.
            ports: Ports to scan.

        Returns:
            Dictionary mapping open ports to service banners.
        """
        host = self._resolve_target(target)
        normalized_ports = self.normalize_ports(ports)
        open_services: dict[int, str] = {}

        for port in normalized_ports:
            if port < 1 or port > 65535:
                continue
            try:
                with socket.create_connection((host, port), timeout=self.timeout):
                    banner = self._read_banner(host, port)
                    open_services[port] = banner if banner else "tcp-open"
            except OSError:
                continue

        return open_services

    def _read_banner(self, host: str, port: int) -> str:
        """Attempt to read service banner.

        Args:
            host: Target hostname.
            port: Target port.

        Returns:
            Banner text or empty string if unavailable.
        """
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(0.5)
                data = sock.recv(1024)
                if data:
                    return data.decode("utf-8", errors="replace").strip()
        except OSError:
            pass
        return ""

    @staticmethod
    def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
        """Normalize HTTP headers to lowercase keys."""
        return {str(k).lower(): str(v) for k, v in headers.items()}

    def http_probe(self, host: str, port: int) -> dict[str, Any]:
        """Probe HTTP/HTTPS service.

        Args:
            host: Target hostname.
            port: Target port.

        Returns:
            Dictionary with HTTP response details or empty dict if unreachable.
        """
        candidates = [
            f"http://{host}:{port}/",
            f"https://{host}:{port}/",
        ]

        for url in candidates:
            try:
                req = request.Request(
                    url,
                    headers={"User-Agent": "PenTest01/0.1", "Timeout": str(self.timeout)},
                )
                with request.urlopen(req, timeout=self.timeout) as response:
                    headers = self._normalize_headers(dict(response.headers.items()))
                    body = response.read(4096).decode("utf-8", errors="replace")
                    return {
                        "url": url,
                        "status_code": response.status,
                        "headers": headers,
                        "content_type": headers.get("content-type", ""),
                        "body": body,
                    }
            except (error.URLError, ValueError, OSError, Exception):
                continue

        return {"url": None, "status_code": None, "headers": {}, "content_type": "", "body": ""}

    def _findings_for_probe(self, host: str, port: int, probe: dict[str, Any]) -> list[Finding]:
        """Generate findings from HTTP probe results.

        Args:
            host: Target hostname.
            port: Target port.
            probe: HTTP probe result dictionary.

        Returns:
            List of findings detected from probe.
        """
        findings: list[Finding] = []
        headers = probe.get("headers", {})
        body = probe.get("body", "")
        url = probe.get("url")
        lower_body = body.lower()

        # Missing security headers
        if "x-frame-options" not in headers:
            findings.append(
                Finding(
                    id="missing-security-headers",
                    severity="medium",
                    title="Missing security headers",
                    description="The service is not setting standard browser security headers (X-Frame-Options).",
                    port=port,
                    service="http",
                    evidence=url,
                )
            )

        # Missing CSP
        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    id="missing-csp",
                    severity="low",
                    title="No Content-Security-Policy header",
                    description="The application does not declare a Content-Security-Policy header.",
                    port=port,
                    service="http",
                    evidence=url,
                )
            )

        # Insecure HTTP
        if url and url.startswith("http://"):
            findings.append(
                Finding(
                    id="insecure-http",
                    severity="high",
                    title="Insecure HTTP endpoint",
                    description="The service is reachable over plain HTTP rather than HTTPS.",
                    port=port,
                    service="http",
                    evidence=url,
                )
            )

        # Authentication surface detected
        auth_keywords = ("username", "password", "login", "sign in", "auth")
        if any(keyword in lower_body for keyword in auth_keywords):
            findings.append(
                Finding(
                    id="auth-surface",
                    severity="low",
                    title="Authentication surface detected",
                    description="The endpoint contains authentication-related content and may warrant credential testing.",
                    port=port,
                    service="http",
                    evidence=url,
                )
            )

        # Insecure cookie
        set_cookie = headers.get("set-cookie", "")
        if set_cookie and "secure" not in set_cookie.lower():
            findings.append(
                Finding(
                    id="insecure-cookie",
                    severity="medium",
                    title="Cookie missing Secure flag",
                    description="The application sets cookies without the Secure attribute.",
                    port=port,
                    service="http",
                    evidence=set_cookie,
                )
            )

        # Missing HSTS
        if url and url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    id="missing-hsts",
                    severity="medium",
                    title="Missing HSTS header",
                    description="HTTPS is available but Strict-Transport-Security header is not set.",
                    port=port,
                    service="http",
                    evidence=url,
                )
            )

        return findings

    def scan(self, target: str, ports: Iterable[int] | str | None = None) -> ScanResult:
        """Execute full scan on target.

        Args:
            target: Target hostname or IP.
            ports: Ports to scan (None for defaults).

        Returns:
            ScanResult with findings and service information.
        """
        host = self._resolve_target(target)
        open_services = self.scan_ports(host, ports)
        result = ScanResult(
            target=host, open_ports=sorted(open_services), services=open_services
        )

        # Probe HTTP services
        for port in sorted(open_services):
            probe = self.http_probe(host, port)
            if not probe.get("url"):
                continue
            result.findings.extend(self._findings_for_probe(host, port, probe))

        # Deduplicate findings
        deduped: list[Finding] = []
        seen: set[tuple[str, int | None, str | None]] = set()
        for finding in result.findings:
            key = (finding.id, finding.port, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        result.findings = sorted(deduped, key=lambda f: (f.port or 0, f.id))

        return result


def scan_target(
    target: str, ports: Iterable[int] | str | None = None, timeout: float = 1.0
) -> ScanResult:
    """Convenience function to scan a target.

    Args:
        target: Target hostname or IP.
        ports: Ports to scan.
        timeout: Connection timeout.

    Returns:
        ScanResult with findings.
    """
    scanner = VulnerabilityScanner(timeout=timeout)
    return scanner.scan(target, ports)
