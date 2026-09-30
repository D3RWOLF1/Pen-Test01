from __future__ import annotations

import json
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib import error, request

DEFAULT_PORTS = [22, 80, 443, 3306, 8080, 8443, 8000, 8888, 9000]


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    port: int | None = None
    service: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "services": self.services,
            "findings": [finding.to_dict() for finding in self.findings],
            "scanned_at": self.scanned_at,
        }


class VulnerabilityScanner:
    """Performs a lightweight scan of a host for common exposure points."""

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    @staticmethod
    def normalize_ports(ports: Iterable[int] | str | None) -> list[int]:
        if ports is None:
            return DEFAULT_PORTS[:]
        if isinstance(ports, str):
            chunks = [chunk.strip() for chunk in ports.split(",") if chunk.strip()]
            values: list[int] = []
            for chunk in chunks:
                if "-" in chunk:
                    start_text, end_text = [part.strip() for part in chunk.split("-", 1)]
                    try:
                        start = int(start_text)
                        end = int(end_text)
                    except ValueError as exc:
                        raise ValueError(f"Invalid port range: {chunk!r}") from exc
                    if start > end:
                        start, end = end, start
                    values.extend(range(start, end + 1))
                else:
                    values.append(int(chunk))
            return sorted(set(values))
        values = []
        for port in ports:
            values.append(int(port))
        return sorted(set(values))

    @staticmethod
    def _resolve_target(target: str) -> str:
        if not target or not target.strip():
            raise ValueError("Target must not be empty.")
        return target.strip()

    def scan_ports(self, target: str, ports: Iterable[int] | str | None = None) -> dict[int, str]:
        host = self._resolve_target(target)
        normalized_ports = self.normalize_ports(ports)
        open_services: dict[int, str] = {}

        for port in normalized_ports:
            if port < 1 or port > 65535:
                continue
            try:
                with socket.create_connection((host, port), timeout=self.timeout):
                    banner = self._read_banner(host, port)
                    if banner:
                        open_services[port] = banner
                    else:
                        open_services[port] = "tcp-open"
            except OSError:
                continue
        return open_services

    @staticmethod
    def _read_banner(host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=1.0) as sock:
                sock.settimeout(1.0)
                data = sock.recv(1024)
                if data:
                    return data.decode("utf-8", errors="replace").strip()
        except OSError:
            pass
        return ""

    @staticmethod
    def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
        return {str(k).lower(): str(v) for k, v in headers.items()}

    def http_probe(self, host: str, port: int) -> dict[str, Any]:
        candidates = []
        if port in {80, 443}:
            candidates = [
                f"http://{host}:{port}/",
                f"https://{host}:{port}/",
            ]
        else:
            candidates = [
                f"http://{host}:{port}/",
                f"https://{host}:{port}/",
            ]

        for url in candidates:
            try:
                req = request.Request(url, headers={"User-Agent": "PenTest01/0.1"})
                with request.urlopen(req, timeout=self.timeout) as response:
                    headers = self._normalize_headers(dict(response.headers.items()))
                    return {
                        "url": url,
                        "status_code": response.status,
                        "headers": headers,
                        "content_type": headers.get("content-type", ""),
                        "body": response.read(2048).decode("utf-8", errors="replace"),
                    }
            except (error.URLError, ValueError, TimeoutError):
                continue
            except Exception:
                continue
        return {"url": None, "status_code": None, "headers": {}, "content_type": "", "body": ""}

    def _findings_for_probe(self, host: str, port: int, probe: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        headers = probe.get("headers", {})
        body = probe.get("body", "")
        title = probe.get("url")
        lower_body = body.lower()

        if "x-frame-options" not in headers:
            findings.append(
                Finding(
                    id="missing-security-headers",
                    severity="medium",
                    title="Missing security headers",
                    description="The service is not setting standard browser security headers.",
                    port=port,
                    service="http",
                    evidence=title,
                )
            )
        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    id="missing-csp",
                    severity="low",
                    title="No Content-Security-Policy header",
                    description="The application does not declare a Content-Security-Policy header.",
                    port=port,
                    service="http",
                    evidence=title,
                )
            )
        if probe.get("url", "").startswith("http://"):
            findings.append(
                Finding(
                    id="insecure-http",
                    severity="high",
                    title="Insecure HTTP endpoint",
                    description="The service is reachable over plain HTTP rather than HTTPS.",
                    port=port,
                    service="http",
                    evidence=probe.get("url"),
                )
            )
        if any(keyword in lower_body for keyword in ("username", "password", "login", "sign in")):
            findings.append(
                Finding(
                    id="auth-surface",
                    severity="low",
                    title="Authentication surface detected",
                    description="The endpoint contains login-oriented content and may warrant credential testing.",
                    port=port,
                    service="http",
                    evidence=title,
                )
            )
        if "set-cookie" in headers and "secure" not in headers.get("set-cookie", "").lower():
            findings.append(
                Finding(
                    id="insecure-cookie",
                    severity="medium",
                    title="Cookie missing Secure flag",
                    description="The application sets cookies without the Secure attribute.",
                    port=port,
                    service="http",
                    evidence=headers.get("set-cookie", ""),
                )
            )

        return findings

    def scan(self, target: str, ports: Iterable[int] | str | None = None) -> ScanResult:
        host = self._resolve_target(target)
        open_services = self.scan_ports(host, ports)
        result = ScanResult(target=host, open_ports=sorted(open_services), services=open_services)

        for port in sorted(open_services):
            probe = self.http_probe(host, port)
            if not probe.get("url"):
                continue
            result.findings.extend(self._findings_for_probe(host, port, probe))

        deduped: list[Finding] = []
        seen: set[str] = set()
        for finding in result.findings:
            key = (finding.id, finding.port, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        result.findings = deduped
        return result


def scan_target(target: str, ports: Iterable[int] | str | None = None, timeout: float = 1.0) -> ScanResult:
    scanner = VulnerabilityScanner(timeout=timeout)
    return scanner.scan(target, ports)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Lightweight web service and port scanner")
    parser.add_argument("target", help="Host or IP to scan")
    parser.add_argument("--ports", default=None, help="Comma-separated port list or range, e.g. 80,443,8080-8085")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    result = scan_target(args.target, args.ports, timeout=args.timeout)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"Target: {result.target}")
        print(f"Open ports: {result.open_ports or 'none'}")
        if result.findings:
            print("Findings:")
            for finding in result.findings:
                print(f"- [{finding.severity.upper()}] {finding.title} (port {finding.port})")
        else:
            print("No significant findings detected.")


if __name__ == "__main__":
    main()
