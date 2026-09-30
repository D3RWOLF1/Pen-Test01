from __future__ import annotations

import argparse
import json

from .scanner import scan_target


def main() -> None:
    parser = argparse.ArgumentParser(description="Pen-Test01 vulnerability scanner")
    parser.add_argument("target", help="Host or IP address to scan")
    parser.add_argument("--ports", default=None, help="Comma-separated ports or ranges, e.g. 80,443,8080-8085")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    args = parser.parse_args()

    result = scan_target(args.target, ports=args.ports, timeout=args.timeout)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    print(f"Target: {result.target}")
    print(f"Open ports: {result.open_ports if result.open_ports else 'none'}")
    if result.findings:
        print("Findings:")
        for finding in result.findings:
            print(f"- [{finding.severity.upper()}] {finding.title} (port {finding.port})")
    else:
        print("No findings detected.")


if __name__ == "__main__":
    main()
