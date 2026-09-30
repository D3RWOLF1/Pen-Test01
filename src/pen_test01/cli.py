"""Command-line interface for Pen-Test01."""

from __future__ import annotations

import argparse
import json
import sys

from .scanner import scan_target


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Pen-Test01: Lightweight vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pen-test01 localhost
  pen-test01 example.com --ports 80,443,8080
  pen-test01 192.168.1.1 --ports 80-8090 --json
  pen-test01 example.com --timeout 2.5 --json > results.json
        """,
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "--ports",
        default=None,
        help="Ports to scan (comma-separated or ranges). Example: 80,443,8000-8090",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "--version", action="version", version="pen-test01 0.1.0"
    )

    args = parser.parse_args()

    try:
        result = scan_target(args.target, ports=args.ports, timeout=args.timeout)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"\nTarget: {result.target}")
            print(f"Open ports: {result.open_ports if result.open_ports else 'none'}")

            if result.findings:
                print(f"\nFindings ({len(result.findings)} detected):\n")
                by_severity = {}
                for finding in result.findings:
                    sev = finding.severity.upper()
                    if sev not in by_severity:
                        by_severity[sev] = []
                    by_severity[sev].append(finding)

                severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                for sev in severity_order:
                    if sev in by_severity:
                        print(f"[{sev}]")
                        for finding in by_severity[sev]:
                            print(
                                f"  • {finding.title} (port {finding.port})"
                            )
                            print(f"    {finding.description}")
                        print()
            else:
                print("\nNo findings detected.\n")

            print(f"Scan completed at: {result.scanned_at}")

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
