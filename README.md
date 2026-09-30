# Pen-Test01

Production vulnerability scanner clone for professional penetration testers.

## Overview

Pen-Test01 is a lightweight reconnaissance and vulnerability scanning tool designed for quick security assessments. It identifies open ports, probes HTTP/HTTPS services, detects missing security headers, and classifies findings by severity.

## Features

- **Port Discovery**: Scan and identify open ports on target hosts
- **Service Detection**: Banner grabbing and service identification
- **HTTP/HTTPS Probing**: Test web services for accessibility and security configurations
- **Security Header Validation**: Detect missing or improperly configured security headers
- **Finding Classification**: Severity-based reporting (low, medium, high, critical)
- **JSON Output**: Machine-readable results for automation and CI/CD integration
- **Fast Scans**: Configurable timeouts and concurrent port checks

## Installation

```bash
git clone https://github.com/D3RWOLF1/Pen-Test01.git
cd Pen-Test01
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

## Quick Start

### Scan a host with default ports

```bash
pen-test01 localhost
```

### Scan specific ports

```bash
pen-test01 example.com --ports 80,443,8080
```

### Scan a port range

```bash
pen-test01 192.168.1.1 --ports 80-8090
```

### Output JSON results

```bash
pen-test01 example.com --json > scan_results.json
```

### Adjust timeout

```bash
pen-test01 example.com --timeout 2.5
```

## Example Output

### Text Format

```
Target: localhost
Open ports: [80, 443]
Findings:
- [HIGH] Insecure HTTP endpoint (port 80)
- [MEDIUM] Missing security headers (port 80)
- [LOW] No Content-Security-Policy header (port 443)
```

### JSON Format

```json
{
  "target": "localhost",
  "open_ports": [80, 443],
  "services": {
    "80": "nginx/1.18.0",
    "443": "nginx/1.18.0"
  },
  "findings": [
    {
      "id": "insecure-http",
      "severity": "high",
      "title": "Insecure HTTP endpoint",
      "description": "The service is reachable over plain HTTP rather than HTTPS.",
      "port": 80,
      "service": "http",
      "evidence": "http://localhost:80/"
    },
    {
      "id": "missing-security-headers",
      "severity": "medium",
      "title": "Missing security headers",
      "description": "The service is not setting standard browser security headers.",
      "port": 80,
      "service": "http",
      "evidence": "http://localhost:80/"
    }
  ],
  "scanned_at": "2026-09-30T14:55:00+00:00"
}
```

## Architecture

- `src/pen_test01/__init__.py` - Package initialization and public API
- `src/pen_test01/scanner.py` - Core scanning engine and finding detection
- `src/pen_test01/cli.py` - Command-line interface
- `tests/` - Unit and integration tests

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Install in development mode
pip install -e ".[dev]"

# Run type checks
mypy src/
```

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.
