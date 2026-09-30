# Pen-Test01

Pen-Test01 is a lightweight vulnerability scanner designed for quick reconnaissance and basic security auditing. It helps identify common exposure patterns in network services and HTTP endpoints, making it useful for internal validation and educational workflows.

## Features

- TCP port discovery for a target host
- HTTP/HTTPS endpoint probing
- Security header validation for web services
- Basic findings classification with severity tagging
- JSON-friendly output for automation and CI/CD integration
- CLI tooling for quick scans

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pen-test01 --target localhost --ports 80,443,8080 --json
```

## Example output

```json
{
  "target": "localhost",
  "open_ports": [80],
  "findings": [
    {
      "id": "missing-security-headers",
      "severity": "medium",
      "title": "Missing security headers",
      "description": "The service is not setting standard browser security headers."
    }
  ]
}
```

## Notes

This project intentionally focuses on common, low-noise checks rather than enterprise-grade exploitation workflows. It is ideal for local validation and learning while keeping the implementation dependency-light and portable.
