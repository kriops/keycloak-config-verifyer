# Usage Guide

Comprehensive guide for using the Keycloak Configuration Security Analyzer.

## Command Line Interface

```bash
keycloak-analyzer <path> [OPTIONS]
```

### Arguments

- `path` - Directory containing Keycloak realm export files (JSON)

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format: `console`, `json`, `html`, or `all` | `console` |
| `-o, --output` | Output file path (required for json/html formats) | - |
| `-s, --severity` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | Show all |
| `-g, --group-by` | Grouping mode: `severity`, `realm`, or `client` | `severity` |
| `--no-fail` | Always exit with code 0 (don't fail on findings) | Exit 1 on Critical/High |
| `-q, --quiet` | Suppress console output | Show output |
| `--help` | Show help message | - |

## Basic Usage

### Simple Analysis

Analyze realm configurations and display results in the terminal:

```bash
keycloak-analyzer ./keycloak-configs
```

Output shows:
- Summary statistics (realms, clients, findings by severity)
- Detailed findings organized by severity
- Remediation steps for each issue
- RFC/CVE references

### Generate Reports

**HTML Report:**
```bash
keycloak-analyzer ./keycloak-configs --format html --output report.html
```

Open `report.html` in a browser to get:
- Interactive dashboard
- Filter by severity
- Sortable findings table
- Expandable details

**JSON Report:**
```bash
keycloak-analyzer ./keycloak-configs --format json --output report.json
```

Machine-readable format for:
- CI/CD integration
- Custom tooling
- Programmatic analysis

**All Formats:**
```bash
keycloak-analyzer ./keycloak-configs --format all --output report
```

Creates both `report.json` and `report.html`.

## Filtering & Grouping

### Filter by Severity

Show only Critical and High severity findings:

```bash
keycloak-analyzer ./keycloak-configs --severity high
```

Show only Critical findings:

```bash
keycloak-analyzer ./keycloak-configs --severity critical
```

### Group Findings

**By Severity (default):**
```bash
keycloak-analyzer ./keycloak-configs
```

Output organized:
```
Critical (5)
  - Finding 1
  - Finding 2
High (12)
  - Finding 3
  ...
```

**By Realm:**
```bash
keycloak-analyzer ./keycloak-configs --group-by realm
```

Output organized:
```
Realm: production
  Critical (3)
    - Finding 1
  High (5)
    - Finding 2
Realm: staging
  ...
```

**By Client:**
```bash
keycloak-analyzer ./keycloak-configs --group-by client
```

Output organized:
```
Realm: production
  Client: my-web-app
    - Finding 1
    - Finding 2
  Client: mobile-app
    - Finding 3
```

Note: Realm-level findings (without a specific client) are excluded in client grouping mode.

## CI/CD Integration

### Exit Codes

- `0` - Success, no Critical or High severity findings
- `1` - Critical or High severity findings detected, or error occurred

### GitHub Actions Example

```yaml
name: Keycloak Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh

      - name: Install analyzer
        run: |
          uv venv
          source .venv/bin/activate
          uv pip install keycloak-config-verifyer

      - name: Run security analysis
        run: |
          source .venv/bin/activate
          keycloak-analyzer ./keycloak-configs --format json --output report.json --quiet

      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: report.json
```

### Don't Fail on Findings (Audit Mode)

Use `--no-fail` to generate reports without blocking CI:

```bash
keycloak-analyzer ./keycloak-configs --format json --output report.json --no-fail
```

Always exits with code 0, even with Critical findings. Useful for:
- Initial security audits
- Periodic reporting
- Tracking improvements over time

### Quiet Mode

Suppress console output, only generate files:

```bash
keycloak-analyzer ./keycloak-configs --format json --output report.json --quiet
```

Combines well with CI/CD pipelines.

## File Discovery

The analyzer automatically discovers realm export files by scanning the specified directory recursively.

### Supported File Patterns

- `realm-export.json`
- `*-realm.json` (e.g., `production-realm.json`, `staging-realm.json`)

### Directory Structure Examples

**Single realm:**
```
keycloak-configs/
└── realm-export.json
```

**Multiple realms:**
```
keycloak-configs/
├── production-realm.json
├── staging-realm.json
└── development-realm.json
```

**Nested structure:**
```
keycloak-configs/
├── prod/
│   └── realm-export.json
└── staging/
    └── realm-export.json
```

### Export Format Support

Both single-realm and multi-realm export formats are supported:

**Single realm export:**
```json
{
  "realm": "my-realm",
  "clients": [...]
}
```

**Multi-realm export:**
```json
[
  {
    "realm": "realm1",
    "clients": [...]
  },
  {
    "realm": "realm2",
    "clients": [...]
  }
]
```

## Common Workflows

### Initial Security Audit

```bash
# 1. Analyze and review console output
keycloak-analyzer ./keycloak-configs

# 2. Generate HTML report for stakeholders
keycloak-analyzer ./keycloak-configs --format html --output audit-report.html

# 3. Generate JSON for tracking
keycloak-analyzer ./keycloak-configs --format json --output audit-baseline.json --no-fail
```

### Focus on Critical Issues

```bash
# Show only Critical findings
keycloak-analyzer ./keycloak-configs --severity critical

# Generate report with only High+ findings
keycloak-analyzer ./keycloak-configs --severity high --format html --output critical-issues.html
```

### Client-Specific Analysis

```bash
# Group by client to see which clients have issues
keycloak-analyzer ./keycloak-configs --group-by client

# Generate client-focused report
keycloak-analyzer ./keycloak-configs --group-by client --format html --output client-report.html
```

### Compare Environments

```bash
# Analyze production
keycloak-analyzer ./prod-configs --format json --output prod-report.json --no-fail

# Analyze staging
keycloak-analyzer ./staging-configs --format json --output staging-report.json --no-fail

# Compare manually or with custom tooling
diff prod-report.json staging-report.json
```

### Track Improvements Over Time

```bash
# Initial baseline
keycloak-analyzer ./keycloak-configs --format json --output baseline-2024-01.json --no-fail

# After fixes
keycloak-analyzer ./keycloak-configs --format json --output report-2024-02.json --no-fail

# Compare
python -c "
import json
baseline = json.load(open('baseline-2024-01.json'))
current = json.load(open('report-2024-02.json'))
print(f\"Baseline: {baseline['summary']['total_findings']} findings\")
print(f\"Current: {current['summary']['total_findings']} findings\")
print(f\"Improvement: {baseline['summary']['total_findings'] - current['summary']['total_findings']}\")
"
```

## Troubleshooting

### No realm files found

**Error:** "No Keycloak realm export files found"

**Solution:** Ensure files match the naming pattern:
- `realm-export.json`
- `*-realm.json`

### Module not found

**Error:** "No module named keycloak_analyzer"

**Solution:** Activate virtual environment and install:
```bash
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Permission denied

**Error:** Permission denied when reading files

**Solution:** Check file permissions:
```bash
chmod +r keycloak-configs/*.json
```

### Invalid JSON

**Error:** JSON decoding error

**Solution:** Validate your realm export files:
```bash
python -m json.tool realm-export.json > /dev/null
```

If invalid, re-export from Keycloak Admin Console.

## Related Documentation

- [README.md](../README.md) - Quick start and overview
- [docs/check-reference.md](check-reference.md) - Complete security check documentation
- [docs/reports.md](reports.md) - Report format details
- [AGENTS.md](../AGENTS.md) - Development guide
