# Report Formats

Detailed documentation for the three output formats supported by the Keycloak Configuration Security Analyzer.

## Overview

The analyzer supports three report formats:

| Format | Use Case | Interactive | Programmatic |
|--------|----------|-------------|--------------|
| **Console** | Quick review, development | No | No |
| **JSON** | CI/CD, automation, tooling | No | Yes |
| **HTML** | Stakeholder reports, audits | Yes | No |

## Console Output

### Description

Rich terminal output with color-coded severity badges, perfect for quick reviews and development workflows.

### Features

- **Color-coded severity badges**:
  - 🔴 Critical (Red)
  - 🟠 High (Orange)
  - 🟡 Medium (Yellow)
  - 🔵 Low (Blue)
  - ⚪ Info (White/Gray)

- **Summary table** with finding counts
- **Detailed finding cards** with:
  - Check ID and name
  - Realm and client context
  - Description of the issue
  - Step-by-step remediation
  - RFC/CVE references

- **Grouping support**:
  - By severity (default)
  - By realm
  - By client (hierarchical)

### Example Output

```
╔══════════════════════════════════════╗
║ 🔒 Keycloak Security Analysis Report ║
╚══════════════════════════════════════╝

          Summary
╭──────────────────┬───────╮
│ Metric           │ Count │
├──────────────────┼───────┤
│ Realms Analyzed  │     3 │
│ Clients Analyzed │    45 │
│ Total Findings   │   127 │
│ Critical         │    12 │
│ High             │    28 │
│ Medium           │    45 │
│ Low              │    25 │
│ Info             │    17 │
╰──────────────────┴───────╯

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔴 CRITICAL (12 findings)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1. [KC-PKCE-001] PKCE not enforced for client 'mobile-app'
     Realm: production | Client: mobile-app

     Public client 'mobile-app' does not enforce PKCE, making it
     vulnerable to authorization code interception attacks.

     REMEDIATION:
     1. Log into Keycloak Admin Console
     2. Navigate to: Clients → 'mobile-app'
     3. Go to: Settings → Capability config
     4. Enable 'Proof Key for Code Exchange (PKCE) Code Challenge Method'
     5. Select 'S256' as the challenge method
     6. Click 'Save'

     References: RFC 9700 Section 3.1, RFC 7636, CVE-2023-28131
```

### Usage

```bash
# Default console output
keycloak-analyzer ./keycloak-configs

# With grouping
keycloak-analyzer ./keycloak-configs --group-by realm

# Filter severity
keycloak-analyzer ./keycloak-configs --severity high
```

### Best For

- Development and testing
- Quick security reviews
- Terminal-based workflows
- SSH sessions without GUI

## JSON Output

### Description

Machine-readable JSON format designed for programmatic consumption, CI/CD integration, and custom tooling.

### Structure

```json
{
  "metadata": {
    "version": "1.0",
    "timestamp": "2024-12-04T13:30:00",
    "analyzer_version": "0.1.0",
    "grouping_mode": "severity",
    "standards": [
      "RFC 9700 - OAuth 2.0 Security BCP",
      "RFC 7636 - PKCE",
      "OAuth 2.1 (Draft)",
      "OpenID Connect Core 1.0"
    ]
  },
  "summary": {
    "total_findings": 127,
    "realms_analyzed": 3,
    "clients_analyzed": 45,
    "exit_code": 1,
    "by_severity": {
      "critical": 12,
      "high": 28,
      "medium": 45,
      "low": 25,
      "info": 17
    },
    "by_category": {
      "PKCE": 15,
      "REDIRECT_URI": 22,
      "TOKEN_SECURITY": 18,
      ...
    },
    "by_client": {
      "mobile-app": 8,
      "web-app": 12,
      ...
    }
  },
  "grouped_findings": {
    "critical": [...],
    "high": [...],
    "medium": [...],
    "low": [...],
    "info": [...]
  },
  "findings": [
    {
      "check_id": "KC-PKCE-001",
      "check_name": "PKCE Not Enforced",
      "severity": "critical",
      "category": "PKCE",
      "realm_name": "production",
      "client_id": "mobile-app",
      "file_path": "/path/to/realm-export.json",
      "title": "PKCE not enforced for client 'mobile-app'",
      "description": "Public client 'mobile-app' does not enforce PKCE...",
      "remediation": "1. Log into Keycloak Admin Console...",
      "evidence": {
        "client_id": "mobile-app",
        "public_client": true,
        "pkce_code_challenge_method": null
      },
      "references": [
        "RFC 9700 Section 3.1",
        "RFC 7636",
        "CVE-2023-28131"
      ],
      "timestamp": "2024-12-04T13:30:00.123456"
    }
  ]
}
```

### Key Fields

**Metadata:**
- `version` - JSON schema version
- `timestamp` - Analysis timestamp (ISO 8601)
- `analyzer_version` - Tool version
- `grouping_mode` - How findings are grouped
- `standards` - Security standards used

**Summary:**
- `total_findings` - Total number of findings
- `realms_analyzed` - Number of realms scanned
- `clients_analyzed` - Number of clients scanned
- `exit_code` - Exit code (0 or 1)
- `by_severity` - Counts by severity level
- `by_category` - Counts by check category
- `by_client` - Counts per client

**Grouped Findings:**
- Organized by grouping mode (severity, realm, or client)
- Hierarchical structure for client grouping

**Findings (Flat List):**
- Always includes complete flat list
- Each finding has all details
- Evidence object with raw data
- Timestamps for tracking

### Grouping Modes

**By Severity (default):**
```json
{
  "grouped_findings": {
    "critical": [finding1, finding2],
    "high": [finding3, finding4],
    ...
  }
}
```

**By Realm:**
```json
{
  "grouped_findings": {
    "production": [finding1, finding2],
    "staging": [finding3, finding4],
    ...
  }
}
```

**By Client:**
```json
{
  "grouped_findings": {
    "production": {
      "mobile-app": [finding1, finding2],
      "web-app": [finding3]
    },
    "staging": {
      "mobile-app": [finding4]
    }
  },
  "grouping_note": "Findings grouped by realm then client. Realm-level findings excluded."
}
```

### Usage

```bash
# Generate JSON report
keycloak-analyzer ./keycloak-configs --format json --output report.json

# With grouping
keycloak-analyzer ./keycloak-configs --format json --output report.json --group-by client

# Quiet mode (no console output)
keycloak-analyzer ./keycloak-configs --format json --output report.json --quiet
```

### Best For

- CI/CD pipelines
- Automated security gates
- Custom reporting tools
- Data analysis and trending
- Integration with SIEM/security platforms

### Example: Parse with Python

```python
import json

with open('report.json') as f:
    report = json.load(f)

# Get summary
print(f"Total findings: {report['summary']['total_findings']}")
print(f"Critical: {report['summary']['by_severity']['critical']}")

# Filter critical findings
critical = [f for f in report['findings'] if f['severity'] == 'critical']
for finding in critical:
    print(f"{finding['check_id']}: {finding['title']}")

# Get findings by client
for client, count in report['summary']['by_client'].items():
    print(f"{client}: {count} findings")
```

### Example: Parse with jq

```bash
# Count findings by severity
jq '.summary.by_severity' report.json

# Get all critical finding titles
jq '.findings[] | select(.severity=="critical") | .title' report.json

# List clients with findings
jq '.summary.by_client | keys' report.json

# Get findings for specific client
jq '.findings[] | select(.client_id=="mobile-app")' report.json
```

## HTML Output

### Description

Interactive web report with JavaScript-based filtering and sorting. Perfect for sharing with stakeholders and conducting security audits.

### Features

- **Executive summary dashboard**
  - Total findings and severity breakdown
  - Realms and clients analyzed
  - Visual severity distribution

- **Dynamic filtering**
  - Filter by severity (Critical, High, Medium, Low, Info)
  - Show/hide specific severities
  - Real-time updates

- **Dynamic grouping**
  - Radio buttons to switch between severity/realm/client grouping
  - Grouping applied client-side (no reload)

- **Sortable findings**
  - Click column headers to sort
  - Sort by severity, realm, client, check ID

- **Expandable details**
  - Click finding to expand full details
  - Description, remediation, evidence, references
  - Collapsible for easy navigation

- **Responsive design**
  - Mobile-friendly layout
  - Works on tablets and phones
  - Accessible via screen readers

- **Print-friendly**
  - CSS optimized for printing
  - Page breaks at appropriate places

### Visual Design

- Color-coded severity badges
- Clean, professional styling
- Dark mode support (browser preference)
- Icons for visual hierarchy

### Usage

```bash
# Generate HTML report
keycloak-analyzer ./keycloak-configs --format html --output report.html

# With grouping (can switch in browser)
keycloak-analyzer ./keycloak-configs --format html --output report.html --group-by client

# Open in browser
open report.html  # macOS
xdg-open report.html  # Linux
start report.html  # Windows
```

### Best For

- Security audit reports
- Stakeholder presentations
- Executive summaries
- Sharing with non-technical users
- Archiving results

### Interactive Features

**Filtering:**
- Check/uncheck severity checkboxes
- Findings update in real-time
- Count updates automatically

**Grouping:**
- Switch between severity/realm/client views
- No page reload required
- Maintains filter state

**Expanding:**
- Click finding card to see full details
- Click again to collapse
- Keyboard accessible (Enter key)

### File Structure

Single HTML file contains:
- Embedded CSS (no external stylesheets)
- Embedded JavaScript (no external scripts)
- All data inline (no AJAX calls)

**Benefits:**
- No internet connection required
- Easy to share (single file)
- No dependencies
- Works offline

**Size:**
- Typical report: 500KB - 5MB
- Depends on number of findings
- Gzip compression recommended for storage

## Comparison

| Feature | Console | JSON | HTML |
|---------|---------|------|------|
| **Interactive filtering** | No | No | Yes |
| **Programmatic access** | No | Yes | No |
| **Shareable** | No | Yes | Yes |
| **Offline viewing** | Yes | No | Yes |
| **CI/CD friendly** | Yes | Yes | No |
| **Mobile-friendly** | No | No | Yes |
| **File size** | N/A | Medium | Large |
| **Export format** | Terminal | JSON | HTML |
| **Grouping support** | Yes | Yes | Yes |
| **Search/filter** | No | External | Built-in |

## Generating All Formats

Generate all three formats at once:

```bash
keycloak-analyzer ./keycloak-configs --format all --output report
```

Creates:
- Console output (displayed)
- `report.json`
- `report.html`

**Use case:** Complete audit package with all formats for different audiences.

## Related Documentation

- [Usage Guide](usage-guide.md) - Command-line options and workflows
- [Check Reference](check-reference.md) - Complete check documentation
- [README.md](../README.md) - Quick start guide
