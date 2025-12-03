"""HTML reporter with JavaScript interactivity."""

from datetime import datetime
from typing import List
from html import escape

from .base import Reporter, ReportSummary
from ..models import Finding, Severity


class HTMLReporter(Reporter):
    """Interactive HTML report with JavaScript filtering."""

    def generate(self, findings: List[Finding], summary: ReportSummary) -> str:
        """
        Generate HTML report.

        Args:
            findings: List of findings to report.
            summary: Summary statistics.

        Returns:
            Complete HTML document as string.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keycloak Security Analysis Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                line-height: 1.6; color: #333; background: #f5f7fa; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        .header {{ background: #fff; padding: 30px; border-radius: 8px; margin-bottom: 20px;
                   box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header h1 {{ color: #2c3e50; margin-bottom: 8px; font-size: 28px; }}
        .header .timestamp {{ color: #7f8c8d; font-size: 14px; }}

        .summary {{ background: #fff; padding: 25px; border-radius: 8px; margin-bottom: 20px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .summary h2 {{ margin-bottom: 20px; color: #2c3e50; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .summary-item {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 6px;
                         transition: transform 0.2s; }}
        .summary-item:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .summary-item .value {{ font-size: 36px; font-weight: bold; margin-bottom: 5px; }}
        .summary-item .label {{ font-size: 13px; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }}

        .severity-critical {{ color: {self.severity_html_color(Severity.CRITICAL)}; }}
        .severity-high {{ color: {self.severity_html_color(Severity.HIGH)}; }}
        .severity-medium {{ color: {self.severity_html_color(Severity.MEDIUM)}; }}
        .severity-low {{ color: {self.severity_html_color(Severity.LOW)}; }}
        .severity-info {{ color: {self.severity_html_color(Severity.INFO)}; }}

        .filters {{ background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .filters h3 {{ margin-bottom: 15px; color: #2c3e50; }}
        .filter-options {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .filter-options label {{ display: flex; align-items: center; gap: 8px; cursor: pointer;
                                  font-size: 14px; user-select: none; }}
        .filter-options input[type="checkbox"] {{ cursor: pointer; width: 18px; height: 18px; }}

        .findings {{ display: grid; gap: 20px; }}
        .realm-group {{ margin-bottom: 30px; }}
        .realm-header {{ background: #2c3e50; color: #fff; padding: 15px 20px; border-radius: 8px 8px 0 0;
                         font-size: 18px; font-weight: 600; margin-bottom: 0; cursor: pointer;
                         display: flex; justify-content: space-between; align-items: center; }}
        .realm-header:hover {{ background: #34495e; }}
        .realm-toggle {{ font-size: 20px; transition: transform 0.3s; }}
        .realm-toggle.collapsed {{ transform: rotate(-90deg); }}
        .realm-findings {{ display: grid; gap: 20px; padding: 20px; background: #f8f9fa;
                           border-radius: 0 0 8px 8px; }}
        .realm-findings.collapsed {{ display: none; }}
        .finding {{ background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    border-left: 5px solid #ddd; transition: all 0.3s; }}
        .finding:hover {{ box-shadow: 0 4px 16px rgba(0,0,0,0.15); }}
        .finding.hidden {{ display: none; }}

        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start;
                           margin-bottom: 15px; gap: 15px; }}
        .finding-title {{ font-size: 18px; font-weight: 600; flex-grow: 1; color: #2c3e50; }}
        .finding-badge {{ padding: 5px 12px; border-radius: 4px; color: #fff; font-size: 12px;
                          font-weight: bold; text-transform: uppercase; white-space: nowrap; }}

        .finding-meta {{ display: flex; gap: 20px; margin-bottom: 15px; font-size: 14px;
                         color: #6c757d; flex-wrap: wrap; }}
        .finding-meta strong {{ color: #495057; }}

        .finding-section {{ margin-bottom: 15px; }}
        .finding-section h4 {{ color: #495057; margin-bottom: 8px; font-size: 14px;
                               text-transform: uppercase; letter-spacing: 0.5px; }}
        .finding-description {{ color: #555; white-space: pre-wrap; line-height: 1.7; }}
        .finding-remediation {{ background: #f8f9fa; padding: 15px; border-radius: 6px;
                                white-space: pre-wrap; font-family: 'Courier New', monospace;
                                font-size: 13px; line-height: 1.6; overflow-x: auto; }}
        .finding-references {{ font-size: 12px; color: #6c757d; }}
        .finding-references span {{ display: inline-block; margin-right: 15px; }}

        .footer {{ text-align: center; padding: 30px; color: #6c757d; font-size: 14px; }}

        .exit-code-warning {{ background: #fff3cd; border: 2px solid #ffc107; padding: 15px;
                              border-radius: 6px; margin: 20px 0; color: #856404; }}
        .exit-code-success {{ background: #d4edda; border: 2px solid #28a745; padding: 15px;
                              border-radius: 6px; margin: 20px 0; color: #155724; }}

        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .filter-options {{ flex-direction: column; }}
            .finding-header {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Keycloak Security Analysis Report</h1>
            <div class="timestamp">Generated: {timestamp}</div>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="value">{summary.realms_analyzed}</div>
                    <div class="label">Realms</div>
                </div>
                <div class="summary-item">
                    <div class="value">{summary.clients_analyzed}</div>
                    <div class="label">Clients</div>
                </div>
                <div class="summary-item">
                    <div class="value">{summary.total_findings}</div>
                    <div class="label">Total Findings</div>
                </div>
"""

        # Add severity counts
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = summary.by_severity.get(severity, 0)
            if count > 0:
                color_class = f"severity-{severity.value.lower()}"
                html += f"""                <div class="summary-item">
                    <div class="value {color_class}">{count}</div>
                    <div class="label">{severity.value}</div>
                </div>
"""

        html += """            </div>
        </div>

"""

        # Exit code notice
        if summary.exit_code == 1:
            html += """        <div class="exit-code-warning">
            <strong>⚠️ Action Required:</strong> Critical or High severity findings detected.
            Address these issues before deploying to production.
        </div>
"""
        else:
            html += """        <div class="exit-code-success">
            <strong>✓ No Critical/High Findings:</strong> Configuration follows security best practices.
        </div>
"""

        # Filters
        html += """        <div class="filters">
            <h3>Filters</h3>
            <div class="filter-options">
                <div style="margin-bottom: 15px;">
                    <label style="font-weight: 600; margin-bottom: 10px; display: block;">Group by Realm</label>
                    <label><input type="checkbox" id="group-by-realm"> Enable realm grouping</label>
                </div>
                <div>
                    <label style="font-weight: 600; margin-bottom: 10px; display: block;">Filter by Severity</label>
                    <div class="filter-options">
                        <label><input type="checkbox" class="severity-filter" value="Critical" checked> Critical</label>
                        <label><input type="checkbox" class="severity-filter" value="High" checked> High</label>
                        <label><input type="checkbox" class="severity-filter" value="Medium" checked> Medium</label>
                        <label><input type="checkbox" class="severity-filter" value="Low" checked> Low</label>
                        <label><input type="checkbox" class="severity-filter" value="Info" checked> Info</label>
                    </div>
                </div>
            </div>
        </div>

        <div class="findings" id="findings-container">
"""

        # Group findings by realm for easier JavaScript processing
        from collections import defaultdict
        findings_by_realm = defaultdict(list)
        for finding in findings:
            findings_by_realm[finding.realm_name].append(finding)

        # Add findings (initially ungrouped)
        for finding in findings:
            html += self._finding_to_html(finding)

        html += """        </div>

        <div class="footer">
            <p>Generated by Keycloak Configuration Security Analyzer v0.1.0</p>
            <p>Based on RFC 9700, OAuth 2.1, and OpenID Connect Security Best Practices</p>
        </div>
    </div>

    <script>
        // Store original HTML
        const findingsContainer = document.getElementById('findings-container');
        const originalFindings = Array.from(findingsContainer.querySelectorAll('.finding')).map(f => f.cloneNode(true));

        // Filter findings by severity
        const filterCheckboxes = document.querySelectorAll('.severity-filter');
        const groupByRealmCheckbox = document.getElementById('group-by-realm');

        filterCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', filterFindings);
        });

        groupByRealmCheckbox.addEventListener('change', toggleGrouping);

        function toggleGrouping() {
            if (groupByRealmCheckbox.checked) {
                groupByRealm();
            } else {
                ungroupFindings();
            }
            filterFindings();
        }

        function groupByRealm() {
            // Group findings by realm
            const findingsByRealm = {};
            originalFindings.forEach(finding => {
                const realm = finding.querySelector('.finding-meta span:nth-child(3)').textContent.replace('Realm: ', '').trim();
                if (!findingsByRealm[realm]) {
                    findingsByRealm[realm] = [];
                }
                findingsByRealm[realm].push(finding.cloneNode(true));
            });

            // Clear container and rebuild with groups
            findingsContainer.innerHTML = '';

            Object.keys(findingsByRealm).sort().forEach(realm => {
                const realmGroup = document.createElement('div');
                realmGroup.className = 'realm-group';

                const realmHeader = document.createElement('div');
                realmHeader.className = 'realm-header';
                realmHeader.innerHTML = `
                    <span>🏰 Realm: ${realm} (${findingsByRealm[realm].length} findings)</span>
                    <span class="realm-toggle">▼</span>
                `;

                const realmFindings = document.createElement('div');
                realmFindings.className = 'realm-findings';

                findingsByRealm[realm].forEach(finding => {
                    realmFindings.appendChild(finding);
                });

                // Toggle collapse
                realmHeader.addEventListener('click', () => {
                    realmFindings.classList.toggle('collapsed');
                    realmHeader.querySelector('.realm-toggle').classList.toggle('collapsed');
                });

                realmGroup.appendChild(realmHeader);
                realmGroup.appendChild(realmFindings);
                findingsContainer.appendChild(realmGroup);
            });
        }

        function ungroupFindings() {
            findingsContainer.innerHTML = '';
            originalFindings.forEach(finding => {
                findingsContainer.appendChild(finding.cloneNode(true));
            });
        }

        function filterFindings() {
            const selectedSeverities = Array.from(filterCheckboxes)
                .filter(cb => cb.checked)
                .map(cb => cb.value);

            document.querySelectorAll('.finding').forEach(finding => {
                const severity = finding.dataset.severity;
                if (selectedSeverities.includes(severity)) {
                    finding.classList.remove('hidden');
                } else {
                    finding.classList.add('hidden');
                }
            });

            // Update counts in realm headers if grouped
            if (groupByRealmCheckbox.checked) {
                document.querySelectorAll('.realm-group').forEach(group => {
                    const visibleCount = group.querySelectorAll('.finding:not(.hidden)').length;
                    const totalCount = group.querySelectorAll('.finding').length;
                    const realm = group.querySelector('.realm-header span:first-child').textContent.split('(')[0].trim();
                    group.querySelector('.realm-header span:first-child').textContent =
                        `${realm} (${visibleCount} of ${totalCount} findings)`;

                    // Hide realm group if no visible findings
                    if (visibleCount === 0) {
                        group.style.display = 'none';
                    } else {
                        group.style.display = 'block';
                    }
                });
            }

            // Update count
            const visibleCount = document.querySelectorAll('.finding:not(.hidden)').length;
            console.log(`Showing ${visibleCount} of ${document.querySelectorAll('.finding').length} findings`);
        }
    </script>
</body>
</html>
"""

        return html

    def save(self, content: str, output_path: str) -> None:
        """
        Save HTML to file.

        Args:
            content: HTML content to save.
            output_path: Path where HTML should be saved.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def _finding_to_html(self, finding: Finding) -> str:
        """Convert a finding to HTML."""
        color = self.severity_html_color(finding.severity)
        severity_lower = finding.severity.value.lower()

        html = f"""            <div class="finding" data-severity="{escape(finding.severity.value)}" data-realm="{escape(finding.realm_name)}" style="border-left-color: {color};">
                <div class="finding-header">
                    <div class="finding-title">{escape(finding.title)}</div>
                    <span class="finding-badge severity-{severity_lower}" style="background-color: {color};">
                        {escape(finding.severity.value)}
                    </span>
                </div>

                <div class="finding-meta">
                    <span><strong>Check ID:</strong> {escape(finding.check_id)}</span>
"""

        if finding.client_id:
            html += f"""                    <span><strong>Client:</strong> {escape(finding.client_id)}</span>
"""

        html += f"""                    <span><strong>Realm:</strong> {escape(finding.realm_name)}</span>
                    <span><strong>Category:</strong> {escape(finding.category.value)}</span>
                </div>

                <div class="finding-section">
                    <h4>Description</h4>
                    <div class="finding-description">{escape(finding.description)}</div>
                </div>

                <div class="finding-section">
                    <h4>🔧 Remediation</h4>
                    <div class="finding-remediation">{escape(finding.remediation)}</div>
                </div>
"""

        if finding.references:
            html += """                <div class="finding-section">
                    <div class="finding-references">
                        <strong>References:</strong>
"""
            for ref in finding.references:
                html += f"""                        <span>{escape(ref)}</span>
"""
            html += """                    </div>
                </div>
"""

        html += """            </div>
"""

        return html
