/**
 * Reporter — aggregates findings from all checkers into a structured report.
 */

import { Severity, compareSeverity } from "./models.js";

export class Reporter {
  constructor(version = "1.0.0") {
    this.toolVersion = version;
  }

  generate(findings) {
    const sorted = [...findings].sort((a, b) =>
      compareSeverity(a.severity, b.severity)
    );

    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of sorted) {
      if (f.severity in counts) {
        counts[f.severity]++;
      }
    }

    return {
      tool: "ClawSec",
      version: this.toolVersion,
      timestamp: new Date().toISOString(),
      summary: {
        total: sorted.length,
        ...counts,
      },
      pass: counts.critical === 0 && counts.high === 0,
      findings: sorted.map((f) => f.toJSON()),
    };
  }

  formatText(report) {
    const lines = [];
    lines.push("=".repeat(60));
    lines.push(`  ClawSec Security Report v${report.version}`);
    lines.push(`  Generated: ${report.timestamp}`);
    lines.push("=".repeat(60));
    lines.push("");
    lines.push(
      `  Status: ${report.pass ? "PASS" : "FAIL"}`
    );
    lines.push(
      `  Findings: ${report.summary.total} total | ` +
        `${report.summary.critical} critical | ${report.summary.high} high | ` +
        `${report.summary.medium} medium | ${report.summary.low} low | ${report.summary.info} info`
    );
    lines.push("");

    if (report.findings.length === 0) {
      lines.push("  No security issues detected.");
    }

    for (const f of report.findings) {
      const tag = `[${f.severity.toUpperCase()}]`.padEnd(11);
      lines.push(`  ${tag} ${f.check_id}: ${f.title}`);
      lines.push(`             ${f.detail}`);
      lines.push(`             -> ${f.remediation}`);
      lines.push("");
    }

    lines.push("=".repeat(60));
    return lines.join("\n");
  }
}
