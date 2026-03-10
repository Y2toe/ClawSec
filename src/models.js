/**
 * Core data models for ClawSec findings.
 */

export const Severity = Object.freeze({
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
});

const SEVERITY_ORDER = [
  Severity.CRITICAL,
  Severity.HIGH,
  Severity.MEDIUM,
  Severity.LOW,
  Severity.INFO,
];

export class Finding {
  constructor({ checkId, severity, title, detail, remediation }) {
    this.checkId = checkId;
    this.severity = severity;
    this.title = title;
    this.detail = detail;
    this.remediation = remediation;
  }

  toJSON() {
    return {
      check_id: this.checkId,
      severity: this.severity,
      title: this.title,
      detail: this.detail,
      remediation: this.remediation,
    };
  }
}

export function severityFromCvss(cvss) {
  if (cvss >= 9.0) return Severity.CRITICAL;
  if (cvss >= 7.0) return Severity.HIGH;
  if (cvss >= 4.0) return Severity.MEDIUM;
  if (cvss >= 0.1) return Severity.LOW;
  return Severity.INFO;
}

export function compareSeverity(a, b) {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}
