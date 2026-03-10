import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Reporter } from "../src/reporter.js";
import { Finding, Severity } from "../src/models.js";

describe("Reporter", () => {
  const reporter = new Reporter("1.0.0");

  it("should generate correct report structure", () => {
    const findings = [
      new Finding({
        checkId: "TEST-001",
        severity: Severity.CRITICAL,
        title: "Test critical",
        detail: "Detail",
        remediation: "Fix it",
      }),
      new Finding({
        checkId: "TEST-002",
        severity: Severity.LOW,
        title: "Test low",
        detail: "Detail",
        remediation: "Consider fixing",
      }),
    ];

    const report = reporter.generate(findings);
    assert.equal(report.tool, "ClawSec");
    assert.equal(report.version, "1.0.0");
    assert.equal(report.summary.total, 2);
    assert.equal(report.summary.critical, 1);
    assert.equal(report.summary.low, 1);
    assert.equal(report.pass, false);
  });

  it("should mark as pass when no critical/high findings", () => {
    const findings = [
      new Finding({
        checkId: "TEST-003",
        severity: Severity.MEDIUM,
        title: "Test med",
        detail: "Detail",
        remediation: "Improve",
      }),
    ];

    const report = reporter.generate(findings);
    assert.equal(report.pass, true);
    assert.equal(report.summary.critical, 0);
    assert.equal(report.summary.high, 0);
  });

  it("should sort findings by severity", () => {
    const findings = [
      new Finding({ checkId: "A", severity: Severity.LOW, title: "Low", detail: "", remediation: "" }),
      new Finding({ checkId: "B", severity: Severity.CRITICAL, title: "Crit", detail: "", remediation: "" }),
      new Finding({ checkId: "C", severity: Severity.MEDIUM, title: "Med", detail: "", remediation: "" }),
    ];

    const report = reporter.generate(findings);
    assert.equal(report.findings[0].check_id, "B");
    assert.equal(report.findings[1].check_id, "C");
    assert.equal(report.findings[2].check_id, "A");
  });

  it("should generate text report", () => {
    const report = reporter.generate([]);
    const text = reporter.formatText(report);
    assert.ok(text.includes("ClawSec Security Report"));
    assert.ok(text.includes("PASS"));
    assert.ok(text.includes("No security issues detected"));
  });

  it("should generate report with empty findings", () => {
    const report = reporter.generate([]);
    assert.equal(report.summary.total, 0);
    assert.equal(report.pass, true);
  });
});
