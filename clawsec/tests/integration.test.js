import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { runCheck } from "../src/index.js";

const FIXTURES = resolve(import.meta.dirname, "fixtures");

describe("Integration: runCheck", () => {
  it("should produce a complete report for insecure config", () => {
    const report = runCheck({
      openclaw: {
        configPath: resolve(FIXTURES, "insecure-config.yaml"),
        skillsDir: resolve(FIXTURES, "skills"),
        gatewayConfigPath: resolve(FIXTURES, "gateway-insecure.yaml"),
        version: "2026.1.0",
      },
      versionCheck: { online: false },
    });

    assert.equal(report.tool, "ClawSec");
    assert.ok(report.summary.total > 0, "Should have findings");
    assert.ok(report.summary.critical > 0, "Should have critical findings");
    assert.equal(report.pass, false);
    assert.ok(report.timestamp, "Should have timestamp");

    for (const f of report.findings) {
      assert.ok(f.check_id, "Each finding must have check_id");
      assert.ok(f.severity, "Each finding must have severity");
      assert.ok(f.title, "Each finding must have title");
      assert.ok(f.remediation, "Each finding must have remediation");
    }
  });

  it("should produce a passing report for secure config", () => {
    const report = runCheck({
      openclaw: {
        configPath: resolve(FIXTURES, "secure-config.yaml"),
        skillsDir: "/nonexistent/skills",
        gatewayConfigPath: "/nonexistent/gateway.yaml",
        version: "2026.3.0",
      },
      versionCheck: { online: false },
      checks: {
        portExposure: false,
        sandboxIsolation: false,
      },
    });

    const critFindings = report.findings.filter((f) => f.severity === "critical");
    assert.equal(critFindings.length, 0, "No critical findings for secure setup");
    // CFG-003 (plaintext token in config file) is expected as HIGH — token is stored in file
    const highFindings = report.findings.filter(
      (f) => f.severity === "high" && f.check_id !== "CFG-003"
    );
    assert.equal(highFindings.length, 0, "No unexpected high findings for secure setup");
  });

  it("should handle completely missing environment gracefully", () => {
    const report = runCheck({
      openclaw: {
        configPath: "/nonexistent/config.yaml",
        skillsDir: "/nonexistent/skills",
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
      versionCheck: { online: false },
      checks: {
        portExposure: false,
        sandboxIsolation: false,
      },
    });

    assert.equal(report.tool, "ClawSec");
    assert.ok(Array.isArray(report.findings));
    const infoFindings = report.findings.filter((f) => f.severity === "info");
    assert.ok(infoFindings.length >= 1, "Should have at least one info finding about missing files");
  });

  it("should respect check toggles", () => {
    const report = runCheck({
      openclaw: {
        configPath: "/nonexistent",
        skillsDir: "/nonexistent",
        gatewayConfigPath: "/nonexistent",
      },
      versionCheck: { online: false },
      checks: {
        portExposure: false,
        authConfig: false,
        version: false,
        skillAudit: false,
        websocketSecurity: false,
        hookLoading: false,
        sandboxIsolation: false,
        credentialStorage: false,
      },
    });

    assert.equal(report.summary.total, 0, "All checks disabled = no findings");
  });
});
