import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { VersionChecker, compareVersions } from "../src/checkers/version-checker.js";

describe("VersionChecker", () => {
  const checker = new VersionChecker();

  it("should detect known vulnerable version", () => {
    const config = {
      openclaw: { version: "2026.1.0" },
      versionCheck: { online: false },
      checks: {},
    };
    const findings = checker.run(config);
    const cveFindings = findings.filter((f) => f.checkId.startsWith("VER-"));
    assert.ok(cveFindings.length >= 2, "Should find at least 2 CVEs for 2026.1.0");
  });

  it("should detect version below minimum safe", () => {
    const config = {
      openclaw: { version: "2026.2.0" },
      versionCheck: { online: false },
      checks: {},
    };
    const findings = checker.run(config);
    const verFinding = findings.find((f) => f.checkId === "VER-001");
    assert.ok(verFinding, "Should find VER-001 for old version");
  });

  it("should pass for safe version", () => {
    const config = {
      openclaw: { version: "2026.3.0" },
      versionCheck: { online: false },
      checks: {},
    };
    const findings = checker.run(config);
    const vulnFindings = findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    assert.equal(vulnFindings.length, 0, "No high/critical for safe version");
  });

  it("should handle missing version gracefully", () => {
    const config = {
      openclaw: {},
      versionCheck: { online: false },
      checks: {},
    };
    const findings = checker.run(config);
    const infoFinding = findings.find((f) => f.checkId === "VER-000");
    assert.ok(infoFinding, "Should return info about missing version");
  });
});

describe("compareVersions", () => {
  it("should compare equal versions", () => {
    assert.equal(compareVersions("2026.2.25", "2026.2.25"), 0);
  });

  it("should detect older version", () => {
    assert.equal(compareVersions("2026.1.0", "2026.2.25"), -1);
  });

  it("should detect newer version", () => {
    assert.equal(compareVersions("2026.3.0", "2026.2.25"), 1);
  });

  it("should handle different length versions", () => {
    assert.equal(compareVersions("2026.2", "2026.2.0"), 0);
    assert.equal(compareVersions("2026.2", "2026.2.1"), -1);
  });
});
