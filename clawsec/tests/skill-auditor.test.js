import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { SkillAuditor } from "../src/checkers/skill-auditor.js";

const FIXTURES = resolve(import.meta.dirname, "fixtures");

describe("SkillAuditor", () => {
  const auditor = new SkillAuditor();

  it("should pass for safe skill", () => {
    const config = {
      openclaw: { skillsDir: resolve(FIXTURES, "skills") },
    };
    const findings = auditor.run(config);
    const safeFindings = findings.filter(
      (f) => f.title.includes("safe-skill") && f.severity === "critical"
    );
    assert.equal(safeFindings.length, 0, "No critical findings for safe skill");
  });

  it("should detect missing manifest", () => {
    const config = {
      openclaw: { skillsDir: resolve(FIXTURES, "skills") },
    };
    const findings = auditor.run(config);
    const noManifest = findings.find(
      (f) => f.checkId === "SKILL-001" && f.title.includes("no-manifest-skill")
    );
    assert.ok(noManifest, "Should flag skill without manifest");
  });

  it("should detect untrusted source", () => {
    const config = {
      openclaw: { skillsDir: resolve(FIXTURES, "skills") },
    };
    const findings = auditor.run(config);
    const untrusted = findings.find(
      (f) => f.checkId === "SKILL-003" && f.title.includes("suspicious-skill")
    );
    assert.ok(untrusted, "Should flag untrusted source");
  });

  it("should detect high-risk permissions", () => {
    const config = {
      openclaw: { skillsDir: resolve(FIXTURES, "skills") },
    };
    const findings = auditor.run(config);
    const risky = findings.find(
      (f) => f.checkId === "SKILL-004" && f.title.includes("suspicious-skill")
    );
    assert.ok(risky, "Should flag high-risk permissions");
  });

  it("should detect suspicious code patterns", () => {
    const config = {
      openclaw: { skillsDir: resolve(FIXTURES, "skills") },
    };
    const findings = auditor.run(config);
    const suspicious = findings.find(
      (f) =>
        (f.checkId === "SKILL-005" || f.checkId === "SKILL-006") &&
        f.title.includes("suspicious-skill")
    );
    assert.ok(suspicious, "Should flag suspicious patterns in code");
  });

  it("should handle missing skills directory", () => {
    const config = {
      openclaw: { skillsDir: "/nonexistent/skills" },
    };
    const findings = auditor.run(config);
    const info = findings.find((f) => f.checkId === "SKILL-000");
    assert.ok(info, "Should return info about missing skills dir");
  });
});
