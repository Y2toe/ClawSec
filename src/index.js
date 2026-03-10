/**
 * ClawSec — main entry point and OpenClaw skill adapter.
 * Synchronous execution: all checks run sequentially, returning immediate results.
 */

import { loadConfig } from "./config.js";
import { ConfigScanner } from "./checkers/config-scanner.js";
import { VersionChecker } from "./checkers/version-checker.js";
import { SkillAuditor } from "./checkers/skill-auditor.js";
import { RuntimeMonitor } from "./checkers/runtime-monitor.js";
import { Reporter } from "./reporter.js";
import { Finding, Severity } from "./models.js";

const VERSION = "1.0.0";

export function runCheck(overrides = {}) {
  const config = loadConfig(overrides);
  const findings = [];
  const checks = config.checks || {};

  const checkers = [];

  if (checks.authConfig !== false || checks.credentialStorage !== false) {
    checkers.push({ name: "ConfigScanner", instance: new ConfigScanner() });
  }
  if (checks.version !== false) {
    checkers.push({ name: "VersionChecker", instance: new VersionChecker() });
  }
  if (checks.skillAudit !== false) {
    checkers.push({ name: "SkillAuditor", instance: new SkillAuditor() });
  }
  if (
    checks.portExposure !== false ||
    checks.websocketSecurity !== false ||
    checks.hookLoading !== false ||
    checks.sandboxIsolation !== false
  ) {
    checkers.push({ name: "RuntimeMonitor", instance: new RuntimeMonitor() });
  }

  for (const { name, instance } of checkers) {
    try {
      const results = instance.run(config);
      findings.push(...results);
    } catch (err) {
      findings.push(
        new Finding({
          checkId: "INTERNAL-ERR",
          severity: Severity.INFO,
          title: `Checker ${name} failed`,
          detail: err.message || String(err),
          remediation: "Review ClawSec logs for details.",
        })
      );
    }
  }

  const reporter = new Reporter(VERSION);
  return reporter.generate(findings);
}

// OpenClaw skill interface: default export for skill loader
export default { runCheck };
