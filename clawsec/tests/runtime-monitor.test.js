import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { RuntimeMonitor } from "../src/checkers/runtime-monitor.js";

const FIXTURES = resolve(import.meta.dirname, "fixtures");

describe("RuntimeMonitor", () => {
  const monitor = new RuntimeMonitor();

  it("should run port exposure check without crashing", () => {
    const config = {
      openclaw: { defaultPort: 18789 },
      checks: { portExposure: true, websocketSecurity: false, hookLoading: false, sandboxIsolation: false },
    };
    const findings = monitor.run(config);
    assert.ok(Array.isArray(findings), "Should return array of findings");
  });

  it("should detect hook path traversal", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "hook-unsafe-config.yaml"),
        gatewayConfigPath: "/nonexistent",
        defaultPort: 18789,
      },
      checks: { portExposure: false, websocketSecurity: false, hookLoading: true, sandboxIsolation: false },
    };
    const findings = monitor.run(config);
    const hookFinding = findings.find((f) => f.checkId === "HOOK-001");
    assert.ok(hookFinding, "Should detect path traversal in hooks");
  });

  it("should run sandbox check without crashing", () => {
    const config = {
      openclaw: { defaultPort: 18789 },
      checks: { portExposure: false, websocketSecurity: false, hookLoading: false, sandboxIsolation: true },
    };
    const findings = monitor.run(config);
    assert.ok(Array.isArray(findings), "Should return array");
  });

  it("should respect disabled checks", () => {
    const config = {
      openclaw: { defaultPort: 18789 },
      checks: { portExposure: false, websocketSecurity: false, hookLoading: false, sandboxIsolation: false },
    };
    const findings = monitor.run(config);
    assert.equal(findings.length, 0, "No findings when all checks disabled");
  });
});
