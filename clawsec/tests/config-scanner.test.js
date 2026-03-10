import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { ConfigScanner } from "../src/checkers/config-scanner.js";

const FIXTURES = resolve(import.meta.dirname, "fixtures");

describe("ConfigScanner", () => {
  const scanner = new ConfigScanner();

  it("should detect disabled auth", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "insecure-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const authFinding = findings.find((f) => f.checkId === "AUTH-001");
    assert.ok(authFinding, "Should find AUTH-001");
    assert.equal(authFinding.severity, "critical");
  });

  it("should detect server bound to 0.0.0.0", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "insecure-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
        defaultPort: 18789,
      },
    };
    const findings = scanner.run(config);
    const portFinding = findings.find((f) => f.checkId === "CFG-001");
    assert.ok(portFinding, "Should find CFG-001");
    assert.equal(portFinding.severity, "critical");
  });

  it("should detect wildcard CORS", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "insecure-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const corsFinding = findings.find((f) => f.checkId === "CFG-002");
    assert.ok(corsFinding, "Should find CFG-002");
    assert.equal(corsFinding.severity, "high");
  });

  it("should detect plaintext credentials", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "insecure-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const credFinding = findings.find((f) => f.checkId === "CFG-003");
    assert.ok(credFinding, "Should find CFG-003");
  });

  it("should detect weak token", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "weak-token-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const tokenFinding = findings.find((f) => f.checkId === "AUTH-002");
    assert.ok(tokenFinding, "Should find AUTH-002");
    assert.equal(tokenFinding.severity, "high");
  });

  it("should pass with secure config", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "secure-config.yaml"),
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const criticals = findings.filter((f) => f.severity === "critical");
    assert.equal(criticals.length, 0, "No critical findings for secure config");
  });

  it("should handle missing config gracefully", () => {
    const config = {
      openclaw: {
        configPath: "/nonexistent/config.yaml",
        gatewayConfigPath: "/nonexistent/gateway.yaml",
      },
    };
    const findings = scanner.run(config);
    const infoFinding = findings.find((f) => f.checkId === "CFG-000");
    assert.ok(infoFinding, "Should return info about missing config");
  });

  it("should detect insecure gateway config", () => {
    const config = {
      openclaw: {
        configPath: resolve(FIXTURES, "secure-config.yaml"),
        gatewayConfigPath: resolve(FIXTURES, "gateway-insecure.yaml"),
      },
    };
    const findings = scanner.run(config);
    const gwFinding = findings.find((f) => f.checkId === "GW-001");
    assert.ok(gwFinding, "Should find GW-001");
    assert.equal(gwFinding.severity, "high");
  });
});
