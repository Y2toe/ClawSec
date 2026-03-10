/**
 * Config Scanner — checks OpenClaw config files for security misconfigurations.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { Finding, Severity } from "../models.js";
import { loadDataFile } from "../config.js";

export class ConfigScanner {
  constructor() {
    const sensitiveData = loadDataFile("sensitive-keys.json");
    this.keyPatterns = sensitiveData?.keyPatterns || [];
    this.credentialRegex = sensitiveData?.configCredentialRegex
      ? new RegExp(sensitiveData.configCredentialRegex, "gi")
      : null;
  }

  run(config) {
    const findings = [];
    const openclawConfig = config.openclaw || {};
    const configPath = openclawConfig.configPath || "";

    if (existsSync(configPath)) {
      const parsed = this._loadConfig(configPath);
      if (parsed) {
        findings.push(...this._checkAuth(parsed));
        findings.push(...this._checkPortBinding(parsed, openclawConfig));
        findings.push(...this._checkCors(parsed));
      }
      findings.push(...this._checkPlaintextCredentials(configPath));
    } else {
      findings.push(
        new Finding({
          checkId: "CFG-000",
          severity: Severity.INFO,
          title: "OpenClaw config file not found",
          detail: `Expected config at ${configPath}. Skipping config-based checks.`,
          remediation: "Verify the OpenClaw installation path in ClawSec config.",
        })
      );
    }

    const configDir = existsSync(configPath) ? dirname(configPath) : null;
    for (const envFile of this._findEnvFiles(configDir)) {
      findings.push(...this._checkEnvFile(envFile));
    }

    const gatewayPath = openclawConfig.gatewayConfigPath || "";
    if (existsSync(gatewayPath)) {
      findings.push(...this._checkGatewayConfig(gatewayPath));
    }

    return findings;
  }

  _loadConfig(filePath) {
    try {
      const raw = readFileSync(filePath, "utf-8");
      if (filePath.endsWith(".json")) {
        return JSON.parse(raw);
      }
      return this._parseBasicYaml(raw);
    } catch (err) {
      console.warn(`[clawsec] Failed to parse config ${filePath}: ${err.message}`);
      return null;
    }
  }

  _parseBasicYaml(content) {
    const result = {};
    const lines = content.split("\n");
    const stack = [{ indent: -1, obj: result }];

    for (const rawLine of lines) {
      const line = rawLine.replace(/\r$/, "");
      if (!line.trim() || line.trim().startsWith("#")) continue;

      const indent = line.search(/\S/);
      const colonIdx = line.indexOf(":");
      if (colonIdx === -1) continue;

      const key = line.slice(0, colonIdx).trim();
      let value = line.slice(colonIdx + 1).trim();

      while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
        stack.pop();
      }
      const parent = stack[stack.length - 1].obj;

      if (value === "" || value === null) {
        parent[key] = {};
        stack.push({ indent, obj: parent[key] });
      } else {
        value = value.replace(/^['"]|['"]$/g, "");
        if (value === "true") value = true;
        else if (value === "false") value = false;
        else if (/^\d+$/.test(value)) value = parseInt(value, 10);
        parent[key] = value;
      }
    }
    return result;
  }

  _checkAuth(parsed) {
    const findings = [];
    const auth = typeof parsed.auth === "object" ? parsed.auth : {};

    if (!auth.enabled) {
      findings.push(
        new Finding({
          checkId: "AUTH-001",
          severity: Severity.CRITICAL,
          title: "Authentication is disabled",
          detail:
            "No token-based authentication is configured. " +
            "Any network-reachable client can control this agent.",
          remediation:
            "Enable token auth in config: auth.enabled=true, and set a strong token value.",
        })
      );
    }

    const token = typeof auth.token === "string" ? auth.token : "";
    if (auth.enabled && !token) {
      findings.push(
        new Finding({
          checkId: "AUTH-003",
          severity: Severity.CRITICAL,
          title: "Authentication enabled but token is empty",
          detail:
            "Auth is enabled but the token field is empty, effectively providing no protection.",
          remediation: "Set a strong token of at least 32 random characters.",
        })
      );
    } else if (token && token.length < 32) {
      findings.push(
        new Finding({
          checkId: "AUTH-002",
          severity: Severity.HIGH,
          title: "Authentication token is weak",
          detail:
            `Token length is ${token.length} characters. ` +
            "Short tokens are vulnerable to brute-force attacks.",
          remediation: "Use a token of at least 32 random characters.",
        })
      );
    }

    return findings;
  }

  _checkPortBinding(parsed, openclawConfig) {
    const findings = [];
    const server = typeof parsed.server === "object" ? parsed.server : {};
    const host = server.host || server.bind || "";
    const port = server.port || openclawConfig.defaultPort || 18789;

    if (["0.0.0.0", "::", ""].includes(host) && host !== undefined) {
      if (host === "0.0.0.0" || host === "::") {
        findings.push(
          new Finding({
            checkId: "CFG-001",
            severity: Severity.CRITICAL,
            title: "Server configured to bind to all interfaces",
            detail:
              `Config sets host to '${host}' on port ${port}. ` +
              "This exposes the instance to all network interfaces.",
            remediation:
              "Set server.host to '127.0.0.1' or use an HTTPS reverse proxy.",
          })
        );
      }
    }

    return findings;
  }

  _checkCors(parsed) {
    const findings = [];
    const cors =
      (typeof parsed.cors === "object" && parsed.cors) ||
      (typeof parsed.gateway === "object" && parsed.gateway.cors) ||
      {};

    let origins = cors.allowed_origins || cors.origins || [];
    if (typeof origins === "string") origins = [origins];

    if (Array.isArray(origins) && origins.includes("*")) {
      findings.push(
        new Finding({
          checkId: "CFG-002",
          severity: Severity.HIGH,
          title: "CORS allows all origins",
          detail:
            "Wildcard '*' in allowed_origins permits any website to interact " +
            "with this OpenClaw instance, enabling cross-site attacks.",
          remediation: "Restrict allowed_origins to specific trusted domains.",
        })
      );
    }

    return findings;
  }

  _checkPlaintextCredentials(configPath) {
    const findings = [];
    if (!this.credentialRegex) return findings;

    try {
      const content = readFileSync(configPath, "utf-8");
      this.credentialRegex.lastIndex = 0;
      const matches = content.match(this.credentialRegex);
      if (matches && matches.length > 0) {
        findings.push(
          new Finding({
            checkId: "CFG-003",
            severity: Severity.HIGH,
            title: "Potential plaintext credential in config",
            detail:
              `A sensitive key pattern was found in the config file. ` +
              "Credentials stored in plaintext can be easily exfiltrated.",
            remediation:
              "Use environment variables or a secrets manager for credentials.",
          })
        );
      }
    } catch {
      // read failure is non-critical
    }
    return findings;
  }

  _findEnvFiles(searchDir) {
    if (!searchDir || !existsSync(searchDir)) return [];
    const names = [".env", ".env.local", ".env.production"];
    return names
      .map((n) => join(searchDir, n))
      .filter((p) => existsSync(p));
  }

  _checkEnvFile(envPath) {
    const findings = [];
    try {
      const content = readFileSync(envPath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eqIdx = trimmed.indexOf("=");
        if (eqIdx === -1) continue;
        const key = trimmed.slice(0, eqIdx).trim().toLowerCase();
        if (this.keyPatterns.some((p) => key.includes(p))) {
          const fileName = envPath.split("/").pop() || envPath.split("\\").pop();
          findings.push(
            new Finding({
              checkId: "CFG-004",
              severity: Severity.MEDIUM,
              title: `Sensitive value in ${fileName}`,
              detail:
                `File ${fileName} contains a key matching sensitive patterns. ` +
                "Ensure this file is not committed to version control.",
              remediation:
                "Add the file to .gitignore and use a secrets manager in production.",
            })
          );
          return findings;
        }
      }
    } catch {
      // non-critical
    }
    return findings;
  }

  _checkGatewayConfig(gatewayPath) {
    const findings = [];
    const parsed = this._loadConfig(gatewayPath);
    if (!parsed) return findings;

    const ws = parsed.websocket || parsed.ws || {};
    if (typeof ws === "object") {
      if (!ws.tls && !ws.ssl) {
        findings.push(
          new Finding({
            checkId: "GW-001",
            severity: Severity.HIGH,
            title: "Gateway WebSocket TLS not enabled",
            detail:
              "The WebSocket gateway is configured without TLS. " +
              "Communications can be intercepted and auth tokens stolen (ref: CVE-2026-25253).",
            remediation:
              "Enable TLS for the WebSocket gateway or place it behind an HTTPS proxy.",
          })
        );
      }

      const origins = ws.allowed_origins || ws.origins || [];
      if (!origins.length) {
        findings.push(
          new Finding({
            checkId: "GW-002",
            severity: Severity.MEDIUM,
            title: "No WebSocket origin restrictions",
            detail:
              "The WebSocket gateway has no origin restrictions, " +
              "allowing connections from any web page.",
            remediation:
              "Configure allowed_origins to restrict WebSocket connections to trusted domains.",
          })
        );
      }
    }

    return findings;
  }
}
