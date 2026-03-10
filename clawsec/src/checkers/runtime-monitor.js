/**
 * Runtime Monitor — inspects live process environment for security risks.
 * Checks: port exposure, WebSocket security, hook paths, sandbox isolation.
 */

import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join, isAbsolute, normalize } from "node:path";
import { platform } from "node:os";
import { Finding, Severity } from "../models.js";

export class RuntimeMonitor {
  run(config) {
    const findings = [];
    const checks = config.checks || {};

    if (checks.portExposure !== false) {
      findings.push(...this._checkPortExposure(config));
    }
    if (checks.websocketSecurity !== false) {
      findings.push(...this._checkWebSocketSecurity(config));
    }
    if (checks.hookLoading !== false) {
      findings.push(...this._checkHookLoadingPaths(config));
    }
    if (checks.sandboxIsolation !== false) {
      findings.push(...this._checkSandboxIsolation());
    }

    return findings;
  }

  _checkPortExposure(config) {
    const findings = [];
    const targetPort = config.openclaw?.defaultPort || 18789;

    try {
      const os = platform();
      let output = "";

      if (os === "darwin" || os === "linux") {
        try {
          output = execSync(
            `lsof -iTCP:${targetPort} -sTCP:LISTEN -n -P 2>/dev/null || netstat -tlnp 2>/dev/null | grep :${targetPort}`,
            { encoding: "utf-8", timeout: 5000 }
          );
        } catch {
          try {
            output = execSync(`ss -tlnp 2>/dev/null | grep :${targetPort}`, {
              encoding: "utf-8",
              timeout: 5000,
            });
          } catch {
            return findings;
          }
        }
      } else if (os === "win32") {
        try {
          output = execSync(`netstat -ano | findstr :${targetPort} | findstr LISTEN`, {
            encoding: "utf-8",
            timeout: 5000,
          });
        } catch {
          return findings;
        }
      }

      if (output && (output.includes("0.0.0.0") || output.includes("*:") || output.includes(":::"))) {
        findings.push(
          new Finding({
            checkId: "PORT-001",
            severity: Severity.CRITICAL,
            title: "OpenClaw gateway bound to all interfaces",
            detail:
              `Port ${targetPort} is listening on all interfaces (0.0.0.0 or ::). ` +
              "This exposes the instance to the public network.",
            remediation:
              "Bind to 127.0.0.1 or use an HTTPS reverse proxy with authentication.",
          })
        );
      } else if (output && output.trim()) {
        findings.push(
          new Finding({
            checkId: "PORT-002",
            severity: Severity.INFO,
            title: `Port ${targetPort} is in use`,
            detail: `OpenClaw default port ${targetPort} has a listening process. Binding appears local.`,
            remediation: "No action needed if bound to localhost.",
          })
        );
      }
    } catch {
      // graceful degradation
    }

    return findings;
  }

  _checkWebSocketSecurity(config) {
    const findings = [];
    const gatewayPath = config.openclaw?.gatewayConfigPath || "";

    if (!existsSync(gatewayPath)) return findings;

    try {
      const raw = readFileSync(gatewayPath, "utf-8");
      const lower = raw.toLowerCase();

      if (!lower.includes("wss://") && !lower.includes("tls") && !lower.includes("ssl")) {
        if (lower.includes("ws://") || lower.includes("websocket")) {
          findings.push(
            new Finding({
              checkId: "WS-001",
              severity: Severity.HIGH,
              title: "WebSocket using unencrypted connection (ws://)",
              detail:
                "Gateway is configured with ws:// instead of wss://. " +
                "Auth tokens can be intercepted in transit (ref: CVE-2026-25253).",
              remediation: "Switch to wss:// or terminate TLS at a reverse proxy.",
            })
          );
        }
      }

      if (lower.includes("origin") && lower.includes("*")) {
        findings.push(
          new Finding({
            checkId: "WS-002",
            severity: Severity.HIGH,
            title: "WebSocket allows all origins",
            detail:
              "Wildcard origin in WebSocket config allows any web page to connect, " +
              "enabling cross-site WebSocket hijacking.",
            remediation: "Restrict WebSocket origins to specific trusted domains.",
          })
        );
      }
    } catch {
      // non-critical
    }

    return findings;
  }

  _checkHookLoadingPaths(config) {
    const findings = [];
    const configPath = config.openclaw?.configPath || "";

    if (!existsSync(configPath)) return findings;

    try {
      const content = readFileSync(configPath, "utf-8");
      const hookPatterns = [
        /hooks?\s*[:=]\s*['"]?([^\s'"#]+)/gi,
        /cliPath\s*[:=]\s*['"]?([^\s'"#]+)/gi,
        /customCommand\s*[:=]\s*['"]?([^\s'"#]+)/gi,
      ];

      for (const pattern of hookPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const hookPath = match[1];

          if (hookPath.includes("..") || hookPath.includes("~")) {
            findings.push(
              new Finding({
                checkId: "HOOK-001",
                severity: Severity.HIGH,
                title: "Hook path contains traversal characters",
                detail:
                  `A hook/cliPath value contains '..' or '~', which could be exploited ` +
                  "for path injection (ref: CVE-2026-25593, CVE-2026-28456).",
                remediation:
                  "Use absolute paths without traversal. Validate hook paths in config.",
              })
            );
          }

          if (!isAbsolute(hookPath) && hookPath.startsWith("/") === false) {
            findings.push(
              new Finding({
                checkId: "HOOK-002",
                severity: Severity.MEDIUM,
                title: "Hook uses relative path",
                detail:
                  "A relative hook path may resolve differently depending on the working directory, " +
                  "creating an injection opportunity.",
                remediation: "Use absolute paths for all hooks and cliPath values.",
              })
            );
          }
        }
      }
    } catch {
      // non-critical
    }

    return findings;
  }

  _checkSandboxIsolation() {
    const findings = [];
    const os = platform();

    const isDocker = existsSync("/.dockerenv") || existsSync("/run/.containerenv");

    let cgroupCheck = false;
    if (os === "linux") {
      try {
        const cgroup = readFileSync("/proc/1/cgroup", "utf-8");
        cgroupCheck = cgroup.includes("docker") || cgroup.includes("containerd") || cgroup.includes("kubepods");
      } catch {
        // not in a container
      }
    }

    if (!isDocker && !cgroupCheck) {
      findings.push(
        new Finding({
          checkId: "SANDBOX-001",
          severity: Severity.MEDIUM,
          title: "Not running inside a container",
          detail:
            "OpenClaw does not appear to be running inside Docker or a container. " +
            "Container isolation limits the blast radius of any compromise.",
          remediation:
            "Consider running OpenClaw inside a Docker container with restricted capabilities.",
        })
      );
    }

    if (os === "linux" || os === "darwin") {
      try {
        const whoami = execSync("whoami", { encoding: "utf-8", timeout: 3000 }).trim();
        if (whoami === "root") {
          findings.push(
            new Finding({
              checkId: "SANDBOX-002",
              severity: Severity.HIGH,
              title: "Running as root user",
              detail:
                "OpenClaw is running as root. A compromised agent has full system access.",
              remediation:
                "Run OpenClaw as a non-root user with minimal required permissions.",
            })
          );
        }
      } catch {
        // non-critical
      }
    }

    return findings;
  }
}
