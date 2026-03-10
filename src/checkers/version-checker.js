/**
 * Version Checker — compares OpenClaw version against known vulnerable versions.
 * Vulnerability data is loaded from external JSON, not hardcoded.
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { execSync } from "node:child_process";
import { Finding, Severity, severityFromCvss } from "../models.js";
import { loadDataFile } from "../config.js";

function require_child_process() {
  return { execSync };
}

export class VersionChecker {
  constructor() {
    const vulnData = loadDataFile("vulnerable-versions.json");
    this.vulnerableVersions = vulnData?.versions || {};
    this.minimumSafeVersion = vulnData?._meta?.minimumSafeVersion || "2026.2.25";
  }

  run(config) {
    const findings = [];
    const version = this._detectVersion(config);

    if (!version) {
      findings.push(
        new Finding({
          checkId: "VER-000",
          severity: Severity.INFO,
          title: "Unable to detect OpenClaw version",
          detail:
            "Could not determine the installed OpenClaw version. " +
            "Version-based vulnerability checks were skipped.",
          remediation:
            "Set openclaw.version in ClawSec config or ensure version.txt exists.",
        })
      );
      return findings;
    }

    findings.push(...this._checkKnownVulns(version));
    findings.push(...this._checkMinimumVersion(version));

    if (config.versionCheck?.online) {
      findings.push(...this._checkOnlineFeed(version, config));
    }

    return findings;
  }

  _detectVersion(config) {
    const explicit = config.openclaw?.version;
    if (explicit) return String(explicit);

    const locations = [
      config.openclaw?.configPath
        ? join(config.openclaw.configPath, "..", "version.txt")
        : null,
      join(homedir(), ".openclaw", "version.txt"),
    ].filter(Boolean);

    for (const loc of locations) {
      if (existsSync(loc)) {
        try {
          return readFileSync(loc, "utf-8").trim();
        } catch {
          continue;
        }
      }
    }

    return null;
  }

  _checkKnownVulns(version) {
    const findings = [];
    const vulns = this.vulnerableVersions[version];
    if (!vulns) return findings;

    for (const vuln of vulns) {
      findings.push(
        new Finding({
          checkId: `VER-${vuln.cve.slice(-4)}`,
          severity: severityFromCvss(vuln.cvss),
          title: `Known vulnerability: ${vuln.cve}`,
          detail:
            `OpenClaw version ${version} is affected by ${vuln.cve} ` +
            `(CVSS ${vuln.cvss}): ${vuln.description}.`,
          remediation: `Upgrade to OpenClaw ${this.minimumSafeVersion} or later.`,
        })
      );
    }

    return findings;
  }

  _checkMinimumVersion(version) {
    const findings = [];
    if (compareVersions(version, this.minimumSafeVersion) < 0) {
      findings.push(
        new Finding({
          checkId: "VER-001",
          severity: Severity.HIGH,
          title: "OpenClaw version is below minimum safe version",
          detail:
            `Installed version ${version} is older than the minimum ` +
            `recommended version ${this.minimumSafeVersion}. Multiple security patches may be missing.`,
          remediation: `Upgrade to OpenClaw ${this.minimumSafeVersion} or later immediately.`,
        })
      );
    }
    return findings;
  }

  _checkOnlineFeed(version, config) {
    const findings = [];
    const feedUrl =
      config.versionCheck?.feedUrl ||
      "https://clawsec.github.io/vuln-feed.json";

    try {
      const { execSync } = require_child_process();
      const script = `const https=require('https');const u=new URL('${feedUrl}');https.get(u,{timeout:10000},r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>process.stdout.write(d))}).on('error',()=>{process.exit(1)})`;
      const raw = execSync(`node -e "${script.replace(/"/g, '\\"')}"`, {
        timeout: 15000,
        encoding: "utf-8",
      });
      const feed = JSON.parse(raw);
      const latest = feed.latest_safe_version || this.minimumSafeVersion;
      if (compareVersions(version, latest) < 0) {
        findings.push(
          new Finding({
            checkId: "VER-002",
            severity: Severity.HIGH,
            title: "Newer safe version available",
            detail: `Online feed indicates ${latest} is the latest safe version. Installed: ${version}.`,
            remediation: `Upgrade to OpenClaw ${latest}.`,
          })
        );
      }
    } catch {
      console.warn("[clawsec] Online version check failed or timed out");
    }

    return findings;
  }
}

export function compareVersions(v1, v2) {
  const normalize = (v) =>
    v
      .replace(/-/g, ".")
      .split(".")
      .map((p) => parseInt(p, 10) || 0);

  const p1 = normalize(v1);
  const p2 = normalize(v2);
  const len = Math.max(p1.length, p2.length);

  for (let i = 0; i < len; i++) {
    const a = p1[i] || 0;
    const b = p2[i] || 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}
