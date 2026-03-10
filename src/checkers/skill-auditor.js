/**
 * Skill Auditor — scans installed skills for malicious patterns and untrusted sources.
 * All signatures, patterns, and trusted sources loaded from external data files.
 */

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, basename, relative } from "node:path";
import { Finding, Severity } from "../models.js";
import { loadDataFile } from "../config.js";

export class SkillAuditor {
  constructor() {
    const hashData = loadDataFile("malicious-hashes.json");
    this.maliciousHashes = new Set(hashData?.hashes || []);

    const patternData = loadDataFile("suspicious-patterns.json");
    this.suspiciousPatterns = this._compilePatterns(patternData);

    const trustData = loadDataFile("trusted-sources.json");
    this.trustedSources = new Set(
      (trustData?.sources || []).map((s) => s.toLowerCase())
    );
    this.highRiskPermissions = new Set(trustData?.highRiskPermissions || []);
  }

  _compilePatterns(data) {
    if (!data) return { execution: [], networkAccess: [], dataExfiltration: [], obfuscation: [] };

    const compile = (arr) =>
      (arr || []).map((p) => {
        try {
          return new RegExp(p, "i");
        } catch {
          return null;
        }
      }).filter(Boolean);

    return {
      execution: compile(data.execution),
      networkAccess: compile(data.networkAccess),
      dataExfiltration: compile(data.dataExfiltration),
      obfuscation: compile(data.obfuscation),
    };
  }

  run(config) {
    const findings = [];
    const skillsDir = config.openclaw?.skillsDir || "";

    if (!existsSync(skillsDir)) {
      findings.push(
        new Finding({
          checkId: "SKILL-000",
          severity: Severity.INFO,
          title: "Skills directory not found",
          detail: `Expected skills at ${skillsDir}. Skill audit skipped.`,
          remediation: "Verify the OpenClaw skills directory path.",
        })
      );
      return findings;
    }

    let entries;
    try {
      entries = readdirSync(skillsDir);
    } catch {
      return findings;
    }

    for (const entry of entries.sort()) {
      const skillPath = join(skillsDir, entry);
      try {
        if (!statSync(skillPath).isDirectory()) continue;
      } catch {
        continue;
      }
      findings.push(...this._auditSingleSkill(skillPath, entry));
    }

    return findings;
  }

  _auditSingleSkill(skillPath, skillName) {
    const findings = [];

    const manifest = this._loadManifest(skillPath);
    if (manifest === null) {
      findings.push(
        new Finding({
          checkId: "SKILL-001",
          severity: Severity.MEDIUM,
          title: `Skill '${skillName}' has no manifest`,
          detail:
            "Skills without manifests cannot be verified for source authenticity or permission scoping.",
          remediation: "Remove unverified skills or add a valid manifest.",
        })
      );
    } else {
      findings.push(...this._checkManifest(skillName, manifest));
    }

    findings.push(...this._scanSourceFiles(skillPath, skillName));
    return findings;
  }

  _loadManifest(skillPath) {
    for (const name of ["manifest.yaml", "manifest.yml", "manifest.json"]) {
      const p = join(skillPath, name);
      if (!existsSync(p)) continue;
      try {
        const raw = readFileSync(p, "utf-8");
        if (name.endsWith(".json")) return JSON.parse(raw);
        return this._parseBasicYaml(raw);
      } catch {
        return {};
      }
    }
    return null;
  }

  _parseBasicYaml(content) {
    const result = {};
    let currentKey = null;
    let currentList = null;

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      if (trimmed.startsWith("- ")) {
        if (currentKey && currentList) {
          currentList.push(trimmed.slice(2).trim().replace(/^['"]|['"]$/g, ""));
        }
        continue;
      }

      if (currentKey && currentList) {
        result[currentKey] = currentList;
        currentKey = null;
        currentList = null;
      }

      const idx = trimmed.indexOf(":");
      if (idx === -1) continue;
      const key = trimmed.slice(0, idx).trim();
      let val = trimmed.slice(idx + 1).trim();

      if (val === "" || val === null) {
        currentKey = key;
        currentList = [];
        continue;
      }

      val = val.replace(/^['"]|['"]$/g, "");
      if (val === "true") val = true;
      else if (val === "false") val = false;
      result[key] = val;
    }

    if (currentKey && currentList) {
      result[currentKey] = currentList;
    }

    return result;
  }

  _checkManifest(skillName, manifest) {
    const findings = [];

    const source = (manifest.source || manifest.publisher || "").toLowerCase();
    if (source && !this.trustedSources.has(source)) {
      findings.push(
        new Finding({
          checkId: "SKILL-003",
          severity: Severity.MEDIUM,
          title: `Skill '${skillName}' from untrusted source`,
          detail: `Publisher/source '${source}' is not in the trusted sources list.`,
          remediation:
            "Verify the skill publisher. Only install skills from trusted sources.",
        })
      );
    }

    const permissions = Array.isArray(manifest.permissions)
      ? manifest.permissions
      : [];
    const risky = permissions.filter((p) => this.highRiskPermissions.has(p));
    if (risky.length > 0) {
      findings.push(
        new Finding({
          checkId: "SKILL-004",
          severity: Severity.HIGH,
          title: `Skill '${skillName}' requests high-risk permissions`,
          detail: `Requested permissions include: ${risky.join(", ")}. These allow extensive system access.`,
          remediation:
            "Review if these permissions are justified. Consider sandboxing or removing the skill.",
        })
      );
    }

    return findings;
  }

  _scanSourceFiles(skillPath, skillName) {
    const findings = [];
    const jsFiles = this._findFiles(skillPath, [".js", ".mjs", ".cjs", ".ts"]);
    let hashMatched = false;

    for (const filePath of jsFiles) {
      let fileBytes;
      try {
        fileBytes = readFileSync(filePath);
      } catch {
        continue;
      }

      const fileHash = createHash("sha256").update(fileBytes).digest("hex");
      if (this.maliciousHashes.has(fileHash)) {
        hashMatched = true;
        findings.push(
          new Finding({
            checkId: "SKILL-002",
            severity: Severity.CRITICAL,
            title: `Known malicious file in skill '${skillName}'`,
            detail:
              `File ${basename(filePath)} matches a known malicious signature ` +
              `(SHA-256: ${fileHash.slice(0, 16)}...).`,
            remediation:
              "Remove this skill immediately. Report to ClawHub security team.",
          })
        );
      }

      if (!hashMatched) {
        const content = fileBytes.toString("utf-8");
        findings.push(
          ...this._checkSuspiciousPatterns(content, filePath, skillName)
        );
        findings.push(
          ...this._checkObfuscation(content, filePath, skillName)
        );
      }
    }

    return findings;
  }

  _checkSuspiciousPatterns(content, filePath, skillName) {
    const findings = [];
    const fileName = basename(filePath);
    let matchCount = 0;

    const allPatterns = [
      ...this.suspiciousPatterns.execution,
      ...this.suspiciousPatterns.networkAccess,
      ...this.suspiciousPatterns.dataExfiltration,
    ];

    const matchedCategories = new Set();
    for (const pat of allPatterns) {
      if (pat.test(content)) {
        matchedCategories.add(pat.source);
        matchCount++;
      }
    }

    if (matchedCategories.size >= 3) {
      findings.push(
        new Finding({
          checkId: "SKILL-005",
          severity: Severity.HIGH,
          title: `Multiple suspicious patterns in '${skillName}/${fileName}'`,
          detail:
            `Found ${matchedCategories.size} categories of suspicious code patterns ` +
            "including system execution, code evaluation, or network access.",
          remediation: "Manually review this skill's source code before use.",
        })
      );
    } else if (matchedCategories.size >= 1) {
      findings.push(
        new Finding({
          checkId: "SKILL-006",
          severity: Severity.MEDIUM,
          title: `Suspicious pattern in '${skillName}/${fileName}'`,
          detail:
            "Found potentially risky code patterns. This may be benign but warrants review.",
          remediation: "Review this skill's source code to confirm it is safe.",
        })
      );
    }

    return findings;
  }

  _checkObfuscation(content, filePath, skillName) {
    const findings = [];
    const fileName = basename(filePath);

    for (const pat of this.suspiciousPatterns.obfuscation) {
      if (pat.test(content)) {
        findings.push(
          new Finding({
            checkId: "SKILL-007",
            severity: Severity.HIGH,
            title: `Obfuscated code detected in '${skillName}/${fileName}'`,
            detail:
              "The file contains patterns commonly used to obfuscate malicious code, " +
              "such as hex-encoded strings or dynamic execution of encoded payloads.",
            remediation:
              "This skill is likely malicious. Remove it and report to ClawHub security team.",
          })
        );
        break;
      }
    }

    return findings;
  }

  _findFiles(dir, extensions) {
    const results = [];
    const _walk = (d) => {
      let entries;
      try {
        entries = readdirSync(d);
      } catch {
        return;
      }
      for (const e of entries) {
        if (e === "node_modules" || e === ".git") continue;
        const full = join(d, e);
        try {
          const st = statSync(full);
          if (st.isDirectory()) {
            _walk(full);
          } else if (extensions.some((ext) => e.endsWith(ext))) {
            results.push(full);
          }
        } catch {
          continue;
        }
      }
    };
    _walk(dir);
    return results;
  }
}
