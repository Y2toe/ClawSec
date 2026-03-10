/**
 * Configuration loading — merges defaults with user overrides.
 * No hardcoded values; all defaults come from manifest.yaml or are overridable.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";

function expandHome(p) {
  if (typeof p === "string" && p.startsWith("~")) {
    return join(homedir(), p.slice(1));
  }
  return p;
}

function deepMerge(base, override) {
  const result = { ...base };
  for (const key of Object.keys(override)) {
    if (
      result[key] &&
      typeof result[key] === "object" &&
      !Array.isArray(result[key]) &&
      typeof override[key] === "object" &&
      !Array.isArray(override[key])
    ) {
      result[key] = deepMerge(result[key], override[key]);
    } else {
      result[key] = override[key];
    }
  }
  return result;
}

const DEFAULT_CONFIG = {
  openclaw: {
    configPath: "~/.openclaw/config.yaml",
    skillsDir: "~/.openclaw/skills",
    gatewayConfigPath: "~/.openclaw/gateway.yaml",
    defaultPort: 18789,
  },
  versionCheck: {
    online: false,
    feedUrl: "https://clawsec.github.io/vuln-feed.json",
  },
  checks: {
    portExposure: true,
    authConfig: true,
    version: true,
    skillAudit: true,
    websocketSecurity: true,
    hookLoading: true,
    sandboxIsolation: true,
    credentialStorage: true,
  },
};

export function loadConfig(overrides = {}) {
  let config = { ...DEFAULT_CONFIG };

  const userConfigPath = expandHome(
    process.env.CLAWSEC_CONFIG || "~/.openclaw/clawsec.json"
  );

  if (existsSync(userConfigPath)) {
    try {
      const raw = readFileSync(userConfigPath, "utf-8");
      const userConfig = JSON.parse(raw);
      config = deepMerge(config, userConfig);
    } catch (err) {
      console.warn(`[clawsec] Failed to load user config: ${err.message}`);
    }
  }

  config = deepMerge(config, overrides);

  config.openclaw.configPath = expandHome(config.openclaw.configPath);
  config.openclaw.skillsDir = expandHome(config.openclaw.skillsDir);
  config.openclaw.gatewayConfigPath = expandHome(config.openclaw.gatewayConfigPath);

  return config;
}

export function loadDataFile(filename) {
  const dataDir = resolve(
    process.env.CLAWSEC_DATA_DIR || new URL("../data", import.meta.url).pathname
  );
  const filePath = join(dataDir, filename);
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch (err) {
    console.warn(`[clawsec] Failed to load data file ${filename}: ${err.message}`);
    return null;
  }
}
