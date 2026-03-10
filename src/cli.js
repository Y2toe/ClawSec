#!/usr/bin/env node

/**
 * ClawSec CLI — standalone runner for security checks.
 * Usage: node src/cli.js [--json] [--config <path>] [--fail-on-critical]
 */

import { runCheck } from "./index.js";
import { Reporter } from "./reporter.js";

function parseArgs(argv) {
  const args = {
    json: false,
    failOnCritical: false,
    configPath: null,
    overrides: {},
  };

  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--json":
        args.json = true;
        break;
      case "--fail-on-critical":
        args.failOnCritical = true;
        break;
      case "--config":
        args.configPath = argv[++i];
        break;
      case "--port":
        args.overrides.openclaw = args.overrides.openclaw || {};
        args.overrides.openclaw.defaultPort = parseInt(argv[++i], 10);
        break;
      case "--version":
        args.overrides.openclaw = args.overrides.openclaw || {};
        args.overrides.openclaw.version = argv[++i];
        break;
      case "--config-path":
        args.overrides.openclaw = args.overrides.openclaw || {};
        args.overrides.openclaw.configPath = argv[++i];
        break;
      case "--skills-dir":
        args.overrides.openclaw = args.overrides.openclaw || {};
        args.overrides.openclaw.skillsDir = argv[++i];
        break;
      case "--online":
        args.overrides.versionCheck = args.overrides.versionCheck || {};
        args.overrides.versionCheck.online = true;
        break;
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      default:
        console.warn(`[clawsec] Unknown argument: ${argv[i]}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`
ClawSec - Security Checker for OpenClaw

Usage: node src/cli.js [options]

Options:
  --json              Output JSON report (default: text)
  --fail-on-critical  Exit with code 1 if critical findings exist
  --config <path>     Path to ClawSec config file
  --config-path <p>   Path to OpenClaw config.yaml
  --skills-dir <p>    Path to OpenClaw skills directory
  --port <number>     OpenClaw default port (default: 18789)
  --version <ver>     Manually specify OpenClaw version
  --online            Enable online version check
  -h, --help          Show this help
`);
}

function main() {
  const args = parseArgs(process.argv);

  if (args.configPath) {
    process.env.CLAWSEC_CONFIG = args.configPath;
  }

  const report = runCheck(args.overrides);

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const reporter = new Reporter();
    console.log(reporter.formatText(report));
  }

  if (args.failOnCritical && report.summary.critical > 0) {
    process.exit(1);
  }
}

main();
