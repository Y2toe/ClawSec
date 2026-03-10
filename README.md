# ClawSec

**Security checker for OpenClaw installations | OpenClaw 安装环境安全检查工具**

A synchronous skill (plugin) that performs real-time security assessments of OpenClaw environments — covering authentication, exposed ports, vulnerable versions, malicious skills, and unsafe runtime configurations.

同步执行的安全检查 Skill（插件），对 OpenClaw 环境进行实时安全评估 — 涵盖认证配置、端口暴露、已知漏洞版本、恶意 Skill 检测及运行时安全。

---

## Quick Start | 快速开始

### Requirements | 环境要求

- Node.js >= 18.0.0
- Zero external dependencies | 无需安装任何第三方依赖

### Installation | 安装

```bash
git clone https://github.com/clawsec/clawsec.git
cd clawsec

# Install as an OpenClaw skill (manual)
# 作为 OpenClaw Skill 安装（手动方式）
cp -r clawsec ~/.openclaw/skills/clawsec
```

### Run in 30 Seconds | 30 秒上手

```bash
# Basic scan against your OpenClaw config
# 对 OpenClaw 配置运行基础扫描
node src/cli.js --config-path ~/.openclaw/config.yaml

# JSON output
# JSON 格式输出
node src/cli.js --config-path ~/.openclaw/config.yaml --json

# Full scan with version + skills directory
# 指定版本号 + skills 目录做完整扫描
node src/cli.js \
  --config-path ~/.openclaw/config.yaml \
  --skills-dir ~/.openclaw/skills \
  --version 2026.2.10

# Exit code 1 on critical findings (for CI/CD)
# 存在 critical 级别发现时退出码为 1（适用于 CI/CD）
node src/cli.js --config-path ~/.openclaw/config.yaml --fail-on-critical
```

---

## CLI Reference | 命令行参数

| Argument | Description | Default |
|----------|-------------|---------|
| `--config-path <path>` | Path to OpenClaw config file / OpenClaw 配置文件路径 | `~/.openclaw/config.yaml` |
| `--skills-dir <path>` | Path to OpenClaw skills directory / Skills 目录路径 | `~/.openclaw/skills` |
| `--version <ver>` | Manually specify OpenClaw version / 手动指定版本号 | Auto-detect / 自动检测 |
| `--port <number>` | OpenClaw default port / 默认端口 | `18789` |
| `--json` | Output report as JSON / JSON 格式输出 | Text / 文本 |
| `--fail-on-critical` | Exit with code 1 on critical findings / 有 Critical 时退出码为 1 | Disabled / 不启用 |
| `--online` | Enable online version check / 启用在线版本检查 | Disabled / 不启用 |
| `--config <path>` | Path to ClawSec config file / ClawSec 配置文件路径 | `~/.openclaw/clawsec.json` |
| `-h, --help` | Show help / 显示帮助 | - |

---

## Usage as OpenClaw Skill | 作为 OpenClaw Skill 使用

### Natural Language Triggers | 自然语言触发

> "Run ClawSec check"
> "Check my OpenClaw security"
> "Security scan"

### Programmatic API | 编程接口

```javascript
import { runCheck } from "clawsec";

const report = runCheck({
  openclaw: {
    configPath: "/path/to/config.yaml",
    skillsDir: "/path/to/skills",
    version: "2026.2.10",
  },
});

console.log(report);
```

### Startup Pre-flight | 启动预检

Add to your OpenClaw `config.yaml`:

在 OpenClaw 的 `config.yaml` 中添加：

```yaml
startup_skills:
  - name: clawsec
    args:
      failOnCritical: true
```

---

## Configuration | 配置

Optional. Create `~/.openclaw/clawsec.json` or set the `CLAWSEC_CONFIG` environment variable.

可选。创建 `~/.openclaw/clawsec.json` 或通过 `CLAWSEC_CONFIG` 环境变量指定路径。

```json
{
  "openclaw": {
    "configPath": "~/.openclaw/config.yaml",
    "skillsDir": "~/.openclaw/skills",
    "gatewayConfigPath": "~/.openclaw/gateway.yaml",
    "defaultPort": 18789
  },
  "versionCheck": {
    "online": false,
    "feedUrl": "https://clawsec.github.io/vuln-feed.json"
  },
  "checks": {
    "portExposure": true,
    "authConfig": true,
    "version": true,
    "skillAudit": true,
    "websocketSecurity": true,
    "hookLoading": true,
    "sandboxIsolation": true,
    "credentialStorage": true
  }
}
```

Set any item in `checks` to `false` to skip that check.

将 `checks` 中任一项设为 `false` 可跳过对应检查。

---

## Security Checks | 检查项

### Config Scanner | 配置扫描

| ID | Severity | EN | CN |
|----|----------|----|----|
| AUTH-001 | Critical | Authentication is disabled | 认证功能未启用 |
| AUTH-002 | High | Token shorter than 32 characters | Token 长度不足 32 字符 |
| AUTH-003 | Critical | Auth enabled but token is empty | 认证已启用但 Token 为空 |
| CFG-001 | Critical | Server bound to 0.0.0.0 (publicly exposed) | 服务器绑定到 0.0.0.0（公网暴露）|
| CFG-002 | High | CORS allows wildcard origin | CORS 设置为 * 通配 |
| CFG-003 | High | Plaintext credentials in config | 配置文件中存在明文凭证 |
| CFG-004 | Medium | Sensitive values in .env file | .env 文件中包含敏感字段 |
| GW-001 | High | WebSocket gateway TLS not enabled | WebSocket 网关未启用 TLS |
| GW-002 | Medium | No WebSocket origin restrictions | WebSocket 无 origin 限制 |

### Version Checker | 版本检查

| ID | Severity | EN | CN |
|----|----------|----|----|
| VER-001 | High | Below minimum safe version (2026.2.25) | 版本低于最低安全版本 |
| VER-002 | High | Newer safe version available (online) | 在线检查发现更新的安全版本 |
| VER-xxxx | By CVSS | Matches known CVE vulnerability | 匹配到已知 CVE 漏洞 |

### Skill Auditor | Skill 审计

| ID | Severity | EN | CN |
|----|----------|----|----|
| SKILL-001 | Medium | Skill has no manifest file | Skill 缺少 manifest 文件 |
| SKILL-002 | Critical | File hash matches known malicious signature | 文件哈希匹配已知恶意签名 |
| SKILL-003 | Medium | Skill from untrusted source | Skill 来自不受信任的来源 |
| SKILL-004 | High | Skill requests high-risk permissions | Skill 请求高危权限 |
| SKILL-005 | High | Multiple suspicious code patterns found | 发现多类可疑代码模式 |
| SKILL-006 | Medium | Single suspicious code pattern found | 发现单类可疑代码模式 |
| SKILL-007 | High | Obfuscated code detected | 检测到代码混淆 |

### Runtime Monitor | 运行时监控

| ID | Severity | EN | CN |
|----|----------|----|----|
| PORT-001 | Critical | Default port listening on all interfaces | 默认端口监听在所有网络接口 |
| WS-001 | High | WebSocket using unencrypted connection | WebSocket 使用未加密连接 |
| WS-002 | High | WebSocket allows all origins | WebSocket 允许所有 origin |
| HOOK-001 | High | Hook path contains traversal characters | Hook 路径包含目录穿越字符 |
| HOOK-002 | Medium | Hook uses relative path | Hook 使用相对路径 |
| SANDBOX-001 | Medium | Not running inside a container | 未在容器中运行 |
| SANDBOX-002 | High | Running as root user | 以 root 用户运行 |

---

## Report Output | 报告输出

### Text (default) | 文本格式（默认）

```
============================================================
  ClawSec Security Report v1.0.0
  Generated: 2026-03-10T12:00:00.000Z
============================================================

  Status: FAIL
  Findings: 3 total | 1 critical | 1 high | 1 medium | 0 low | 0 info

  [CRITICAL]  AUTH-001: Authentication is disabled
             No token-based authentication is configured...
             -> Enable token auth in config.yaml...
============================================================
```

### JSON (`--json`)

```json
{
  "tool": "ClawSec",
  "version": "1.0.0",
  "timestamp": "2026-03-10T12:00:00.000Z",
  "summary": { "total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0 },
  "pass": false,
  "findings": [
    {
      "check_id": "AUTH-001",
      "severity": "critical",
      "title": "Authentication is disabled",
      "detail": "...",
      "remediation": "..."
    }
  ]
}
```

The `pass` field is `true` only when both critical and high counts are zero.

`pass` 字段仅在 critical 和 high 数量均为 0 时为 `true`。

---

## Detection Data | 检测数据

All detection data is stored as JSON in the `data/` directory. Update data without changing code.

所有检测数据以 JSON 格式存放在 `data/` 目录下，更新数据无需修改代码。

| File | Purpose | 用途 |
|------|---------|------|
| `vulnerable-versions.json` | Known vulnerable versions mapped to CVEs | 已知漏洞版本与 CVE 映射 |
| `malicious-hashes.json` | SHA-256 hashes of known malicious files | 已知恶意文件的 SHA-256 哈希 |
| `suspicious-patterns.json` | Regex patterns for suspicious code detection | 可疑代码的正则表达式 |
| `trusted-sources.json` | Trusted skill publishers | 受信任的 Skill 发布者列表 |
| `sensitive-keys.json` | Sensitive config key patterns | 敏感配置键名模式 |

Use `CLAWSEC_DATA_DIR` environment variable to specify a custom data directory.

可通过环境变量 `CLAWSEC_DATA_DIR` 指定自定义数据目录。

---

## Testing | 测试

```bash
node --test tests/**/*.test.js
```

---

## Project Structure | 项目结构

```
clawsec/
├── manifest.yaml             # OpenClaw skill manifest / Skill 注册清单
├── package.json
├── data/                     # External detection data / 外部化检测数据
│   ├── vulnerable-versions.json
│   ├── malicious-hashes.json
│   ├── suspicious-patterns.json
│   ├── trusted-sources.json
│   └── sensitive-keys.json
├── src/
│   ├── index.js              # Entry point & skill adapter / 主入口与 Skill 适配
│   ├── cli.js                # CLI runner / 命令行工具
│   ├── models.js             # Finding & Severity models / 数据模型
│   ├── config.js             # Config loader / 配置加载
│   ├── reporter.js           # Report generator / 报告生成
│   └── checkers/
│       ├── config-scanner.js  # Auth, port, CORS, credentials / 认证、端口、凭证
│       ├── version-checker.js # CVE version matching / CVE 版本比对
│       ├── skill-auditor.js   # Malicious skill detection / 恶意 Skill 检测
│       └── runtime-monitor.js # Port, WS, hooks, sandbox / 端口、WS、沙箱
└── tests/                    # 35 tests / 35 项测试
```

---

## Security Notes | 安全说明

- ClawSec makes **no outbound network requests** unless `--online` is explicitly enabled.
- All checks are **read-only** — no files or configurations are ever modified.
- Detected tokens/passwords are **never included** in reports; only metadata (length, location) is reported.
- Skill auditing reads files as **raw text only** — no scanned code is ever executed.

---

- ClawSec **不会发起外部网络请求**，除非手动开启 `--online` 选项。
- 所有检查均为**只读操作**，不会修改任何文件或配置。
- 检测到的 Token/密码**不会出现在报告中**，仅报告元数据（长度、位置）。
- Skill 审计仅以**文本方式读取文件**，不执行任何被扫描的代码。

---

## License

MIT
