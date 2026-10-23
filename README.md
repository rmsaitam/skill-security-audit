# Security Audit

[![skills.sh](https://skills.sh/b/rmsaitam/skill-security-audit)](https://skills.sh/rmsaitam/skill-security-audit)

Security Audit is a defensive security-audit plugin for AI coding agents. It scopes the audit, collects evidence, reviews code and configuration against **OWASP Top 10:2021** and **CWE**, scores findings with **CVSS** v3.1, and produces one validated artifact:

- `SECURITY-AUDIT.md`: scope, authorization, methodology, threat model, findings, risk summary, remediation plan, deployment readiness, evidence, assumptions, audit answers, and traceability.

Findings use three severities: **High**, **Medium**, and **Low**. The default mode is passive static analysis plus manual review. Active testing requires explicit written authorization and an isolated non-production environment.

Repository: https://github.com/rmsaitam/skill-security-audit

## Supported agents

| Agent | Manifest |
| --- | --- |
| Claude Code | `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` |
| Codex | `.codex-plugin/plugin.json` and `.agents/plugins/marketplace.json` |
| Cursor | `.cursor-plugin/plugin.json` and `.cursor-plugin/marketplace.json` |
| GitHub Copilot CLI | `.github/plugin/marketplace.json` with the root `plugin.json` |
| Antigravity | root `plugin.json` |

All agents use the shared skill at `skills/security-audit/SKILL.md` and the commands in `commands/`.

## Install

### skills.sh

```bash
npx skills add rmsaitam/skill-security-audit
npx skills add rmsaitam/skill-security-audit -g -y
```

### Claude Code

From a published marketplace:

```text
/plugin marketplace add rmsaitam/skill-security-audit
/plugin install security-audit@security-audit
```

From a local checkout:

```text
/plugin marketplace add /absolute/path/to/skill-security-audit
/plugin install security-audit@security-audit
```

### Codex

```bash
codex plugin marketplace add rmsaitam/skill-security-audit
codex plugin install security-audit@security-audit
```

### GitHub Copilot CLI

```bash
copilot plugin marketplace add rmsaitam/skill-security-audit
copilot plugin install security-audit@security-audit
```

### Cursor

Install the plugin from a marketplace that lists this repository, or point Cursor at a local plugin directory containing this repository. Cursor reads `.cursor-plugin/plugin.json`, the shared `skills/` directory, and `commands/`.

### Antigravity

Install the repository root as a plugin. Antigravity reads the root `plugin.json` directly.

Command syntax varies by agent version. When a command is unavailable, use the agent's plugin marketplace UI and select the `security-audit` plugin.

## Usage

Start an audit:

```text
/security-audit Review this repository and produce SECURITY-AUDIT.md
```

The skill follows eight gates:

1. Inspect the workspace and reuse known facts.
2. Confirm scope, authorization, data handling, and stop conditions.
3. Present the audit plan and wait for approval.
4. Collect non-destructive evidence with approved tools.
5. Perform manual review against OWASP Top 10 and CWE.
6. Write `SECURITY-AUDIT.md` with findings, evidence, and remediation.
7. Validate the report and fix every error.
8. Report the result and stop before remediation.

Validate an existing report:

```text
/security-audit-validate
/security-audit-validate docs/SECURITY-AUDIT.md
```

## Severity model

| Severity | CVSS 3.1 | Meaning |
| --- | --- | --- |
| High | 7.0 to 10.0 | Remote code execution, privilege escalation, authentication bypass, or critical data exposure |
| Medium | 4.0 to 6.9 | Conditional exploitation, denial of service, limited exposure, or meaningful weakening of a control |
| Low | 0.0 to 3.9 | Misconfiguration, missing hardening, minor information leak, or best-practice gap |

Score the finding, explain the contextual impact, and never downgrade a finding without a recorded exception.

## Artifact contract

### SECURITY-AUDIT.md

The file starts with:

```html
<!-- security-audit:artifact type=report version=1 -->
```

It must contain section markers for `summary`, `scope`, `authorization`, `methodology`, `threatmodel`, `findings`, `risk`, `remediation`, `readiness`, `evidence`, `assumptions`, `qa`, and `traceability`.

Every finding uses a marker:

```html
<!-- security-audit:finding id=FIND-001 severity=high cvss=9.8 cwe=CWE-89 owasp=A03:2021 status=open -->
```

Each finding also contains:

- Severity, CVSS, CWE, OWASP, Location, and Confidence.
- Description, Impact, Evidence, and an affected code block.
- Remediation, Verification, and References.

The counts marker must match the findings:

```html
<!-- security-audit:counts high=1 medium=2 low=0 -->
```

A clean audit is valid. State that no findings were identified, document the checks performed, and set all counts to zero.

The report requires at least six answered audit questions. Its deployment-readiness verdict must be `Ready`, `Ready with conditions`, or `Not ready`, and an open High finding blocks a `Ready` verdict.

## Validation

Run the report validator:

```bash
python3 skills/security-audit/scripts/validate_report.py SECURITY-AUDIT.md --min-questions 6
```

Options:

```text
--min-findings 0     Minimum number of findings. Zero allows a clean audit.
--min-questions 6    Minimum answered audit questions.
--strict             Treat warnings as failures.
--json               Emit a machine-readable report.
```

The validator uses only the Python standard library. It checks markers, metadata, required sections, finding IDs and order, severity and CVSS consistency, CWE and OWASP formats, field completeness, code blocks, counts, remediation and traceability coverage, readiness consistency, audit answers, placeholders, and unredacted secret patterns.

If Python is unavailable, use `skills/security-audit/references/validation-checklist.md`.

## Development

Prerequisites:

- Python 3.10 or newer.
- `uv` for the test environment.

The published plugin has no Python runtime dependencies. Its validators use only the standard library. For development:

```bash
uv sync --extra dev
source .venv/bin/activate
pytest -q
```

Run the tests and coverage gate:

```bash
make coverage
```

Validate the plugin structure:

```bash
make validate
```

Run everything:

```bash
make check
```

The test suite requires at least 80 percent branch coverage over both validator scripts.

## Repository layout

```text
.
├── plugin.json
├── .claude-plugin/
├── .codex-plugin/
├── .cursor-plugin/
├── .agents/plugins/
├── .github/
├── agents/openai.yaml
├── assets/
├── commands/
├── skills/security-audit/
│   ├── SKILL.md
│   ├── references/
│   └── scripts/validate_report.py
├── scripts/validate_plugin.py
└── tests/
```

## Security and ethics

- The default is passive static review.
- Active testing requires explicit written authorization, an isolated non-production environment, a defined window, and agreed stop conditions.
- Never test production, attempt denial of service, exfiltrate data, or expose secrets.
- Redact secrets, tokens, personal data, and customer data from the report.
- Do not invent CVE identifiers, CVSS vectors, or exploit results.
- Do not modify application code or dependencies unless the user explicitly requests remediation.
- The plugin contains instructions, Markdown commands, and Python validators. It does not include MCP servers, hooks, network calls, telemetry, or credentials.

## License

MIT. See `LICENSE`.
