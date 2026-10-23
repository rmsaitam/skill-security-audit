---
description: Audit a project for security weaknesses and generate SECURITY-AUDIT.md
argument-hint: Target repository, service, or scope notes
---

# Security Audit

Load and follow the `security-audit` skill.

Host arguments: `$ARGUMENTS`

Use the host arguments as the audit target and scope notes when present. Otherwise use the repository in the current workspace. If the target or authorization is unclear, ask before running any check.

Start with context and reconnaissance, then confirm scope and authorization in rounds of at most five questions. Do not run scanners or write `SECURITY-AUDIT.md` until the user approves the audit plan.

Default to passive static review and manual analysis. Active testing requires explicit written authorization, an isolated non-production environment, a defined time window, and agreed stop conditions. Never test production, attempt denial of service, exfiltrate data, or expose secrets.

After generating the report, run the bundled validator, fix every error, and report the finding counts, deployment-readiness verdict, highest risks, limitations, and validation result. Do not modify application code, dependencies, or configuration. Do not modify the target unless the user explicitly requests remediation after the audit.
