---
description: Validate SECURITY-AUDIT.md against the Security Audit report contract
argument-hint: Optional path to SECURITY-AUDIT.md
---

# Validate Security Audit Report

Load and follow the `security-audit` skill for the report contract.

Host arguments: `$ARGUMENTS`

Use the host arguments as the report path when provided. Otherwise default to `SECURITY-AUDIT.md` in the current directory.

Resolve the validator script relative to the installed `security-audit` skill and run:

```bash
python3 scripts/validate_report.py SECURITY-AUDIT.md --min-questions 6
```

Use the actual path supplied by the user. Add `--strict` when the user wants warnings treated as errors. Add `--json` when a machine-readable report is useful. Add `--min-findings 1` when the audit must contain at least one finding.

Report errors first, then warnings, then finding counts, open High and Medium findings, and the deployment-readiness verdict. Do not edit the report unless the user asks. If asked to fix it, update the report, preserve the markers, and re-run validation until it passes.
