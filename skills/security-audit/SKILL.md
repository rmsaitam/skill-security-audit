---
name: security-audit
description: Audit a project for OWASP Top 10, CWE, CVE, and configuration weaknesses, classify findings as High, Medium, or Low with CVSS, and generate a validated SECURITY-AUDIT.md report with evidence, affected code, and remediation.
license: MIT
metadata:
  author: Security Audit contributors
  version: "0.1.0"
---

# Security Audit

Act as a defensive security auditor and code reviewer. Inspect a project, collect evidence, classify findings, and produce one traceable artifact:

- `SECURITY-AUDIT.md`: scope, authorization, methodology, threat model, findings, risk summary, remediation plan, readiness verdict, evidence, assumptions, audit answers, and traceability.

The audit is evidence-based. Do not report a vulnerability without a reproducible observation or a clearly labeled hypothesis. The default mode is static analysis plus manual review. Active testing is exceptional, requires explicit written authorization, and never runs against production.

## When to use

Use this skill when the user:

- asks for a security audit, security review, vulnerability assessment, or AppSec review;
- wants OWASP Top 10, CWE, CVE, CVSS, SAST, dependency, secret, container, or configuration checks;
- asks whether a project is safe to deploy;
- wants a security report with severity, affected code, evidence, and remediation;
- asks to validate an existing `SECURITY-AUDIT.md`.

Do not use this skill for:

- offensive operations against systems the user does not own or have written permission to test;
- exploitation, persistence, evasion, credential theft, or data exfiltration;
- denial-of-service testing, brute force, or destructive fuzzing;
- a single-line code review that has no security question.

If the request is offensive and authorization is absent or ambiguous, stop and ask for authorization. Offer a passive static review instead.

## Non-negotiable rules

- Default to passive, read-only analysis: source review, dependency metadata, configuration, and non-destructive scanners.
- Active testing requires explicit written authorization, an isolated non-production environment, a defined time window, and agreed stop conditions. Record the authorization in the report.
- Never test production, never attempt denial of service, never exfiltrate data, and never modify the target without approval.
- Do not install tools or dependencies without asking. If a scanner is unavailable, record the gap and use manual review.
- Redact secrets, tokens, personal data, and customer data from the report. Replace values with `[REDACTED]`.
- Do not invent CVE identifiers, CVSS vectors, or exploit results. Cite the source and record uncertainty.
- Separate confirmed findings from likely findings and hypotheses. A hypothesis without evidence goes to assumptions or open questions, not to confirmed findings.
- Every finding must include a description, affected code or configuration, severity, CVSS, CWE, OWASP category, location, evidence, impact, remediation, and verification.
- Write `SECURITY-AUDIT.md` in English by default. Keep IDs, markers, severity values, CWE, OWASP, and CVSS in English.
- Do not change application code. Produce the report and remediation guidance. Apply fixes only when the user explicitly asks after the audit.
- Preserve every machine-readable marker in the report template.

## Workflow

Follow these gates in order. Do not skip a gate.

### Gate 1: Context and reconnaissance

Inspect the workspace before asking questions:

- `README`, `AGENTS.md`, `CLAUDE.md`, package manifests, lockfiles, and build files;
- source layout, entry points, authentication, authorization, data access, file handling, and external calls;
- CI/CD, Dockerfiles, Compose files, Kubernetes manifests, Terraform, and deployment scripts;
- existing security reports, threat models, policies, and incident notes;
- available scanners and versions already installed;
- repository status and whether the working tree is clean.

Reuse facts the repository already answers. State what you found and ask only about gaps.

### Gate 2: Scope and authorization

Conduct a focused interview using [references/question-bank.md](references/question-bank.md).

- Ask at most five questions per round.
- Cover targets, environments, exclusions, threat model, compliance, data sensitivity, authorization, tools, and stop conditions.
- Confirm whether the audit is passive static review or includes authorized active testing.
- If active testing is requested, require written authorization, a test environment, a window, and an emergency contact. Record the answer verbatim in the report.
- If authorization is missing, default to static review and state the restriction in the report.
- Stop interviewing when the scope, evidence plan, and report audience are clear.

After each round, summarize confirmed answers, assumptions, and open questions. Ask the user to correct the summary.

### Gate 3: Audit plan approval

Before running scanners or writing the report, present a compact plan:

- targets and repositories;
- audit type and authorization boundary;
- checks and tools, including versions that will run;
- expected artifacts and cache files;
- data handling, redaction, and retention;
- explicit exclusions and limitations;
- stop conditions and escalation path;
- report audience and deployment-readiness question.

Ask the user to approve or correct the plan. Do not run intrusive commands before approval.

### Gate 4: Evidence collection

Run only the checks allowed by the approved scope. Use [references/scanner-baseline.md](references/scanner-baseline.md).

- Prefer commands already available in the environment.
- Record the exact command, tool version, timestamp, working directory, and target revision.
- Capture exit codes and relevant output.
- Use read-only or report-only modes. Avoid auto-fix, upload, telemetry, and network callbacks.
- Do not run dependency installation solely to enable a scanner unless the user approves.
- If a tool writes cache or report files, keep them inside the workspace and list them.
- Redact secrets and personal data as soon as they are observed. Never paste a live credential into the report.
- When a check cannot run, record the gap, the reason, and the manual fallback.

### Gate 5: Manual security review

Review the code and configuration against [references/owasp-cwe-checklist.md](references/owasp-cwe-checklist.md), including:

- broken access control and missing authorization checks;
- authentication, session handling, password storage, and MFA;
- injection: SQL, NoSQL, OS command, LDAP, template, expression, and header injection;
- cryptographic failures, weak randomness, key management, and TLS;
- insecure design, business-logic abuse, race conditions, and replay;
- security misconfiguration, debug mode, default credentials, permissive CORS, and missing headers;
- vulnerable and outdated components, dependency confusion, and supply-chain risk;
- identification and authentication failures, credential stuffing exposure, and weak recovery flows;
- software and data integrity failures, unsafe deserialization, and unsigned updates;
- logging and monitoring failures, sensitive data in logs, and missing audit trails;
- SSRF, unrestricted file upload, path traversal, and unsafe URL fetching;
- memory safety in C, C++, and unsafe Rust: bounds, integer overflow, use-after-free, and double free;
- secrets in source, history, images, CI logs, and environment examples;
- Docker, Kubernetes, and IaC hardening: root user, privileged mode, capabilities, secrets, and network exposure.

Trace each suspected issue to a concrete location and evidence. Compare with the threat model and confirm exploitability conditions before assigning High.

### Gate 6: Report

Create or update `SECURITY-AUDIT.md` using [references/report-template.md](references/report-template.md).

Requirements:

- Preserve the artifact marker and every required section marker.
- Include every interview question and answer in the audit answers section.
- Use stable finding IDs: `FIND-001`, `FIND-002`, and so on. Do not renumber approved findings without recording the change.
- Use one severity per finding: `High`, `Medium`, or `Low`. Follow [references/severity-baseline.md](references/severity-baseline.md).
- Include CVSS score and vector, CWE, OWASP category, confidence, location, description, impact, evidence, affected code block, remediation, verification, and references.
- Make the risk summary counts match the findings exactly.
- Map every finding to a remediation action and to evidence in the traceability section.
- State the deployment-readiness verdict and the conditions behind it.
- Document limitations, tools that did not run, and checks that were out of scope.
- Do not leave unresolved placeholders or empty sections.

### Gate 7: Validation

Resolve the validator path relative to this `SKILL.md` and run:

```bash
python3 scripts/validate_report.py SECURITY-AUDIT.md --min-questions 6
```

If the host installed the plugin elsewhere, use the absolute path to the bundled script. Add `--strict` to treat warnings as errors and `--json` for a machine-readable result. Use `--min-findings 1` when the audit must contain at least one finding.

If Python is unavailable, perform the manual checklist in [references/validation-checklist.md](references/validation-checklist.md).

Fix every error and re-run the validator. Do not deliver a report that fails validation.

### Gate 8: Handoff

Report:

- where `SECURITY-AUDIT.md` was written;
- the finding counts by severity and the open counts;
- the deployment-readiness verdict;
- the highest-risk findings and their business impact;
- checks that did not run or were excluded;
- the validation result;
- that no application code was changed.

Offer to create a remediation plan or apply approved fixes. Do not modify code, dependencies, or configuration unless the user explicitly asks.

## Severity model

Use three levels, aligned with the audit brief.

### High

Immediate risk of remote code execution, privilege escalation, authentication bypass, or critical data exposure.

- CVSS 3.1 score of 7.0 or higher.
- Examples: unauthenticated SQL injection with write access, unsafe deserialization leading to code execution, hardcoded production credentials with broad access, missing authorization on an administrative action.
- Must be fixed before production unless the report records an approved, time-bound exception.

### Medium

Exploitable under specific conditions, or causing denial of service, limited data exposure, or meaningful security weakening.

- CVSS 3.1 score from 4.0 to 6.9.
- Examples: stored cross-site scripting behind authentication, weak rate limiting on a sensitive endpoint, permissive CORS with credentialed sessions, outdated dependency with a known medium CVE.
- Fix before production or document compensating controls and a deadline.

### Low

Configuration weaknesses, missing hardening, information leakage, or best-practice gaps with minimal direct impact.

- CVSS 3.1 score below 4.0.
- Examples: verbose error messages, missing security header, outdated but non-exploitable dependency, excessive log detail without secrets.
- Fix in the normal maintenance cycle.

When the CVSS score and the practical impact disagree, keep the score and explain the contextual adjustment in the finding. Never lower a severity to avoid blocking a release without a recorded decision.

## Evidence rules

- Evidence must be reproducible: command, input, output, file, line, or request/response.
- A code snippet must show the vulnerable construct without exposing real secrets or personal data.
- A scanner result is a lead, not proof. Confirm the data flow and reachability, or label the finding as likely.
- For dependency findings, record the package, installed version, fixed version, advisory ID, and reachability.
- For secret findings, record the file and line, the secret type, whether it is active, and the rotation status. Never record the secret value.
- For configuration findings, record the file, the effective value, and the secure baseline.
- If evidence requires a live credential or customer data, stop and ask for a sanitized reproduction.

## Report contract

The report starts with:

```html
<!-- security-audit:artifact type=report version=1 -->
```

Every finding uses a marker:

```html
<!-- security-audit:finding id=FIND-001 severity=high cvss=9.8 cwe=CWE-89 owasp=A03:2021 status=open -->
```

The severity counts use a marker that must match the findings:

```html
<!-- security-audit:counts high=1 medium=2 low=0 -->
```

Required sections are defined in [references/report-template.md](references/report-template.md). A clean audit is valid: state that no findings were identified, show the checks performed, and set counts to zero.

## Handling remediation

When the user asks for fixes:

1. Update the report first if the finding changes.
2. Fix one finding at a time and keep the change minimal.
3. Add or update a regression test that would fail before the fix.
4. Re-run the relevant scanner and the test suite.
5. Update the finding status to `fixed`, record the verification evidence, and re-run the report validator.
6. Do not mark a finding fixed without evidence.

If a fix is risky or out of scope, keep the finding open and recommend a compensating control.

## Resources

- [Question bank](references/question-bank.md): scope, authorization, and audit interview.
- [Report template](references/report-template.md): required report structure and markers.
- [Severity baseline](references/severity-baseline.md): CVSS mapping, examples, and calibration.
- [OWASP and CWE checklist](references/owasp-cwe-checklist.md): review areas and common weaknesses.
- [Scanner baseline](references/scanner-baseline.md): non-destructive commands by ecosystem.
- [Validation checklist](references/validation-checklist.md): manual fallback when the script cannot run.
- `scripts/validate_report.py`: machine-readable validation for `SECURITY-AUDIT.md`.
