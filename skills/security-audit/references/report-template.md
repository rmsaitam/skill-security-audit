# Report Template

Copy this structure into `SECURITY-AUDIT.md`. Replace every prompt with audited evidence. Preserve every HTML marker exactly. The prose is English by default; marker IDs, severity values, CWE, OWASP, CVSS, and finding IDs stay in English.

A report with findings:

````markdown
<!-- security-audit:artifact type=report version=1 -->
# Security Audit: Project or Service Name

- Status: Final
- Date: 2026-01-01
- Owner: Security team
- Target: repository, service, revision, or artifact under review
- Audit type: Static and manual review
- Report language: English
- Authorization: Passive static review only; no active exploitation.
- Deployment readiness: Ready with conditions

<!-- security-audit:section id=summary -->
## 1. Executive Summary

Describe the target, the audit scope, the number of findings, the highest severity, and the deployment recommendation in one or two paragraphs.

<!-- security-audit:counts high=1 medium=1 low=0 -->

<!-- security-audit:section id=scope -->
## 2. Scope

### In scope

- Repository, branch, commit, or artifact reviewed.
- Services, modules, and configurations assessed.

### Out of scope

- Systems, environments, and components explicitly excluded.

### Limits

- Checks that were unavailable, unsafe, or not authorized.

<!-- security-audit:section id=authorization -->
## 3. Authorization and Rules of Engagement

State who authorized the audit, the authorization reference, the permitted mode, the environment, the time window, and the stop conditions. For passive review, state that no active testing was performed.

<!-- security-audit:section id=methodology -->
## 4. Methodology

- OWASP Top 10:2021 review.
- CWE Top 25 and relevant CWE categories.
- CVSS v3.1 scoring.
- SAST, dependency, secret, container, or IaC checks that were actually run.
- Manual review of authentication, authorization, input handling, cryptography, and business logic.
- Evidence collection and redaction rules.

<!-- security-audit:section id=threatmodel -->
## 5. Threat Model

### Assets

- Credentials, customer data, administrative functions, availability, and integrity.

### Actors

- Unauthenticated internet users, authenticated users, administrators, insiders, partners, and supply-chain actors.

### Trust boundaries

- Browser to edge, edge to API, API to database, service to service, and CI to registry.

### Relevant attack paths

- The most plausible paths from an actor to a critical asset.

<!-- security-audit:section id=findings -->
## 6. Findings

<!-- security-audit:finding id=FIND-001 severity=high cvss=9.8 cwe=CWE-89 owasp=A03:2021 status=open -->
### FIND-001: Short finding title

- Severity: High
- CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- CWE: CWE-89
- OWASP: A03:2021 - Injection
- Location: path/to/file.ext:42
- Confidence: Confirmed
- Description: Explain the vulnerable behavior and the condition that makes it reachable.
- Impact: Explain what an attacker can achieve and which data or function is at risk.
- Evidence: Provide a sanitized reproduction, tool output summary, or data-flow trace.
- Affected code:
```text
Show the vulnerable construct with secrets and personal data redacted.
```
- Remediation: Describe the specific fix and any defense-in-depth control.
- Verification: Describe the test, scan, or manual check that proves the fix.
- References: CWE-89, OWASP A03:2021, and the relevant advisory if one exists.

<!-- security-audit:finding id=FIND-002 severity=medium cvss=5.3 cwe=CWE-307 owasp=A07:2021 status=open -->
### FIND-002: Short finding title

- Severity: Medium
- CVSS: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- CWE: CWE-307
- OWASP: A07:2021 - Identification and Authentication Failures
- Location: path/to/file.ext:88
- Confidence: Likely
- Description: Explain the weakness and the conditions required to exploit it.
- Impact: Explain the limited or conditional impact.
- Evidence: Provide the sanitized observation.
- Affected code:
```text
Show the relevant configuration or code with sensitive values redacted.
```
- Remediation: Describe the fix and compensating controls.
- Verification: Describe how the fix will be verified.
- References: CWE-307 and OWASP A07:2021.

<!-- security-audit:section id=risk -->
## 7. Risk Summary

| Severity | Total | Open | Fixed | Accepted | Notes |
| --- | --- | --- | --- | --- | --- |
| High | 1 | 1 | 0 | 0 | Must be resolved or explicitly accepted before production. |
| Medium | 1 | 1 | 0 | 0 | Resolve before production or document compensating controls. |
| Low | 0 | 0 | 0 | 0 | Address in the maintenance cycle. |

<!-- security-audit:section id=remediation -->
## 8. Remediation Plan

| Finding | Priority | Action | Owner | Target date | Verification |
| --- | --- | --- | --- | --- | --- |
| FIND-001 | P1 | Replace string concatenation with parameterized queries. | Application team | 2026-01-15 | Regression test and SAST rescan. |
| FIND-002 | P2 | Add rate limiting and account lockout with monitoring. | Platform team | 2026-02-01 | Load test and configuration review. |

Every finding must appear in this table. Prioritize by severity, exploitability, and business impact.

<!-- security-audit:section id=readiness -->
## 9. Deployment Readiness

State the verdict and the conditions. A High finding that is open cannot be marked `Ready`.

- [ ] Every High finding is fixed or has an approved, time-bound exception.
- [ ] Every Medium finding is fixed or has compensating controls and a deadline.
- [ ] Authentication and authorization paths were reviewed.
- [ ] Dependency and secret scans were run or their absence is documented.
- [ ] Logging and monitoring were reviewed for sensitive data.
- [ ] Remediation owners and target dates are recorded.

<!-- security-audit:section id=evidence -->
## 10. Evidence

- Tool: tool name and version.
- Command: exact command executed.
- Target: revision, directory, image, or endpoint.
- Date: timestamp and timezone.
- Result: summarized output, exit code, and relevant artifact path.
- Limitations: checks that could not run and why.
- Redaction: secrets, tokens, personal data, and customer data were removed.

<!-- security-audit:section id=assumptions -->
## 11. Assumptions and Open Questions

- Assumption that must remain true for the findings to apply.
- Open question that could change severity or reachability.
- Residual-risk owner and decision, when applicable.

<!-- security-audit:section id=qa -->
## 12. Audit Answers

### Q-001

- Question: Exact question asked during the audit interview.
- Answer: Exact answer or approved decision.

### Q-002

- Question: Exact question asked during the audit interview.
- Answer: Exact answer or approved decision.

Add one entry for every question asked. If the user delegated a decision, write the chosen assumption and note that it was approved.

<!-- security-audit:section id=traceability -->
## 13. Traceability

| Finding | Evidence | Remediation | Status |
| --- | --- | --- | --- |
| FIND-001 | Section 10, command output and data-flow trace | Section 8, parameterized queries | Open |
| FIND-002 | Section 10, configuration review | Section 8, rate limiting and lockout | Open |

Every finding must appear in this table and map to both evidence and remediation.
````

A clean audit uses the same structure but states in the findings section that no findings were identified, sets the counts marker to `high=0 medium=0 low=0`, and documents the checks that support that conclusion.
