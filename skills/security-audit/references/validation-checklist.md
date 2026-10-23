# Validation Checklist

Use this checklist when the validator script cannot run.

## Report structure

- [ ] The file starts with `<!-- security-audit:artifact type=report version=1 -->`.
- [ ] Status, date, owner, target, audit type, report language, authorization, and deployment readiness are present.
- [ ] Every required section marker exists:
  - `summary`
  - `scope`
  - `authorization`
  - `methodology`
  - `threatmodel`
  - `findings`
  - `risk`
  - `remediation`
  - `readiness`
  - `evidence`
  - `assumptions`
  - `qa`
  - `traceability`
- [ ] No section is empty.
- [ ] The scope has explicit in-scope and out-of-scope lists, plus limits.
- [ ] The authorization section states the permitted mode and restrictions.
- [ ] The methodology mentions OWASP, CWE, CVSS, manual review, and the tools used.
- [ ] The threat model names assets, actors, and trust boundaries.
- [ ] The evidence section records commands, tools, dates, limitations, and redaction.

## Findings

- [ ] Every finding uses a marker with `id`, `severity`, `cvss`, `cwe`, `owasp`, and `status`.
- [ ] Finding IDs match `FIND-NNN`, are unique, and are in increasing order.
- [ ] Severity is `High`, `Medium`, or `Low`.
- [ ] CVSS is between 0.0 and 10.0 and matches the severity range.
- [ ] CWE matches `CWE-NNN`.
- [ ] OWASP matches `A01:2021` through `A10:2021`.
- [ ] Each finding has Severity, CVSS, CWE, OWASP, Location, Confidence, Description, Impact, Evidence, Affected code, Remediation, Verification, and References.
- [ ] The affected code block is present and redacted.
- [ ] Description, impact, evidence, remediation, and verification are substantive.
- [ ] A clean audit states that no findings were identified and documents the checks performed.
- [ ] Counts in the counts marker match the findings.
- [ ] The risk summary matches the findings.

## Remediation and traceability

- [ ] Every finding appears in the remediation plan.
- [ ] Every finding appears in the traceability table.
- [ ] The remediation plan has an owner, priority, and verification.
- [ ] The deployment readiness verdict is consistent with open findings.
- [ ] A High finding that is open prevents a `Ready` verdict.
- [ ] A Medium finding that is open produces a warning or a condition.
- [ ] Accepted risks have an owner, rationale, and expiry.

## Audit answers

- [ ] At least six question and answer pairs are present.
- [ ] The answers cover target, authorization, scope, data, threat model, tools, remediation, and readiness.
- [ ] No answer is a placeholder or an unexplained assumption.

## Safety and hygiene

- [ ] No active testing occurred without written authorization.
- [ ] No production environment was tested.
- [ ] No secret or personal data appears in the report.
- [ ] No CVE, CVSS vector, or exploit result was invented.
- [ ] Limitations and checks that did not run are documented.
- [ ] No unresolved placeholder text remains.

## Evidence

- [ ] The exact commands and tool versions are recorded.
- [ ] Exit codes and artifact paths are recorded.
- [ ] Dependency findings include advisory IDs, installed versions, and fixed versions.
- [ ] Secret findings include type, location, active status, and rotation status, but not the value.
- [ ] Configuration findings include the effective value and the secure baseline.
- [ ] The report states which checks were not performed.
