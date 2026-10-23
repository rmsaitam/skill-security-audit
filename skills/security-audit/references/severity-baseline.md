# Severity Baseline

Use three severities: High, Medium, and Low. Score each finding with CVSS v3.1 and record the vector. The score is the starting point; the report must also explain contextual impact and exploitability.

## Mapping

| Severity | CVSS 3.1 | Release decision | Typical impact |
| --- | --- | --- | --- |
| High | 7.0 to 10.0 | Block release unless an approved, time-bound exception exists | Remote code execution, privilege escalation, authentication bypass, critical data exposure |
| Medium | 4.0 to 6.9 | Fix before release or document compensating controls and a deadline | Conditional exploitation, denial of service, limited data exposure, meaningful weakening of a control |
| Low | 0.0 to 3.9 | Fix in the normal maintenance cycle | Misconfiguration, missing hardening, minor information leak, best-practice gap |

## High

Use High when an attacker can gain control, cross a privilege boundary, or access critical data with realistic preconditions.

Examples:

- unauthenticated SQL injection that can read or write sensitive tables;
- unsafe deserialization or template injection that leads to code execution;
- hardcoded production credentials with broad access in a public repository;
- missing authorization on an administrative endpoint;
- authentication bypass or session forgery;
- path traversal that exposes arbitrary files;
- server-side request forgery with access to cloud metadata credentials;
- a known critical or high CVE that is reachable in the deployed configuration.

Evidence standard:

- a concrete data flow from an untrusted source to a dangerous sink;
- the affected version or configuration;
- a sanitized reproduction or a scanner result confirmed by manual review;
- the conditions required for exploitation.

## Medium

Use Medium when exploitation depends on specific conditions or the impact is limited.

Examples:

- stored cross-site scripting that requires an authenticated victim;
- weak rate limiting on a login or password-reset endpoint;
- permissive CORS combined with credentialed sessions;
- insecure direct object reference limited to non-sensitive records;
- outdated dependency with a known medium CVE that is reachable;
- unrestricted file upload with type restrictions but no content inspection;
- denial of service through a bounded but expensive operation;
- missing audit logging for a sensitive action;
- weak password policy without a direct account-takeover path.

Evidence standard:

- the precondition that makes the issue exploitable;
- the limit on impact;
- the control that reduces likelihood or blast radius;
- the fix or compensating control.

## Low

Use Low when the issue is primarily a hardening gap or has minimal direct impact.

Examples:

- verbose error messages without secrets;
- missing security headers such as HSTS or a content security policy;
- cookie flags missing on a non-sensitive session;
- directory listing disabled only by convention;
- outdated dependency with no known exploitable path;
- excessive log detail that does not include secrets or personal data;
- missing documentation for an existing control.

Evidence standard:

- the effective configuration or code;
- why the issue is not directly exploitable;
- the secure baseline;
- the maintenance action.

## Calibration rules

- Score the vulnerability, then adjust the narrative for context. Do not change the CVSS score to match a desired release decision.
- Use the official CVSS v3.1 vector and components. Do not use a CVSS v2 or v4 vector in a v3.1 report unless the report says which version is used.
- Prefer the vendor or NVD score for dependency advisories. If the environmental score differs, record both and explain why.
- Increase severity when the target is internet-facing, handles regulated data, or has weak compensating controls.
- Decrease severity only when a verified control blocks the attack path, not when exploitation is merely inconvenient.
- A scanner result without reachability analysis is a lead. Label it `Likely` or `Needs validation`, not `Confirmed`.
- Do not report a finding twice. Group variants under one finding when the root cause and remediation are the same.
- If a finding is a false positive, mark it `false-positive`, explain the evidence, and keep it out of the open risk count.
- If a finding is accepted, mark it `accepted`, record the owner, rationale, and expiry date, and include it in the readiness conditions.
- Never downgrade a finding because a fix is hard or because the release is urgent. Record the exception instead.

## CVSS quick reference

- Attack vector: Network, Adjacent, Local, Physical.
- Attack complexity: Low or High.
- Privileges required: None, Low, or High.
- User interaction: None or Required.
- Scope: Unchanged or Changed.
- Confidentiality, integrity, availability: None, Low, or High.

The report should show the vector, for example:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

## Status values

Use one of:

- `open`: confirmed and not remediated.
- `fixed`: remediation is implemented and verification evidence is recorded.
- `accepted`: risk accepted by the named owner with a rationale and expiry.
- `false-positive`: the suspected issue is not a vulnerability; evidence is recorded.
- `needs-validation`: a lead that requires a safe reproduction or more evidence before confirmation.
