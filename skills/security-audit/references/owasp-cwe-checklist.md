# OWASP and CWE Checklist

Use this checklist during manual review. Adapt the checks to the language and architecture. A check that does not apply must be recorded as not applicable in the report scope or methodology, not silently skipped.

## OWASP Top 10:2021

### A01:2021 - Broken Access Control

- Verify authorization on every server-side action, not only in the UI.
- Test horizontal access between tenants, users, and objects.
- Test vertical access from user to administrator.
- Check direct object references for ownership validation.
- Check forced browsing to hidden routes and API endpoints.
- Verify CORS policy does not trust arbitrary origins with credentials.
- Verify file and directory access cannot escape the intended root.

Related CWE: CWE-22, CWE-284, CWE-285, CWE-352, CWE-639, CWE-862, CWE-863.

### A02:2021 - Cryptographic Failures

- Verify TLS is enforced and weak protocols and ciphers are disabled.
- Check password hashing uses a modern memory-hard algorithm with a unique salt.
- Check encryption keys are managed outside source code and rotated.
- Check random values use a cryptographically secure generator.
- Check sensitive data is not stored or transmitted in clear text.
- Check cookies use Secure, HttpOnly, and an appropriate SameSite policy.
- Check deprecated algorithms such as MD5, SHA-1, DES, and RC4 are absent.

Related CWE: CWE-261, CWE-296, CWE-310, CWE-319, CWE-321, CWE-322, CWE-326, CWE-327, CWE-328, CWE-330.

### A03:2021 - Injection

- Check SQL and NoSQL queries use parameterization or safe query builders.
- Check OS commands avoid shell interpolation and allowlists.
- Check LDAP, XPath, template, expression, and header sinks.
- Check logs are not vulnerable to log injection.
- Check output encoding for HTML, attribute, JavaScript, URL, and CSS contexts.
- Check file names and paths are normalized and validated.

Related CWE: CWE-20, CWE-74, CWE-77, CWE-78, CWE-79, CWE-89, CWE-90, CWE-91, CWE-94, CWE-943.

### A04:2021 - Insecure Design

- Check abuse cases and business-logic limits.
- Check race conditions in balances, quotas, approvals, and one-time actions.
- Check replay protection for signed requests and webhooks.
- Check trust boundaries between services.
- Check threat modeling exists for critical flows.
- Check security requirements are testable.

Related CWE: CWE-209, CWE-256, CWE-501, CWE-522, CWE-602, CWE-799, CWE-840, CWE-841.

### A05:2021 - Security Misconfiguration

- Check debug mode, stack traces, and default accounts are disabled.
- Check unnecessary features, ports, and services are removed.
- Check security headers and caching policy.
- Check cloud storage and bucket permissions.
- Check Docker and Kubernetes run as non-root with dropped capabilities.
- Check error handling does not leak internals.
- Check dependency and framework versions are supported.

Related CWE: CWE-2, CWE-11, CWE-13, CWE-16, CWE-260, CWE-315, CWE-489, CWE-526, CWE-942, CWE-1004.

### A06:2021 - Vulnerable and Outdated Components

- Inventory direct and transitive dependencies.
- Check known advisories and fixed versions.
- Check unsupported runtimes and base images.
- Check lockfiles are committed and integrity is verified.
- Check package sources and registry trust.
- Check container image scanning results.
- Check vendored code and patched forks.

Related CWE: CWE-1104, CWE-1035, CWE-937, CWE-1329, CWE-1357.

### A07:2021 - Identification and Authentication Failures

- Check credential stuffing and brute-force resistance.
- Check account lockout and rate limiting.
- Check password recovery and email verification flows.
- Check session rotation after login and privilege change.
- Check logout invalidates the session server-side.
- Check MFA enrollment and recovery are not bypassable.
- Check default and weak passwords are rejected.
- Check authentication errors do not enumerate users.

Related CWE: CWE-287, CWE-288, CWE-290, CWE-294, CWE-295, CWE-297, CWE-300, CWE-302, CWE-304, CWE-306, CWE-307, CWE-384.

### A08:2021 - Software and Data Integrity Failures

- Check deserialization of untrusted data.
- Check update and plugin mechanisms verify signatures.
- Check CI/CD artifacts and dependencies use pinned, verified sources.
- Check webhook signatures and replay protection.
- Check client-side trust decisions.
- Check auto-update and remote code loading paths.

Related CWE: CWE-345, CWE-346, CWE-353, CWE-426, CWE-494, CWE-502, CWE-565, CWE-784, CWE-829, CWE-830.

### A09:2021 - Security Logging and Monitoring Failures

- Check authentication, authorization, and administrative actions are logged.
- Check logs include actor, action, target, result, and correlation ID.
- Check secrets, tokens, passwords, and personal data are excluded from logs.
- Check log injection and log forging are prevented.
- Check alerts exist for repeated failures and high-risk actions.
- Check audit logs are protected from tampering and retention meets policy.

Related CWE: CWE-117, CWE-223, CWE-532, CWE-778.

### A10:2021 - Server-Side Request Forgery

- Check user-controlled URLs are validated against an allowlist.
- Check redirects are followed safely.
- Check cloud metadata endpoints and internal networks are blocked.
- Check DNS rebinding and time-of-check/time-of-use risks.
- Check response size and time limits.
- Check webhook and image-fetch features.

Related CWE: CWE-918, CWE-441, CWE-610.

## CWE Top 25 areas to review

| CWE | Name | Review focus |
| --- | --- | --- |
| CWE-79 | Cross-site scripting | Output encoding, framework escaping, raw HTML sinks |
| CWE-787 | Out-of-bounds write | Array indexing, buffer sizes, native parsing |
| CWE-89 | SQL injection | Parameterization, dynamic query construction |
| CWE-352 | Cross-site request forgery | State-changing requests, token validation, SameSite |
| CWE-22 | Path traversal | Normalization, allowlists, archive extraction |
| CWE-125 | Out-of-bounds read | Native parsing, length checks, serialization |
| CWE-78 | OS command injection | Shell invocation, argument handling, allowlists |
| CWE-416 | Use after free | Object lifetime, ownership, async callbacks |
| CWE-862 | Missing authorization | Server-side checks, role enforcement |
| CWE-434 | Unrestricted upload | Type, size, content, storage, execution |
| CWE-94 | Code injection | Eval, dynamic import, template compilation |
| CWE-20 | Improper input validation | Type, range, format, length, encoding |
| CWE-77 | Command injection | Process execution, shell metacharacters |
| CWE-287 | Improper authentication | Session, token, password, MFA |
| CWE-269 | Improper privilege management | Role assignment, admin paths, impersonation |
| CWE-502 | Deserialization of untrusted data | Native serializers, object graphs, gadgets |
| CWE-200 | Exposure of sensitive information | Errors, headers, logs, API responses |
| CWE-522 | Insufficiently protected credentials | Storage, transport, rotation |
| CWE-798 | Hardcoded credentials | Source, history, images, CI |
| CWE-918 | SSRF | URL fetching, allowlists, metadata access |
| CWE-119 | Buffer bounds | Native memory operations |
| CWE-476 | NULL pointer dereference | Error paths, optional values |
| CWE-121 | Stack-based buffer overflow | Fixed buffers, input length |
| CWE-190 | Integer overflow | Size calculations, arithmetic |
| CWE-400 | Uncontrolled resource consumption | Rate limits, quotas, expensive operations |

## Language-specific hot spots

### JavaScript and TypeScript

- `eval`, `new Function`, dynamic `require`, and template compilation.
- `innerHTML`, `dangerouslySetInnerHTML`, and raw HTML rendering.
- Prototype pollution through deep merge and object assignment.
- JWT verification settings, algorithm confusion, and secret strength.
- Express middleware order and missing authorization on routes.
- SSRF through fetch, axios, image proxies, and webhooks.
- Dependency confusion and postinstall scripts.

### Java and Spring

- Spring Security filter chain, method security, and `permitAll` rules.
- SpEL injection, JNDI lookup, and unsafe expression evaluation.
- Deserialization gadgets and unsafe object mappers.
- JDBC string concatenation and native query construction.
- Actuator exposure and management endpoint security.
- SSRF through RestTemplate, WebClient, and URL parsing.
- Log4j and logging configuration.

### Python

- `eval`, `exec`, `pickle`, `yaml.load`, and unsafe deserialization.
- Django and Flask template escaping and raw SQL.
- `subprocess` with `shell=True` and unvalidated arguments.
- Path traversal in file handling and archive extraction.
- Dependency and setup script supply chain.
- SSRF through requests, httpx, and URL parsers.

### PHP

- `include`, `require`, and dynamic file paths.
- `unserialize` and object injection.
- SQL concatenation and ORM raw queries.
- File upload validation and execution paths.
- Session fixation and insecure cookie settings.
- Framework debug mode and exposed admin panels.

### Go

- `text/template` versus `html/template`.
- `exec.Command` argument handling.
- Path traversal and archive extraction.
- `unsafe` pointer arithmetic.
- Race conditions detected with the race detector.
- TLS configuration and certificate verification.

### C and C++

- Bounds checks, integer overflow, signedness, and format strings.
- Use after free, double free, and ownership.
- Stack and heap buffers.
- Uninitialized memory and error paths.
- Parsing of untrusted binary formats.
- Build hardening flags and sanitizers.

### SQL and data stores

- Parameterization, least privilege, and row-level security.
- Stored procedure permissions.
- NoSQL operator injection.
- Backup encryption and access control.
- Migration scripts and seed data with credentials.

### Docker, Kubernetes, and IaC

- Root user, privileged mode, capabilities, and host mounts.
- Secrets in images, environment variables, and manifests.
- Exposed ports and management interfaces.
- Network policies and service-to-service authorization.
- Image provenance, signing, and scanning.
- Terraform state and cloud IAM permissions.
