# Question Bank

Use this bank to scope the audit. Ask at most five questions per round. Prefer structured multiple-choice questions when the host supports them. Otherwise ask numbered questions and wait for answers.

Do not read the entire bank to the user. Select the questions that reduce the most uncertainty. Cover every category before writing the report. When a category does not apply, record why in the report instead of skipping it silently.

## Round 1: Target and authorization

### Target

- Which repository, branch, commit, service, or artifact is in scope?
- Is the target source code, a built artifact, a running environment, or a combination?
- Which environments may be inspected: local, test, staging, or production metadata only?
- Are generated files, vendored code, and third-party modules in scope?
- Which files, directories, services, or domains are explicitly excluded?

### Authorization

- Who owns the target and who authorized this audit?
- Is the authorization limited to passive static review, or does it include active testing?
- For active testing, what is the written authorization reference, test environment, time window, and emergency contact?
- What are the stop conditions if a test could affect availability or data?
- Are there contractual, regulatory, or customer restrictions on testing or data handling?

### Objective

- Is the goal a pre-deployment gate, a due-diligence review, an incident follow-up, or a periodic assessment?
- Which decision will this report support: release, procurement, remediation planning, or certification?
- What is the acceptable residual risk, and who accepts it?
- What is the deadline and report audience?

## Round 2: Architecture and data

### Architecture

- What are the entry points, trust boundaries, and externally reachable services?
- Which languages, frameworks, runtimes, databases, queues, and infrastructure are used?
- Is there an API, web frontend, worker, CLI, mobile client, or service mesh?
- Which authentication and authorization model is used?
- Which third-party services and integrations receive or provide data?

### Data

- Which data is personal, financial, health, credential, or otherwise sensitive?
- Where is the data stored, transmitted, logged, backed up, and retained?
- Which data must never leave the environment?
- Is production data present in the test environment?
- Which compliance regimes apply: LGPD, GDPR, PCI DSS, HIPAA, SOC 2, ISO 27001, or internal policy?

### Threat model

- Who are the relevant attackers: unauthenticated internet, authenticated user, insider, partner, or supply chain?
- Which assets matter most: credentials, customer data, admin functions, availability, or integrity?
- Which attack paths are most plausible for this product?
- Which past incidents, near misses, or known weaknesses should guide the review?
- Are there business-logic abuses that do not look like classic vulnerabilities?

## Round 3: Checks and evidence

### Static analysis

- Are SAST, secret scanning, dependency scanning, container scanning, or IaC scanning tools already installed?
- Which tool versions and configurations should be used?
- Are there existing suppressions, baseline files, or accepted risks?
- May the audit run read-only scanners that write cache or report files?
- Which checks must not run because of licensing, network, or data restrictions?

### Manual review

- Which modules are highest risk and deserve deep manual review?
- Which authentication, authorization, payment, upload, and admin paths are critical?
- Which dependency or vendor components are trusted without review?
- Which configuration and deployment files are authoritative?
- Which security controls are claimed but not documented?

### Evidence handling

- Where may evidence be stored, and for how long?
- Which data must be redacted before it appears in the report?
- Who may receive the report?
- Is a machine-readable result required in addition to Markdown?
- Should the report include proof-of-concept requests, or only sanitized reproductions?

## Round 4: Remediation and readiness

### Remediation

- Who owns remediation for each system or team?
- What is the target timeline for High, Medium, and Low findings?
- Are fixes expected in this engagement or only recommendations?
- Which changes require change-management approval?
- Are compensating controls acceptable when a fix is delayed?

### Readiness

- What is the deployment decision this audit must support?
- Which findings block release, and which can be accepted with conditions?
- Who accepts residual risk?
- What evidence is required to prove a finding is fixed?
- When will the next audit or retest happen?

### Reporting

- Which language and format should the report use? The default is English Markdown.
- Should the report include an executive summary for non-technical stakeholders?
- Are CVSS vectors and CWE mappings required for every finding?
- Should the report include a remediation backlog with priorities and owners?
- Are there branding, confidentiality, or distribution restrictions?

## Decision rules

- Prefer evidence over assumptions. Replace "looks vulnerable" with a data flow, a line, and a reproducible observation.
- When the user does not know, propose two or three concrete options with trade-offs and ask the user to choose.
- When the user delegates a decision, record it as an assumption and ask for approval before the report is finalized.
- Do not run active tests without written authorization and an isolated environment.
- Do not infer authorization from repository ownership or from a general request to "check security".
- Do not ask about tools before the target, authorization, and data sensitivity are clear.
- Do not repeat a question that the repository or a previous answer already answers.
- Stop when the remaining questions would not change the scope, evidence plan, severity, or readiness verdict.

## Minimum coverage before writing the report

Record an answer or an explicit non-applicability note for:

- target, revision, and environments;
- authorization mode and limits;
- exclusions and data-handling restrictions;
- architecture, entry points, and trust boundaries;
- sensitive data and compliance;
- threat model and attacker profiles;
- tools available and checks performed;
- checks that could not run and why;
- manual review areas;
- severity calibration and acceptance criteria;
- remediation ownership and timeline;
- deployment-readiness decision and residual-risk owner;
- report audience and distribution.
