# Scanner Baseline

Use this reference to collect non-destructive evidence. Prefer tools already installed in the environment. Do not install packages, run auto-fix, upload results, or enable telemetry without user approval.

## Safety rules

- Run only against the approved target and revision.
- Use report-only modes. Never use `--fix`, `--write`, or a command that edits application code.
- Avoid commands that contact external services unless the scope allows network access.
- Do not pipe secrets or customer data into logs, tickets, or chat.
- Record the tool version, command, exit code, and artifact path.
- If a tool writes cache files, keep them inside the workspace and list them in the report.
- If the tool is unavailable, record the gap and use the manual checklist instead.
- A scanner result is a lead. Confirm reachability and data flow before marking a finding as confirmed.

## Repository inventory

```bash
git status --short
git rev-parse HEAD
git ls-files
find . -maxdepth 3 -type f \( -name "package.json" -o -name "pom.xml" -o -name "build.gradle*" -o -name "requirements*.txt" -o -name "pyproject.toml" -o -name "go.mod" -o -name "composer.json" -o -name "Gemfile" -o -name "Cargo.toml" \) -print
```

Use the inventory to identify languages, frameworks, lockfiles, and build systems before choosing scanners.

## Dependency scanning

### JavaScript and TypeScript

```bash
npm audit --json
pnpm audit --json
yarn npm audit --json
```

Record the lockfile version, advisory IDs, installed versions, and fixed versions.

### Python

```bash
pip-audit --format json
pip-audit -r requirements.txt --format json
safety check --json
```

Do not create a new virtual environment solely to run a scanner without approval.

### Java and Maven

```bash
mvn -q org.owasp:dependency-check-maven:check
mvn -q dependency:tree
gradle dependencyInsight --dependency <name>
```

If the plugin is not available locally, record the gap instead of downloading it without approval.

### Go

```bash
go list -m all
govulncheck ./...
```

### PHP

```bash
composer audit --format=json
```

### Ruby

```bash
bundle audit check --update
```

### .NET

```bash
dotnet list package --vulnerable --include-transitive
```

## SAST and code review

### Semgrep

```bash
semgrep --config auto --json --output semgrep.json .
semgrep --config p/owasp-top-ten --json .
```

### CodeQL

Use the project's existing CodeQL workflow or database. Do not upload results without approval.

### Bandit for Python

```bash
bandit -r . -f json -o bandit.json
```

### gosec for Go

```bash
gosec -fmt=json -out=gosec.json ./...
```

### Node.js

```bash
npx eslint . --format json
```

Do not install ESLint plugins or run network-dependent configurations without approval.

## Secret scanning

### Gitleaks

```bash
gitleaks detect --source . --report-format json --report-path gitleaks.json --no-git
gitleaks detect --source . --report-format json --report-path gitleaks.json
```

### TruffleHog

```bash
trufflehog filesystem . --json --no-update
```

### Manual checks

- Search source, configuration, tests, examples, CI, Dockerfiles, and documentation for credential-like strings.
- Review git history for removed secrets.
- Review CI logs and build artifacts.
- Check environment examples for real values.
- Check container image layers and build arguments.

Never copy a discovered secret into the report. Record the type, location, active status, and rotation status.

## Container and infrastructure scanning

### Trivy

```bash
trivy fs --format json --output trivy-fs.json .
trivy image --format json --output trivy-image.json <image>
trivy config --format json --output trivy-config.json .
```

### Grype

```bash
grype dir:. -o json
grype <image> -o json
```

### Docker configuration review

```bash
docker image inspect <image>
docker history --no-trunc <image>
docker scout cves <image>
```

If Docker is unavailable, review the Dockerfile, Compose file, and image metadata manually.

### Kubernetes and IaC

```bash
kubectl auth can-i --list
kube-score score deployment.yaml
checkov -d . --output json
tfsec .
```

Use read-only cluster access. Do not apply manifests or change cluster state.

## Configuration and platform checks

- TLS configuration and certificate chain.
- Security headers: HSTS, content security policy, frame options, content type options.
- CORS policy and allowed origins.
- Cookie flags and session configuration.
- Debug mode and stack trace exposure.
- Default accounts and sample applications.
- Backup, logging, and monitoring configuration.
- Cloud IAM policies and storage permissions.

## Evidence template

For each command, record:

```text
Tool: name and version
Command: exact command
Target: repository, revision, directory, image, or endpoint
Date: timestamp and timezone
Exit code: numeric exit code
Result: summary and artifact path
Limitations: what the command does not cover
Redaction: what was removed from the report
```

## When a tool is unavailable

Record the gap in the evidence section and use [owasp-cwe-checklist.md](owasp-cwe-checklist.md) for manual review. Do not claim that a check passed when the tool did not run.
