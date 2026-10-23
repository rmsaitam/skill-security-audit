from __future__ import annotations

import json
import re
from textwrap import dedent

import pytest

from validate_report import (
    main,
    metadata_value,
    nonempty_content_lines,
    parse_attributes,
    parse_cvss,
    section_bodies,
    split_list,
    validate_files,
    validate_texts,
)


VALID_REPORT = dedent(
    """\
    <!-- security-audit:artifact type=report version=1 -->
    # Security Audit: Example Service

    - Status: Final
    - Date: 2026-01-01
    - Owner: Security team
    - Target: example-service at commit abc123
    - Audit type: Static and manual review
    - Report language: English
    - Authorization: Passive static review only; no active exploitation.
    - Deployment readiness: Ready with conditions

    <!-- security-audit:section id=summary -->
    ## 1. Executive Summary

    The service exposes an authenticated API backed by PostgreSQL.
    One High and one Medium finding were identified.

    <!-- security-audit:counts high=1 medium=1 low=0 -->

    <!-- security-audit:section id=scope -->
    ## 2. Scope

    ### In scope

    - API source code in src/.
    - Dependency manifests and container configuration.

    ### Out of scope

    - Production infrastructure and third-party services.

    ### Limits

    - No dynamic testing or exploitation was performed.

    <!-- security-audit:section id=authorization -->
    ## 3. Authorization and Rules of Engagement

    - Passive static review only.
    - No active testing was requested or performed.

    <!-- security-audit:section id=methodology -->
    ## 4. Methodology

    - OWASP Top 10:2021 review.
    - CWE Top 25 manual review.
    - CVSS v3.1 scoring.
    - SAST and dependency audit with available tools.
    - Manual review of authentication, authorization, and input validation.

    <!-- security-audit:section id=threatmodel -->
    ## 5. Threat Model

    ### Assets

    - User credentials and audit records.

    ### Actors

    - Unauthenticated internet users and authenticated operators.

    ### Trust boundaries

    - Browser to API and API to database.

    ### Relevant attack paths

    - Credential stuffing and injection through the search endpoint.

    <!-- security-audit:section id=findings -->
    ## 6. Findings

    <!-- security-audit:finding id=FIND-001 severity=high cvss=9.8 cwe=CWE-89 owasp=A03:2021 status=open -->
    ### FIND-001: SQL injection in user search

    - Severity: High
    - CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    - CWE: CWE-89
    - OWASP: A03:2021 - Injection
    - Location: src/users/repository.ts:42
    - Confidence: Confirmed
    - Description: User input is concatenated directly into a SQL query.
    - Impact: An attacker can read or modify arbitrary database records.
    - Evidence: The query string includes the raw search parameter without binding.
    - Affected code:
    ```ts
    const sql = `SELECT * FROM users WHERE name = '${name}'`;
    ```
    - Remediation: Use parameterized queries and validate the search input.
    - Verification: Add a regression test with a malicious payload and rerun SAST.
    - References: CWE-89 and OWASP A03:2021.

    <!-- security-audit:finding id=FIND-002 severity=medium cvss=5.3 cwe=CWE-307 owasp=A07:2021 status=open -->
    ### FIND-002: Missing login rate limiting

    - Severity: Medium
    - CVSS: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
    - CWE: CWE-307
    - OWASP: A07:2021 - Identification and Authentication Failures
    - Location: src/auth/login.ts:88
    - Confidence: Confirmed
    - Description: The login endpoint accepts unlimited attempts per account.
    - Impact: An attacker can perform credential stuffing and password guessing.
    - Evidence: Manual review found no counter, lockout, or rate-limit middleware.
    - Affected code:
    ```ts
    app.post('/login', authenticate);
    ```
    - Remediation: Add per-account and per-IP rate limiting with lockout alerts.
    - Verification: Run a load test and confirm throttling after the threshold.
    - References: CWE-307 and OWASP A07:2021.

    <!-- security-audit:section id=risk -->
    ## 7. Risk Summary

    | Severity | Total | Open | Fixed | Accepted | Notes |
    | --- | --- | --- | --- | --- | --- |
    | High | 1 | 1 | 0 | 0 | Must be resolved before production. |
    | Medium | 1 | 1 | 0 | 0 | Resolve before production or document a control. |
    | Low | 0 | 0 | 0 | 0 | Address in the maintenance cycle. |

    <!-- security-audit:section id=remediation -->
    ## 8. Remediation Plan

    | Finding | Priority | Action | Owner | Verification |
    | --- | --- | --- | --- | --- |
    | FIND-001 | P1 | Replace concatenation with parameterized queries. | Application team | Regression test and SAST rescan. |
    | FIND-002 | P2 | Add rate limiting and account lockout with monitoring. | Platform team | Load test and configuration review. |

    <!-- security-audit:section id=readiness -->
    ## 9. Deployment Readiness

    The service is ready with conditions: resolve the High finding before release.

    - [ ] Every High finding is fixed or has an approved, time-bound exception.
    - [ ] Every Medium finding is fixed or has compensating controls.
    - [x] Authentication and authorization paths were reviewed.
    - [x] Dependency and secret scans were run.
    - [x] Logging and monitoring were reviewed.
    - [x] Remediation owners and target dates are recorded.

    <!-- security-audit:section id=evidence -->
    ## 10. Evidence

    - Tool: semgrep 1.50.0.
    - Command: semgrep --config p/owasp-top-ten --json .
    - Target: example-service at commit abc123.
    - Date: 2026-01-01, UTC.
    - Limitations: no dynamic testing; scanner output was reviewed manually.
    - Redaction: secrets and personal data were removed.

    <!-- security-audit:section id=assumptions -->
    ## 11. Assumptions and Open Questions

    - The audited revision matches commit abc123.
    - No production data was accessed during the review.

    <!-- security-audit:section id=qa -->
    ## 12. Audit Answers

    ### Q-001

    - Question: Which repository and revision are in scope?
    - Answer: The example-service repository at commit abc123.

    ### Q-002

    - Question: What authorization applies to this audit?
    - Answer: Passive static review only; no active testing is authorized.

    ### Q-003

    - Question: Which components are excluded?
    - Answer: Production infrastructure and third-party services are excluded.

    ### Q-004

    - Question: Which data is sensitive?
    - Answer: User credentials and audit records are sensitive.

    ### Q-005

    - Question: Which tools were available?
    - Answer: Semgrep and the package manager audit command were available.

    ### Q-006

    - Question: What deployment decision does this report support?
    - Answer: Release readiness with the High finding resolved first.

    <!-- security-audit:section id=traceability -->
    ## 13. Traceability

    | Finding | Evidence | Remediation | Status |
    | --- | --- | --- | --- |
    | FIND-001 | Section 10, semgrep output and manual data-flow review. | Section 8, parameterized queries. | Open |
    | FIND-002 | Section 10, manual review of the login path. | Section 8, rate limiting and lockout. | Open |
    """
)


def clean_report() -> str:
    text = re.sub(
        r"<!-- security-audit:finding.*?(?=<!-- security-audit:section id=risk -->)",
        "",
        VALID_REPORT,
        flags=re.S,
    )
    text = text.replace("<!-- security-audit:counts high=1 medium=1 low=0 -->", "<!-- security-audit:counts high=0 medium=0 low=0 -->")
    text = text.replace(
        "## 6. Findings\n\n",
        "## 6. Findings\n\nNo findings were identified. The checks in the methodology were performed.\n\n",
    )
    text = re.sub(r"\| FIND-00[12] \|.*?\n", "", text)
    text = text.replace(
        "- [ ] Every High finding is fixed or has an approved, time-bound exception.",
        "- [x] No High findings are open.",
    )
    text = text.replace(
        "- [ ] Every Medium finding is fixed or has compensating controls.",
        "- [x] No Medium findings are open.",
    )
    text = text.replace("One High and one Medium finding were identified.", "No findings were identified.")
    text = text.replace("Ready with conditions", "Ready")
    return text


def codes(report) -> set[str]:
    return {issue.code for issue in report.errors}


def test_valid_report_passes() -> None:
    report = validate_texts(VALID_REPORT)
    assert report.ok, [issue.message for issue in report.errors]
    assert report.stats["findings_total"] == 2
    assert report.stats["high"] == 1
    assert report.stats["open_high"] == 1
    assert report.stats["interview_questions"] == 6
    assert not report.warnings


def test_valid_report_with_min_findings() -> None:
    report = validate_texts(VALID_REPORT, min_findings=2)
    assert report.ok


def test_clean_report_passes() -> None:
    report = validate_texts(clean_report())
    assert report.ok, [issue.message for issue in report.errors]
    assert report.stats["findings_total"] == 0


def test_clean_report_fails_min_findings() -> None:
    report = validate_texts(clean_report(), min_findings=1)
    assert "insufficient-findings" in codes(report)


def test_clean_report_requires_no_findings_statement() -> None:
    text = clean_report().replace("No findings were identified. The checks in the methodology were performed.", "")
    report = validate_texts(text)
    assert "empty-findings" in codes(report)


def test_missing_artifact_marker() -> None:
    text = VALID_REPORT.replace("<!-- security-audit:artifact type=report version=1 -->", "")
    report = validate_texts(text)
    assert "missing-artifact-marker" in codes(report)


def test_wrong_artifact_type() -> None:
    text = VALID_REPORT.replace("type=report", "type=prd")
    report = validate_texts(text)
    assert "wrong-artifact-type" in codes(report)


def test_artifact_version_warning() -> None:
    text = VALID_REPORT.replace("version=1", "version=2")
    report = validate_texts(text)
    assert "artifact-version" in {issue.code for issue in report.warnings}


def test_missing_metadata() -> None:
    text = VALID_REPORT.replace("- Status: Final\n", "")
    report = validate_texts(text)
    assert "missing-metadata" in codes(report)


def test_invalid_date() -> None:
    text = VALID_REPORT.replace("- Date: 2026-01-01", "- Date: 01/01/2026")
    report = validate_texts(text)
    assert "invalid-date" in codes(report)


def test_non_english_report_warns() -> None:
    text = VALID_REPORT.replace("- Report language: English", "- Report language: Portuguese")
    report = validate_texts(text)
    assert "report-language" in {issue.code for issue in report.warnings}


def test_invalid_readiness() -> None:
    text = VALID_REPORT.replace("- Deployment readiness: Ready with conditions", "- Deployment readiness: Maybe")
    report = validate_texts(text)
    assert "invalid-readiness" in codes(report)


def test_missing_authorization_value() -> None:
    text = VALID_REPORT.replace(
        "- Authorization: Passive static review only; no active exploitation.",
        "- Authorization: None",
    )
    report = validate_texts(text)
    assert "missing-authorization" in codes(report)


def test_missing_section() -> None:
    text = VALID_REPORT.replace("section id=evidence", "section id=evidencex")
    report = validate_texts(text)
    assert "missing-section" in codes(report)


def test_thin_section() -> None:
    text = VALID_REPORT.replace(
        "- Tool: semgrep 1.50.0.\n"
        "- Command: semgrep --config p/owasp-top-ten --json .\n"
        "- Target: example-service at commit abc123.\n"
        "- Date: 2026-01-01, UTC.\n"
        "- Limitations: no dynamic testing; scanner output was reviewed manually.\n"
        "- Redaction: secrets and personal data were removed.\n",
        "- Short.\n",
    )
    report = validate_texts(text)
    assert "thin-section" in codes(report)


def test_missing_scope_subsections() -> None:
    text = VALID_REPORT.replace("### In scope", "### Included")
    report = validate_texts(text)
    assert "missing-in-scope" in codes(report)


def test_methodology_missing_term() -> None:
    text = VALID_REPORT.replace("- OWASP Top 10:2021 review.", "- OWAS review.")
    report = validate_texts(text)
    assert "methodology-missing-term" in codes(report)


def test_thin_threatmodel() -> None:
    text = VALID_REPORT.replace("### Assets", "### Things").replace("### Actors", "### People")
    report = validate_texts(text)
    assert "thin-threatmodel" in codes(report)


def test_evidence_missing_limitations() -> None:
    text = VALID_REPORT.replace("- Limitations: no dynamic testing; scanner output was reviewed manually.", "- Notes: review completed.")
    report = validate_texts(text)
    assert "missing-limitations" in codes(report)


def test_invalid_finding_id() -> None:
    text = VALID_REPORT.replace("id=FIND-001", "id=FIND-1")
    report = validate_texts(text)
    assert "invalid-finding-id" in codes(report)


def test_duplicate_finding_id() -> None:
    text = VALID_REPORT.replace("id=FIND-002", "id=FIND-001")
    report = validate_texts(text)
    assert "duplicate-finding-id" in codes(report)


def test_finding_order() -> None:
    text = VALID_REPORT.replace("id=FIND-002", "id=FIND-000")
    report = validate_texts(text)
    assert "finding-order" in codes(report)


def test_finding_gap_warning() -> None:
    text = VALID_REPORT.replace("FIND-002", "FIND-003")
    report = validate_texts(text)
    assert "finding-gap" in {issue.code for issue in report.warnings}


def test_invalid_severity() -> None:
    text = VALID_REPORT.replace("severity=high", "severity=urgent")
    report = validate_texts(text)
    assert "invalid-severity" in codes(report)


def test_invalid_cvss() -> None:
    text = VALID_REPORT.replace("cvss=9.8", "cvss=abc")
    report = validate_texts(text)
    assert "invalid-cvss" in codes(report)


def test_cvss_out_of_range() -> None:
    text = VALID_REPORT.replace("cvss=9.8", "cvss=11.0")
    report = validate_texts(text)
    assert "cvss-out-of-range" in codes(report)


def test_cvss_marker_requires_score() -> None:
    text = VALID_REPORT.replace("cvss=9.8", "cvss=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    report = validate_texts(text)
    assert "invalid-cvss" in codes(report)


def test_severity_cvss_mismatch() -> None:
    text = VALID_REPORT.replace("severity=high cvss=9.8", "severity=high cvss=5.3")
    report = validate_texts(text)
    assert "severity-cvss-mismatch" in codes(report)


def test_missing_cwe() -> None:
    text = VALID_REPORT.replace(" cwe=CWE-89", "")
    report = validate_texts(text)
    assert "missing-cwe" in codes(report)


def test_invalid_cwe() -> None:
    text = VALID_REPORT.replace("cwe=CWE-89", "cwe=89")
    report = validate_texts(text)
    assert "invalid-cwe" in codes(report)


def test_invalid_owasp() -> None:
    text = VALID_REPORT.replace("owasp=A03:2021", "owasp=A03:2020")
    report = validate_texts(text)
    assert "invalid-owasp" in codes(report)


def test_missing_status() -> None:
    text = VALID_REPORT.replace(" status=open", "", 1)
    report = validate_texts(text)
    assert "missing-status" in codes(report)


def test_invalid_status() -> None:
    text = VALID_REPORT.replace("status=open", "status=resolved", 1)
    report = validate_texts(text)
    assert "invalid-status" in codes(report)


def test_missing_description() -> None:
    text = VALID_REPORT.replace(
        "- Description: User input is concatenated directly into a SQL query.",
        "- Description: Short.",
    )
    report = validate_texts(text)
    assert "missing-description" in codes(report)


def test_missing_field() -> None:
    text = VALID_REPORT.replace(
        "- Impact: An attacker can read or modify arbitrary database records.\n",
        "",
    )
    report = validate_texts(text)
    assert "missing-impact" in codes(report)


def test_invalid_confidence() -> None:
    text = VALID_REPORT.replace("- Confidence: Confirmed", "- Confidence: Maybe", 1)
    report = validate_texts(text)
    assert "invalid-confidence" in codes(report)


def test_missing_code_block() -> None:
    text = VALID_REPORT.replace(
        "```ts\nconst sql = `SELECT * FROM users WHERE name = '${name}'`;\n```\n",
        "No code block provided.\n",
    )
    report = validate_texts(text)
    assert "missing-code-block" in codes(report)


def test_marker_field_mismatch_warnings() -> None:
    text = VALID_REPORT
    text = text.replace("- Severity: High", "- Severity: Low", 1)
    text = text.replace("- CVSS: 9.8 (", "- CVSS: 9.0 (", 1)
    text = text.replace("- CWE: CWE-89", "- CWE: CWE-79", 1)
    text = text.replace("- OWASP: A03:2021 - Injection", "- OWASP: A07:2021 - Injection", 1)
    report = validate_texts(text)
    warning_codes = {issue.code for issue in report.warnings}
    assert {"severity-mismatch", "cvss-mismatch", "cwe-mismatch", "owasp-mismatch"} <= warning_codes


def test_counts_mismatch() -> None:
    text = VALID_REPORT.replace("counts high=1", "counts high=2")
    report = validate_texts(text)
    assert "counts-mismatch" in codes(report)


def test_missing_counts() -> None:
    text = VALID_REPORT.replace("<!-- security-audit:counts high=1 medium=1 low=0 -->", "")
    report = validate_texts(text)
    assert "missing-counts" in codes(report)


def test_invalid_count() -> None:
    text = VALID_REPORT.replace("counts high=1", "counts high=x")
    report = validate_texts(text)
    assert "invalid-count" in codes(report)


def test_negative_count() -> None:
    text = VALID_REPORT.replace("counts high=1", "counts high=-1")
    report = validate_texts(text)
    assert "invalid-count" in codes(report)


def test_remediation_gap() -> None:
    text = VALID_REPORT.replace(
        "| FIND-002 | P2 | Add rate limiting and account lockout with monitoring. | Platform team | Load test and configuration review. |\n",
        "",
    )
    report = validate_texts(text)
    assert "remediation-gap" in codes(report)


def test_traceability_gap() -> None:
    text = VALID_REPORT.replace(
        "| FIND-002 | Section 10, manual review of the login path. | Section 8, rate limiting and lockout. | Open |\n",
        "",
    )
    report = validate_texts(text)
    assert "traceability-gap" in codes(report)


def test_thin_readiness() -> None:
    text = VALID_REPORT.replace("- [x] Authentication and authorization paths were reviewed.\n", "")
    text = text.replace("- [x] Dependency and secret scans were run.\n", "")
    text = text.replace("- [x] Logging and monitoring were reviewed.\n", "")
    report = validate_texts(text)
    assert "thin-readiness" in codes(report)


def test_risk_missing_severity() -> None:
    text = VALID_REPORT.replace("| Medium | 1 | 1 | 0 | 0 |", "| Moderate | 1 | 1 | 0 | 0 |")
    report = validate_texts(text)
    assert "risk-missing-severity" in codes(report)


def test_insufficient_questions() -> None:
    text = VALID_REPORT.replace("### Q-006", "### Q-6")
    report = validate_texts(text)
    assert "insufficient-questions" in codes(report)


def test_duplicate_question() -> None:
    text = VALID_REPORT.replace("### Q-006", "### Q-005")
    report = validate_texts(text)
    assert "duplicate-question" in codes(report)


def test_placeholder_rejected() -> None:
    text = VALID_REPORT + "\nTODO: remove this line.\n"
    report = validate_texts(text)
    assert "placeholder" in codes(report)


def test_unredacted_secret_rejected() -> None:
    text = VALID_REPORT + "\nAKIAIOSFODNN7EXAMPLE\n"
    report = validate_texts(text)
    assert "unredacted-secret" in codes(report)


def test_active_audit_requires_written_authorization() -> None:
    text = VALID_REPORT.replace("- Audit type: Static and manual review", "- Audit type: Active testing")
    report = validate_texts(text)
    assert "missing-written-authorization" in codes(report)


def test_active_audit_cannot_target_production() -> None:
    text = VALID_REPORT.replace("- Audit type: Static and manual review", "- Audit type: Active testing in production")
    text = text.replace(
        "- No active testing was requested or performed.",
        "- Active testing is authorized by written authorization.",
    )
    report = validate_texts(text)
    assert "production-active-test" in codes(report)


def test_high_finding_blocks_ready_verdict() -> None:
    text = VALID_REPORT.replace("Ready with conditions", "Ready")
    report = validate_texts(text)
    assert "readiness-contradiction" in codes(report)


def test_medium_finding_ready_verdict_warns() -> None:
    text = VALID_REPORT.replace("Ready with conditions", "Ready")
    text = text.replace("id=FIND-001 severity=high cvss=9.8", "id=FIND-001 severity=high cvss=9.8", 1)
    text = text.replace("status=open", "status=fixed", 1)
    report = validate_texts(text)
    assert report.ok, [issue.message for issue in report.errors]
    assert "readiness-condition" in {issue.code for issue in report.warnings}


def test_validate_files_missing() -> None:
    report = validate_files(__import__("pathlib").Path("/nonexistent/SECURITY-AUDIT.md"))
    assert "missing-file" in codes(report)


def test_cli_pass(tmp_path, capsys) -> None:
    path = tmp_path / "SECURITY-AUDIT.md"
    path.write_text(VALID_REPORT, encoding="utf-8")
    assert main([str(path)]) == 0
    captured = capsys.readouterr()
    assert "PASS" in captured.out


def test_cli_json_pass(tmp_path, capsys) -> None:
    path = tmp_path / "SECURITY-AUDIT.md"
    path.write_text(VALID_REPORT, encoding="utf-8")
    assert main([str(path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "pass"
    assert payload["stats"]["findings_total"] == 2


def test_cli_fail_on_missing_file(capsys) -> None:
    assert main(["/nonexistent/SECURITY-AUDIT.md"]) == 1
    assert "missing-file" in capsys.readouterr().err


def test_cli_strict_fails_on_warning(tmp_path, capsys) -> None:
    path = tmp_path / "SECURITY-AUDIT.md"
    path.write_text(VALID_REPORT.replace("FIND-002", "FIND-003"), encoding="utf-8")
    assert main([str(path), "--strict"]) == 1
    assert "finding-gap" in capsys.readouterr().err


def test_cli_invalid_arguments() -> None:
    with pytest.raises(SystemExit):
        main(["--min-findings", "-1"])
    with pytest.raises(SystemExit):
        main(["--min-questions", "-1"])


def test_helpers() -> None:
    attributes = parse_attributes('id=FIND-001 severity="high" status=open')
    assert attributes == {"id": "FIND-001", "severity": "high", "status": "open"}
    assert split_list("A, B ,C") == ["A", "B", "C"]
    assert split_list("none") == []
    assert parse_cvss("9.8 (CVSS:3.1/AV:N)") == 9.8
    assert parse_cvss("not-a-score") is None
    assert metadata_value(VALID_REPORT, "Owner") == "Security team"
    sections = section_bodies(VALID_REPORT)
    assert "summary" in sections
    assert nonempty_content_lines("## Heading\n\n- item\n") == ["- item"]
