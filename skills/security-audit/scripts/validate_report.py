#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


ARTIFACT_MARKER_RE = re.compile(r"<!--\s*security-audit:artifact\s+([^>]*?)-->")
SECTION_MARKER_RE = re.compile(r"<!--\s*security-audit:section\s+([^>]*?)-->")
FINDING_MARKER_RE = re.compile(r"<!--\s*security-audit:finding\s+([^>]*?)-->")
COUNTS_MARKER_RE = re.compile(r"<!--\s*security-audit:counts\s+([^>]*?)-->")
ATTRIBUTE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)=(\"[^\"]*\"|'[^']*'|[^\s]+)")
FINDING_ID_RE = re.compile(r"^FIND-(\d{3})$")
QUESTION_RE = re.compile(r"(?m)^###\s+Q-(\d{3})\s*$")
CHECKBOX_RE = re.compile(r"(?m)^\s*-\s*\[[ xX]\]")
CODE_BLOCK_RE = re.compile(r"(?ms)^```[^\n]*\n.*?^```\s*$")
PLACEHOLDER_RE = re.compile(
    r"\b(?:TODO|TBD|FIXME)\b|\[insert\b|<insert\b|\[placeholder\b|<placeholder\b",
    re.IGNORECASE,
)
CWE_RE = re.compile(r"^CWE-\d{1,4}$")
OWASP_RE = re.compile(r"^A(?:0[1-9]|10):2021$")
CVSS_VALUE_RE = re.compile(r"\b(\d{1,2}(?:\.\d)?)\b")
CVSS_SCORE_RE = re.compile(r"\d{1,2}(?:\.\d)?")
TITLE_RE = re.compile(r"(?m)^#{2,4}\s+(.+?)\s*$")
SECRET_PATTERNS = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)
FIELD_PATTERNS = {
    "severity": re.compile(r"(?mi)^\s*-\s*Severity:\s*(.+?)\s*$"),
    "cvss": re.compile(r"(?mi)^\s*-\s*CVSS:\s*(.+?)\s*$"),
    "cwe": re.compile(r"(?mi)^\s*-\s*CWE:\s*(.+?)\s*$"),
    "owasp": re.compile(r"(?mi)^\s*-\s*OWASP:\s*(.+?)\s*$"),
    "location": re.compile(r"(?mi)^\s*-\s*Location:\s*(.+?)\s*$"),
    "confidence": re.compile(r"(?mi)^\s*-\s*Confidence:\s*(.+?)\s*$"),
    "description": re.compile(r"(?mi)^\s*-\s*Description:\s*(.+?)\s*$"),
    "impact": re.compile(r"(?mi)^\s*-\s*Impact:\s*(.+?)\s*$"),
    "evidence": re.compile(r"(?mi)^\s*-\s*Evidence:\s*(.+?)\s*$"),
    "affected_code": re.compile(r"(?mi)^\s*-\s*Affected code:\s*(.*?)\s*$"),
    "remediation": re.compile(r"(?mi)^\s*-\s*Remediation:\s*(.+?)\s*$"),
    "verification": re.compile(r"(?mi)^\s*-\s*Verification:\s*(.+?)\s*$"),
    "references": re.compile(r"(?mi)^\s*-\s*References:\s*(.+?)\s*$"),
}
FIELD_MIN_LENGTHS = {
    "location": 3,
    "confidence": 4,
    "description": 20,
    "impact": 20,
    "evidence": 10,
    "remediation": 15,
    "verification": 10,
    "references": 5,
}

REPORT_REQUIRED_SECTIONS = (
    "summary",
    "scope",
    "authorization",
    "methodology",
    "threatmodel",
    "findings",
    "risk",
    "remediation",
    "readiness",
    "evidence",
    "assumptions",
    "qa",
    "traceability",
)
MIN_CONTENT_LINES = {
    "summary": 2,
    "scope": 4,
    "authorization": 2,
    "methodology": 4,
    "threatmodel": 4,
    "findings": 1,
    "risk": 3,
    "remediation": 2,
    "readiness": 4,
    "evidence": 4,
    "assumptions": 1,
    "qa": 1,
    "traceability": 2,
}
METADATA_FIELDS = (
    "Status",
    "Date",
    "Owner",
    "Target",
    "Audit type",
    "Report language",
    "Authorization",
    "Deployment readiness",
)
ALLOWED_SEVERITIES = ("high", "medium", "low")
ALLOWED_STATUSES = ("open", "fixed", "accepted", "false-positive", "needs-validation")
ALLOWED_CONFIDENCE = ("confirmed", "likely", "needs-validation")
ALLOWED_READINESS = ("ready", "ready with conditions", "not ready")
SEVERITY_RANGES = {
    "high": (7.0, 10.0),
    "medium": (4.0, 6.9),
    "low": (0.0, 3.9),
}


@dataclass
class Issue:
    level: str
    code: str
    message: str
    location: str = ""


@dataclass
class Report:
    errors: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    stats: dict[str, object] = field(default_factory=dict)

    def error(self, code: str, message: str, location: str = "") -> None:
        self.errors.append(Issue("error", code, message, location))

    def warning(self, code: str, message: str, location: str = "") -> None:
        self.warnings.append(Issue("warning", code, message, location))

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "pass" if self.ok else "fail",
            "stats": self.stats,
            "errors": [issue.__dict__ for issue in self.errors],
            "warnings": [issue.__dict__ for issue in self.warnings],
        }


@dataclass
class Finding:
    finding_id: str
    attributes: dict[str, str]
    body: str
    title: str
    fields: dict[str, str]
    has_code_block: bool


def parse_attributes(raw: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for match in ATTRIBUTE_RE.finditer(raw):
        key = match.group(1).lower()
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        attributes[key] = value.strip()
    return attributes


def split_list(value: str) -> list[str]:
    normalized = value.strip()
    if not normalized or normalized.lower() in {"none", "n/a", "na", "-"}:
        return []
    return [item.strip() for item in normalized.split(",") if item.strip()]


def strip_fenced_code(text: str) -> str:
    return re.sub(r"(?ms)^```.*?^```\s*$", "", text)


def strip_comments(text: str) -> str:
    return re.sub(r"(?s)<!--.*?-->", "", text)


def marker_positions(text: str, pattern: re.Pattern[str]) -> list[tuple[int, int, dict[str, str]]]:
    matches: list[tuple[int, int, dict[str, str]]] = []
    for match in pattern.finditer(text):
        matches.append((match.start(), match.end(), parse_attributes(match.group(1))))
    return matches


def section_bodies(text: str) -> dict[str, str]:
    markers = marker_positions(text, SECTION_MARKER_RE)
    bodies: dict[str, str] = {}
    for index, (_, end, attributes) in enumerate(markers):
        section_id = attributes.get("id", "")
        next_start = markers[index + 1][0] if index + 1 < len(markers) else len(text)
        bodies[section_id] = text[end:next_start]
    return bodies


def nonempty_content_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r"<!--.*?-->", line):
            continue
        if line.startswith("#"):
            continue
        lines.append(line)
    return lines


def metadata_value(text: str, label: str) -> str:
    match = re.search(rf"(?mi)^\s*-\s*{re.escape(label)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else ""


def parse_cvss(value: str) -> float | None:
    match = CVSS_VALUE_RE.search(value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def parse_findings(text: str) -> list[Finding]:
    markers = marker_positions(text, FINDING_MARKER_RE)
    sections = marker_positions(text, SECTION_MARKER_RE)
    boundaries = sorted([position for position, _, _ in markers + sections])
    findings: list[Finding] = []
    for _, end, attributes in markers:
        next_start = next((position for position in boundaries if position >= end), len(text))
        body = text[end:next_start]
        title_match = TITLE_RE.search(body)
        title = title_match.group(1).strip() if title_match else ""
        fields: dict[str, str] = {}
        for name, pattern in FIELD_PATTERNS.items():
            match = pattern.search(body)
            fields[name] = match.group(1).strip() if match else ""
        findings.append(
            Finding(
                finding_id=attributes.get("id", ""),
                attributes=attributes,
                body=body,
                title=title,
                fields=fields,
                has_code_block=bool(CODE_BLOCK_RE.search(body)),
            )
        )
    return findings


def parse_counts(text: str, report: Report) -> dict[str, int] | None:
    marker = COUNTS_MARKER_RE.search(text)
    if not marker:
        report.error(
            "missing-counts",
            "SECURITY-AUDIT.md is missing the security-audit:counts marker.",
            "SECURITY-AUDIT.md",
        )
        return None
    attributes = parse_attributes(marker.group(1))
    counts: dict[str, int] = {}
    for severity in ALLOWED_SEVERITIES:
        raw = attributes.get(severity)
        if raw is None:
            report.error(
                "missing-count",
                f"Counts marker is missing {severity}.",
                "SECURITY-AUDIT.md",
            )
            continue
        try:
            value = int(raw)
        except ValueError:
            report.error(
                "invalid-count",
                f"Counts marker has a non-integer {severity} value: {raw}.",
                "SECURITY-AUDIT.md",
            )
            continue
        if value < 0:
            report.error(
                "invalid-count",
                f"Counts marker has a negative {severity} value.",
                "SECURITY-AUDIT.md",
            )
            continue
        counts[severity] = value
    return counts


def parse_questions(text: str, report: Report) -> list[tuple[str, str]]:
    matches = list(QUESTION_RE.finditer(text))
    questions: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, match in enumerate(matches):
        question_id = f"Q-{match.group(1)}"
        if question_id in seen:
            report.error(
                "duplicate-question",
                f"Audit answer {question_id} is defined more than once.",
                "SECURITY-AUDIT.md",
            )
        seen.add(question_id)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[start:end]
        question_match = re.search(r"(?mi)^\s*-\s*Question:\s*(.+?)\s*$", block)
        answer_match = re.search(r"(?mi)^\s*-\s*Answer:\s*(.+?)\s*$", block)
        question = question_match.group(1).strip() if question_match else ""
        answer = answer_match.group(1).strip() if answer_match else ""
        if question and answer:
            questions.append((question, answer))
    return questions


def validate_findings(findings: list[Finding], report: Report) -> None:
    seen_ids: set[str] = set()
    previous_number = 0
    for finding in findings:
        location = finding.finding_id or "SECURITY-AUDIT.md"
        if not finding.finding_id:
            report.error("missing-finding-id", "A finding marker is missing its id.", "SECURITY-AUDIT.md")
            continue
        match = FINDING_ID_RE.match(finding.finding_id)
        if not match:
            report.error(
                "invalid-finding-id",
                f"Finding ID {finding.finding_id} must match FIND-NNN.",
                location,
            )
            continue
        number = int(match.group(1))
        if finding.finding_id in seen_ids:
            report.error(
                "duplicate-finding-id",
                f"Finding ID {finding.finding_id} is duplicated.",
                location,
            )
        seen_ids.add(finding.finding_id)
        if number <= previous_number:
            report.error(
                "finding-order",
                f"Finding {finding.finding_id} is not in increasing order.",
                location,
            )
        elif number != previous_number + 1:
            report.warning(
                "finding-gap",
                f"Finding IDs jump from {previous_number:03d} to {number:03d}.",
                location,
            )
        previous_number = number

        if not finding.title:
            report.error("missing-finding-title", f"Finding {finding.finding_id} needs a title.", location)

        severity = finding.attributes.get("severity", "").strip().lower()
        if not severity:
            report.error("missing-severity", f"Finding {finding.finding_id} needs a severity attribute.", location)
        elif severity not in ALLOWED_SEVERITIES:
            report.error(
                "invalid-severity",
                f"Finding {finding.finding_id} has invalid severity {severity!r}.",
                location,
            )

        cvss_raw = finding.attributes.get("cvss", "").strip()
        cvss = parse_cvss(cvss_raw) if cvss_raw else None
        if not cvss_raw:
            report.error("missing-cvss", f"Finding {finding.finding_id} needs a CVSS attribute.", location)
        elif not CVSS_SCORE_RE.fullmatch(cvss_raw):
            report.error(
                "invalid-cvss",
                f"Finding {finding.finding_id} CVSS attribute must be a numeric score.",
                location,
            )
            cvss = None
        elif cvss is None:
            report.error(
                "invalid-cvss",
                f"Finding {finding.finding_id} has an invalid CVSS value.",
                location,
            )
        elif cvss < 0.0 or cvss > 10.0:
            report.error(
                "cvss-out-of-range",
                f"Finding {finding.finding_id} CVSS must be between 0.0 and 10.0.",
                location,
            )
        elif severity in SEVERITY_RANGES:
            low, high = SEVERITY_RANGES[severity]
            if cvss < low or cvss > high:
                report.error(
                    "severity-cvss-mismatch",
                    f"Finding {finding.finding_id} severity {severity} does not match CVSS {cvss}.",
                    location,
                )

        cwe = finding.attributes.get("cwe", "").strip().upper()
        if not cwe:
            report.error("missing-cwe", f"Finding {finding.finding_id} needs a CWE attribute.", location)
        elif not CWE_RE.match(cwe):
            report.error(
                "invalid-cwe",
                f"Finding {finding.finding_id} CWE must match CWE-NNN.",
                location,
            )

        owasp = finding.attributes.get("owasp", "").strip().upper()
        if not owasp:
            report.error("missing-owasp", f"Finding {finding.finding_id} needs an OWASP attribute.", location)
        elif not OWASP_RE.match(owasp):
            report.error(
                "invalid-owasp",
                f"Finding {finding.finding_id} OWASP must match A01:2021 through A10:2021.",
                location,
            )

        status = finding.attributes.get("status", "").strip().lower()
        if not status:
            report.error("missing-status", f"Finding {finding.finding_id} needs a status attribute.", location)
        elif status not in ALLOWED_STATUSES:
            report.error(
                "invalid-status",
                f"Finding {finding.finding_id} has invalid status {status!r}.",
                location,
            )

        for field_name, minimum in FIELD_MIN_LENGTHS.items():
            value = finding.fields.get(field_name, "")
            if len(value) < minimum:
                report.error(
                    f"missing-{field_name}",
                    f"Finding {finding.finding_id} needs a substantive {field_name} field.",
                    location,
                )

        confidence = finding.fields.get("confidence", "").strip().lower()
        if confidence and confidence not in ALLOWED_CONFIDENCE:
            report.error(
                "invalid-confidence",
                f"Finding {finding.finding_id} confidence must be Confirmed, Likely, or Needs validation.",
                location,
            )

        if not finding.has_code_block:
            report.error(
                "missing-code-block",
                f"Finding {finding.finding_id} needs an affected code block.",
                location,
            )

        if finding.fields.get("severity", "").strip().lower() not in {"", severity}:
            report.warning(
                "severity-mismatch",
                f"Finding {finding.finding_id} marker severity differs from the Severity field.",
                location,
            )
        field_cvss = parse_cvss(finding.fields.get("cvss", ""))
        if cvss is not None and field_cvss is not None and abs(cvss - field_cvss) > 0.001:
            report.warning(
                "cvss-mismatch",
                f"Finding {finding.finding_id} marker CVSS differs from the CVSS field.",
                location,
            )
        field_cwe = finding.fields.get("cwe", "").strip().upper()
        if cwe and field_cwe and cwe != field_cwe:
            report.warning(
                "cwe-mismatch",
                f"Finding {finding.finding_id} marker CWE differs from the CWE field.",
                location,
            )
        field_owasp = finding.fields.get("owasp", "").strip().upper()
        if owasp and field_owasp and not field_owasp.startswith(owasp):
            report.warning(
                "owasp-mismatch",
                f"Finding {finding.finding_id} marker OWASP differs from the OWASP field.",
                location,
            )


def validate_report(
    text: str,
    report: Report,
    min_findings: int = 0,
    min_questions: int = 6,
) -> None:
    artifact = ARTIFACT_MARKER_RE.search(text)
    if not artifact:
        report.error(
            "missing-artifact-marker",
            "SECURITY-AUDIT.md is missing the security-audit artifact marker.",
            "SECURITY-AUDIT.md",
        )
    else:
        attributes = parse_attributes(artifact.group(1))
        if attributes.get("type") != "report":
            report.error(
                "wrong-artifact-type",
                "SECURITY-AUDIT.md artifact type must be report.",
                "SECURITY-AUDIT.md",
            )
        if attributes.get("version") != "1":
            report.warning(
                "artifact-version",
                "SECURITY-AUDIT.md uses an unknown artifact version.",
                "SECURITY-AUDIT.md",
            )

    for label in METADATA_FIELDS:
        if not metadata_value(text, label):
            report.error(
                "missing-metadata",
                f"SECURITY-AUDIT.md is missing metadata field {label}:",
                "SECURITY-AUDIT.md",
            )

    date_value = metadata_value(text, "Date")
    if date_value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_value):
        report.error(
            "invalid-date",
            "SECURITY-AUDIT.md Date must use YYYY-MM-DD.",
            "SECURITY-AUDIT.md",
        )

    language = metadata_value(text, "Report language")
    if language and language.lower() != "english":
        report.warning(
            "report-language",
            "The report is not in the default English language.",
            "SECURITY-AUDIT.md",
        )

    audit_type = metadata_value(text, "Audit type")
    authorization = metadata_value(text, "Authorization")
    readiness = metadata_value(text, "Deployment readiness").lower()
    if readiness and readiness not in ALLOWED_READINESS:
        report.error(
            "invalid-readiness",
            "Deployment readiness must be Ready, Ready with conditions, or Not ready.",
            "SECURITY-AUDIT.md",
        )
    if authorization.lower() in {"", "none", "unknown"}:
        report.error(
            "missing-authorization",
            "SECURITY-AUDIT.md needs an explicit authorization statement.",
            "SECURITY-AUDIT.md",
        )

    sections = section_bodies(text)
    for section_id in REPORT_REQUIRED_SECTIONS:
        if section_id not in sections:
            report.error(
                "missing-section",
                f"SECURITY-AUDIT.md is missing section marker id={section_id}.",
                "SECURITY-AUDIT.md",
            )
            continue
        minimum = MIN_CONTENT_LINES.get(section_id, 1)
        if len(nonempty_content_lines(sections[section_id])) < minimum:
            report.error(
                "thin-section",
                f"SECURITY-AUDIT.md section {section_id} needs at least {minimum} substantive lines.",
                "SECURITY-AUDIT.md",
            )

    scope = sections.get("scope", "")
    if not re.search(r"(?mi)^###\s+In scope\s*$", scope):
        report.error("missing-in-scope", "Scope needs an 'In scope' subsection.", "SECURITY-AUDIT.md")
    if not re.search(r"(?mi)^###\s+Out of scope\s*$", scope):
        report.error("missing-out-of-scope", "Scope needs an 'Out of scope' subsection.", "SECURITY-AUDIT.md")

    authorization_section = sections.get("authorization", "")
    if "active" in audit_type.lower():
        if "written" not in authorization_section.lower():
            report.error(
                "missing-written-authorization",
                "Active testing requires an explicit written authorization statement.",
                "SECURITY-AUDIT.md",
            )
        if "production" in audit_type.lower() and "not production" not in authorization_section.lower():
            report.error(
                "production-active-test",
                "Active testing must explicitly exclude production.",
                "SECURITY-AUDIT.md",
            )

    methodology = sections.get("methodology", "").lower()
    for term in ("owasp", "cwe", "cvss", "manual"):
        if term not in methodology:
            report.error(
                "methodology-missing-term",
                f"Methodology must mention {term.upper()}.",
                "SECURITY-AUDIT.md",
            )

    threatmodel = sections.get("threatmodel", "").lower()
    for term in ("asset", "actor"):
        if term not in threatmodel:
            report.error(
                "thin-threatmodel",
                f"Threat model must mention {term}.",
                "SECURITY-AUDIT.md",
            )

    evidence = sections.get("evidence", "").lower()
    if "limitation" not in evidence:
        report.error(
            "missing-limitations",
            "Evidence must document limitations.",
            "SECURITY-AUDIT.md",
        )
    if "command" not in evidence and "tool" not in evidence:
        report.error(
            "missing-evidence-detail",
            "Evidence must name the commands or tools used.",
            "SECURITY-AUDIT.md",
        )

    findings = parse_findings(text)
    findings_section = sections.get("findings", "")
    if not findings:
        if not re.search(
            r"(?i)\bno (?:findings|vulnerabilities|security issues)\b",
            findings_section,
        ):
            report.error(
                "empty-findings",
                "The findings section must contain at least one finding or state that no findings were identified.",
                "SECURITY-AUDIT.md",
            )
    if len(findings) < min_findings:
        report.error(
            "insufficient-findings",
            f"SECURITY-AUDIT.md has {len(findings)} findings; at least {min_findings} are required.",
            "SECURITY-AUDIT.md",
        )

    validate_findings(findings, report)

    counts = parse_counts(text, report)
    actual_counts = {
        severity: sum(
            1
            for finding in findings
            if finding.attributes.get("severity", "").strip().lower() == severity
        )
        for severity in ALLOWED_SEVERITIES
    }
    if counts is not None:
        for severity in ALLOWED_SEVERITIES:
            if severity in counts and counts[severity] != actual_counts[severity]:
                report.error(
                    "counts-mismatch",
                    f"Counts marker says {counts[severity]} {severity} findings but the report contains {actual_counts[severity]}.",
                    "SECURITY-AUDIT.md",
                )

    open_counts = {
        severity: sum(
            1
            for finding in findings
            if finding.attributes.get("severity", "").strip().lower() == severity
            and finding.attributes.get("status", "").strip().lower() == "open"
        )
        for severity in ALLOWED_SEVERITIES
    }
    if readiness == "ready" and open_counts["high"]:
        report.error(
            "readiness-contradiction",
            "Deployment readiness cannot be Ready while a High finding is open.",
            "SECURITY-AUDIT.md",
        )
    if readiness == "ready" and open_counts["medium"]:
        report.warning(
            "readiness-condition",
            "Deployment readiness is Ready while a Medium finding is open; record the condition.",
            "SECURITY-AUDIT.md",
        )

    remediation = sections.get("remediation", "")
    traceability = sections.get("traceability", "")
    for finding in findings:
        if finding.finding_id and finding.finding_id not in remediation:
            report.error(
                "remediation-gap",
                f"Remediation plan does not reference {finding.finding_id}.",
                "SECURITY-AUDIT.md",
            )
        if finding.finding_id and finding.finding_id not in traceability:
            report.error(
                "traceability-gap",
                f"Traceability section does not reference {finding.finding_id}.",
                "SECURITY-AUDIT.md",
            )

    readiness_section = sections.get("readiness", "")
    if len(CHECKBOX_RE.findall(readiness_section)) < 6:
        report.error(
            "thin-readiness",
            "Deployment readiness needs at least six checklist items.",
            "SECURITY-AUDIT.md",
        )

    risk = sections.get("risk", "").lower()
    for term in ("high", "medium", "low"):
        if term not in risk:
            report.error(
                "risk-missing-severity",
                f"Risk summary must mention {term.capitalize()}.",
                "SECURITY-AUDIT.md",
            )

    questions = parse_questions(text, report)
    if len(questions) < min_questions:
        report.error(
            "insufficient-questions",
            f"SECURITY-AUDIT.md has {len(questions)} answered audit questions; at least {min_questions} are required.",
            "SECURITY-AUDIT.md",
        )

    report.stats.update(
        {
            "findings_total": len(findings),
            "high": actual_counts["high"],
            "medium": actual_counts["medium"],
            "low": actual_counts["low"],
            "open_high": open_counts["high"],
            "open_medium": open_counts["medium"],
            "open_low": open_counts["low"],
            "interview_questions": len(questions),
            "deployment_readiness": metadata_value(text, "Deployment readiness") or "unknown",
        }
    )


def check_placeholders(text: str, report: Report) -> None:
    cleaned = strip_fenced_code(strip_comments(text))
    for match in PLACEHOLDER_RE.finditer(cleaned):
        line = cleaned.count("\n", 0, match.start()) + 1
        report.error(
            "placeholder",
            f"SECURITY-AUDIT.md contains unresolved placeholder {match.group(0)!r}.",
            f"SECURITY-AUDIT.md:{line}",
        )


def check_redaction(text: str, report: Report) -> None:
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            report.error(
                "unredacted-secret",
                f"SECURITY-AUDIT.md contains an unredacted {label}.",
                f"SECURITY-AUDIT.md:{line}",
            )


def validate_texts(
    text: str,
    min_findings: int = 0,
    min_questions: int = 6,
) -> Report:
    report = Report()
    validate_report(text, report, min_findings, min_questions)
    check_placeholders(text, report)
    check_redaction(text, report)
    report.stats["min_findings"] = min_findings
    report.stats["min_questions"] = min_questions
    return report


def validate_files(
    report_path: Path,
    min_findings: int = 0,
    min_questions: int = 6,
) -> Report:
    report = Report()
    if not report_path.is_file():
        report.error("missing-file", f"Report file not found: {report_path}", str(report_path))
        return report
    try:
        text = report_path.read_text(encoding="utf-8")
    except OSError as error:
        report.error("unreadable-file", f"Cannot read {report_path}: {error}.", str(report_path))
        return report
    result = validate_texts(text, min_findings, min_questions)
    result.stats["report_file"] = str(report_path)
    return result


def format_issue(issue: Issue) -> str:
    location = f" ({issue.location})" if issue.location else ""
    return f"[{issue.level.upper()}] {issue.code}: {issue.message}{location}"


def print_report(report: Report, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return
    for issue in report.errors:
        print(format_issue(issue), file=sys.stderr)
    for issue in report.warnings:
        print(format_issue(issue), file=sys.stderr)
    status = "PASS" if report.ok else "FAIL"
    stats = report.stats
    print(
        f"{status}: {stats.get('findings_total', 0)} findings "
        f"(High {stats.get('high', 0)}, Medium {stats.get('medium', 0)}, Low {stats.get('low', 0)}), "
        f"open High {stats.get('open_high', 0)}, open Medium {stats.get('open_medium', 0)}, "
        f"{stats.get('interview_questions', 0)} audit answers, "
        f"readiness {stats.get('deployment_readiness', 'unknown')}."
    )
    print(f"Errors: {len(report.errors)}. Warnings: {len(report.warnings)}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a Security Audit SECURITY-AUDIT.md report.",
    )
    parser.add_argument(
        "report",
        nargs="?",
        default="SECURITY-AUDIT.md",
        help="Path to SECURITY-AUDIT.md",
    )
    parser.add_argument(
        "--min-findings",
        type=int,
        default=0,
        help="Minimum number of findings (default: 0, allowing a clean audit)",
    )
    parser.add_argument(
        "--min-questions",
        type=int,
        default=6,
        help="Minimum answered audit questions",
    )
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    parser.add_argument("--json", action="store_true", help="Emit a JSON report")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.min_findings < 0:
        parser.error("--min-findings must be zero or greater")
    if args.min_questions < 0:
        parser.error("--min-questions must be zero or greater")
    report = validate_files(
        Path(args.report),
        min_findings=args.min_findings,
        min_questions=args.min_questions,
    )
    print_report(report, args.json)
    if report.errors:
        return 1
    if args.strict and report.warnings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
