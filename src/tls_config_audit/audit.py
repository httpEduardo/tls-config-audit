"""Rules that evaluate parsed TLS directives."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path

from .parser import Directive, parse


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            choices = ", ".join(str(s) for s in cls)
            raise ValueError(f"unknown severity {name!r} (choose from {choices})") from None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    remediation: str
    line: int | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = str(self.severity)
        return data


# --- Protocols -------------------------------------------------------------

_PROTOCOL_ALIASES = {
    "sslv2": "SSLv2",
    "sslv3": "SSLv3",
    "tlsv1": "TLSv1",
    "tlsv1.0": "TLSv1",
    "tlsv1.1": "TLSv1.1",
    "tlsv1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3",
}

# What Apache means by "all" on a modern OpenSSL build.
_APACHE_ALL = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}

_BROKEN_PROTOCOLS = {"SSLv2": Severity.CRITICAL, "SSLv3": Severity.CRITICAL}
_DEPRECATED_PROTOCOLS = {"TLSv1": Severity.HIGH, "TLSv1.1": Severity.HIGH}


def resolve_protocols(value: str) -> set[str]:
    """Return the protocols a directive actually enables.

    Handles both nginx lists (``TLSv1.2 TLSv1.3``) and Apache's
    additive syntax (``all -SSLv3 -TLSv1 -TLSv1.1``).
    """
    enabled: set[str] = set()
    for token in value.split():
        op = ""
        if token[0] in "+-":
            op, token = token[0], token[1:]
        if token.lower() == "all":
            names = set(_APACHE_ALL)
        else:
            name = _PROTOCOL_ALIASES.get(token.lower())
            if name is None:
                continue
            names = {name}
        if op == "-":
            enabled -= names
        else:
            enabled |= names
    return enabled


def _check_protocols(directives: list[Directive]) -> list[Finding]:
    found = [d for d in directives if d.key == "protocols"]
    if not found:
        return [Finding(
            "TLS001", Severity.MEDIUM,
            "no protocol directive found, so the server falls back to its build defaults",
            "Set the protocols explicitly, e.g. `ssl_protocols TLSv1.2 TLSv1.3;`.",
        )]

    findings = []
    for d in found:
        enabled = resolve_protocols(d.value)
        for proto in sorted(enabled):
            if proto in _BROKEN_PROTOCOLS:
                findings.append(Finding(
                    "TLS002", _BROKEN_PROTOCOLS[proto],
                    f"{proto} is enabled; it is broken (POODLE, DROWN) and must not be used",
                    f"Remove {proto} from the protocol list.", d.line,
                ))
            elif proto in _DEPRECATED_PROTOCOLS:
                findings.append(Finding(
                    "TLS003", _DEPRECATED_PROTOCOLS[proto],
                    f"{proto} is enabled; it was deprecated by RFC 8996",
                    "Allow only TLSv1.2 and TLSv1.3.", d.line,
                ))
        if enabled and "TLSv1.3" not in enabled:
            findings.append(Finding(
                "TLS004", Severity.LOW,
                "TLSv1.3 is not enabled",
                "Add TLSv1.3 for faster handshakes and stronger defaults.", d.line,
            ))
    return findings


# --- Ciphers ---------------------------------------------------------------

# Fragments of OpenSSL cipher names/aliases that mark a weak suite.
_WEAK_CIPHER_PARTS = {
    "NULL": (Severity.CRITICAL, "no encryption"),
    "ENULL": (Severity.CRITICAL, "no encryption"),
    "ANULL": (Severity.CRITICAL, "no authentication"),
    "ADH": (Severity.CRITICAL, "anonymous key exchange"),
    "AECDH": (Severity.CRITICAL, "anonymous key exchange"),
    "EXP": (Severity.CRITICAL, "export-grade cryptography"),
    "EXPORT": (Severity.CRITICAL, "export-grade cryptography"),
    "RC4": (Severity.HIGH, "RC4 is broken"),
    "DES": (Severity.HIGH, "DES/3DES is vulnerable to SWEET32"),
    "3DES": (Severity.HIGH, "DES/3DES is vulnerable to SWEET32"),
    "CBC3": (Severity.HIGH, "DES/3DES is vulnerable to SWEET32"),
    "MD5": (Severity.HIGH, "MD5 is broken"),
    "IDEA": (Severity.MEDIUM, "IDEA is obsolete"),
    "SEED": (Severity.MEDIUM, "SEED is obsolete"),
}

# Broad aliases that pull in anonymous suites unless !aNULL is present.
_BROAD_ALIASES = {"ALL", "HIGH", "MEDIUM", "DEFAULT", "COMPLEMENTOFDEFAULT"}

_TOKEN_SPLIT = re.compile(r"[:,\s]+")


def _check_ciphers(directives: list[Directive]) -> list[Finding]:
    findings = []
    for d in (d for d in directives if d.key == "ciphers"):
        excluded: set[str] = set()
        included: list[str] = []
        for token in filter(None, _TOKEN_SPLIT.split(d.value)):
            if token[0] in "!-":
                excluded.update(token[1:].upper().split("+"))
            elif token[0] == "+":
                continue  # "+X" only reorders suites already selected
            elif not token.startswith("@"):
                included.append(token)

        reported: set[str] = set()
        for token in included:
            parts = set(re.split(r"[-+_]", token.upper()))
            for part in sorted(parts & _WEAK_CIPHER_PARTS.keys()):
                reason_sev, reason = _WEAK_CIPHER_PARTS[part]
                if part in excluded or reason in reported:
                    continue
                reported.add(reason)
                findings.append(Finding(
                    "TLS005", reason_sev,
                    f"weak cipher enabled by `{token}` ({reason})",
                    "Use an AEAD-only list such as the Mozilla 'intermediate' profile.", d.line,
                ))

        uses_broad = any(t.upper() in _BROAD_ALIASES for t in included)
        if uses_broad and not excluded & {"ANULL", "NULL"}:
            findings.append(Finding(
                "TLS006", Severity.MEDIUM,
                "broad cipher alias used without excluding anonymous suites",
                "Append `:!aNULL` or switch to an explicit list of suites.", d.line,
            ))
    return findings


# --- Other directives ------------------------------------------------------

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_HSTS_RECOMMENDED = 31_536_000  # one year
_HSTS_MINIMUM = 15_552_000  # 180 days


def _duration(seconds: int) -> str:
    if seconds >= 86400:
        days = seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    return f"{seconds} seconds"


def _check_hsts(directives: list[Directive]) -> list[Finding]:
    found = [d for d in directives if d.key == "hsts"]
    if not found:
        return [Finding(
            "TLS007", Severity.MEDIUM,
            "no Strict-Transport-Security header found",
            'Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`.',
        )]

    findings = []
    for d in found:
        match = _HSTS_MAX_AGE_RE.search(d.value)
        if not match:
            findings.append(Finding(
                "TLS008", Severity.MEDIUM, "HSTS header has no max-age",
                "Set max-age to at least 31536000 (one year).", d.line,
            ))
            continue
        max_age = int(match.group(1))
        if max_age < _HSTS_MINIMUM:
            findings.append(Finding(
                "TLS008", Severity.MEDIUM,
                f"HSTS max-age is {_duration(max_age)}, below the 180-day minimum",
                "Set max-age to at least 31536000 (one year).", d.line,
            ))
        elif max_age < _HSTS_RECOMMENDED:
            findings.append(Finding(
                "TLS008", Severity.LOW,
                f"HSTS max-age is {_duration(max_age)}; one year is recommended",
                "Set max-age to 31536000.", d.line,
            ))
        if "includesubdomains" not in d.value.lower():
            findings.append(Finding(
                "TLS009", Severity.LOW,
                "HSTS header does not include subdomains",
                "Add `includeSubDomains` once every subdomain serves HTTPS.", d.line,
            ))
    return findings


def _is_on(value: str) -> bool:
    return value.strip().lower() in {"on", "true", "yes"}


def _check_misc(directives: list[Directive]) -> list[Finding]:
    findings = []
    for d in directives:
        if d.key == "compression" and _is_on(d.value):
            findings.append(Finding(
                "TLS010", Severity.HIGH,
                "TLS compression is enabled, exposing the server to CRIME",
                "Set `SSLCompression off`.", d.line,
            ))
        elif d.key == "session_tickets" and _is_on(d.value):
            findings.append(Finding(
                "TLS011", Severity.LOW,
                "session tickets are enabled, which weakens forward secrecy unless keys are rotated",
                "Disable session tickets or rotate ticket keys frequently.", d.line,
            ))
    return findings


# --- Entry points ----------------------------------------------------------

def audit_config(text: str) -> list[Finding]:
    """Audit configuration text and return findings, most severe first."""
    directives = list(parse(text))
    findings = (
        _check_protocols(directives)
        + _check_ciphers(directives)
        + _check_hsts(directives)
        + _check_misc(directives)
    )
    return sorted(findings, key=lambda f: (-f.severity, f.line or 0, f.rule_id))


def audit_file(path: str | Path) -> list[Finding]:
    """Read and audit a configuration file."""
    return audit_config(Path(path).read_text(encoding="utf-8"))
