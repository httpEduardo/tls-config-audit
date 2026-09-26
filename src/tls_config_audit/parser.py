"""Parse nginx and Apache configuration into TLS-relevant directives."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

# Directive names are normalized to a common key so rules don't care
# which server the configuration came from.
_DIRECTIVES = {
    # nginx
    "ssl_protocols": "protocols",
    "ssl_ciphers": "ciphers",
    "ssl_prefer_server_ciphers": "prefer_server_ciphers",
    "ssl_session_tickets": "session_tickets",
    # Apache httpd (mod_ssl)
    "sslprotocol": "protocols",
    "sslciphersuite": "ciphers",
    "sslhonorcipherorder": "prefer_server_ciphers",
    "sslsessiontickets": "session_tickets",
    "sslcompression": "compression",
}

_COMMENT_RE = re.compile(r"(?<!\\)#.*$")
_HSTS_RE = re.compile(r"strict-transport-security", re.IGNORECASE)


@dataclass(frozen=True)
class Directive:
    """A single configuration directive and where it was found."""

    key: str
    value: str
    line: int
    raw: str


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse(text: str) -> Iterator[Directive]:
    """Yield TLS directives and HSTS headers found in ``text``.

    The parser is deliberately line-oriented: it understands enough of
    nginx and Apache syntax to find the settings that matter here, without
    trying to be a full configuration parser.
    """
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = _COMMENT_RE.sub("", raw_line).strip().rstrip(";").strip()
        if not line:
            continue

        name, _, rest = line.partition(" ")
        if not rest:
            name, _, rest = line.partition("\t")
        key = _DIRECTIVES.get(name.lower())
        if key:
            yield Directive(key, _strip_quotes(rest), number, raw_line.strip())
            continue

        # nginx: add_header Strict-Transport-Security "max-age=..." always;
        # Apache: Header always set Strict-Transport-Security "max-age=..."
        if _HSTS_RE.search(line) and name.lower() in {"add_header", "header"}:
            value = line[_HSTS_RE.search(line).end():].strip()
            yield Directive("hsts", _strip_quotes(value.split(" always")[0]), number, raw_line.strip())
