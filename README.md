# tls-config-audit

A static checker for TLS settings in nginx and Apache configuration files. Point it at a config and it tells you which protocols, cipher suites and headers are putting your HTTPS setup at risk — with the exact line and what to change.

Scanners like SSL Labs or `testssl.sh` test a server that's already running. That's great for verification, but by then the config is in production. This tool reads the config itself, so you can catch a stray `TLSv1` or `RC4` in code review or CI, before anything is deployed. It has no dependencies beyond the Python standard library.

## What it checks

| Rule | Severity | Description |
|------|----------|-------------|
| `TLS001` | Medium | No protocol directive — the server silently uses its build defaults |
| `TLS002` | Critical | SSLv2 or SSLv3 enabled |
| `TLS003` | High | TLS 1.0 or 1.1 enabled (deprecated by RFC 8996) |
| `TLS004` | Low | TLS 1.3 not enabled |
| `TLS005` | Critical → Medium | Weak suites enabled: NULL, anonymous, export-grade, RC4, 3DES, MD5, IDEA, SEED |
| `TLS006` | Medium | Broad alias like `ALL` or `HIGH` without `!aNULL` |
| `TLS007` | Medium | No `Strict-Transport-Security` header |
| `TLS008` | Medium / Low | HSTS `max-age` missing, under 180 days, or under one year |
| `TLS009` | Low | HSTS without `includeSubDomains` |
| `TLS010` | High | TLS compression enabled (CRIME) |
| `TLS011` | Low | Session tickets enabled |

A few details worth knowing:

- **Exclusions are understood.** `HIGH:!aNULL:!MD5:!3DES` is *not* reported for MD5 or 3DES — the `!` means those suites are removed. Only suites that are actually enabled get flagged.
- **Apache's additive syntax is resolved.** `SSLProtocol all -SSLv3` still enables TLS 1.0 and 1.1, and the tool will tell you so.
- **Comments are ignored**, so a commented-out HSTS header doesn't count as configured.

## Installation

Requires Python 3.9 or newer.

```bash
pip install git+https://github.com/httpEduardo/tls-config-audit.git
```

Or run it straight from a clone without installing:

```bash
git clone https://github.com/httpEduardo/tls-config-audit.git
cd tls-config-audit
PYTHONPATH=src python -m tls_config_audit examples/nginx-weak.conf
```

## Usage

```bash
tls-config-audit /etc/nginx/conf.d/ssl.conf
```

```text
examples/nginx-weak.conf: 5 finding(s)

  [TLS003] HIGH     TLSv1 is enabled; it was deprecated by RFC 8996 (line 1)
           -> Allow only TLSv1.2 and TLSv1.3.

  [TLS003] HIGH     TLSv1.1 is enabled; it was deprecated by RFC 8996 (line 1)
           -> Allow only TLSv1.2 and TLSv1.3.

  [TLS008] MEDIUM   HSTS max-age is 1 day, below the 180-day minimum (line 3)
           -> Set max-age to at least 31536000 (one year).

  [TLS004] LOW      TLSv1.3 is not enabled (line 1)
           -> Add TLSv1.3 for faster handshakes and stronger defaults.

  [TLS009] LOW      HSTS header does not include subdomains (line 3)
           -> Add `includeSubDomains` once every subdomain serves HTTPS.

Summary: 2 high, 1 medium, 2 low
```

Several files can be audited in one run:

```bash
tls-config-audit sites-enabled/*.conf
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--format {text,json}` | `text` | Human-readable report or JSON for other tools |
| `--fail-on SEVERITY` | `high` | Lowest severity that produces exit code `1` |
| `--version` | | Print the version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | A file could not be read, or the arguments were invalid |

### JSON output

```bash
tls-config-audit --format json examples/apache-weak.conf
```

```json
[
  {
    "file": "examples/apache-weak.conf",
    "summary": { "high": 5, "medium": 2, "low": 1 },
    "findings": [
      {
        "rule_id": "TLS003",
        "severity": "high",
        "message": "TLSv1 is enabled; it was deprecated by RFC 8996",
        "remediation": "Allow only TLSv1.2 and TLSv1.3.",
        "line": 1
      }
    ]
  }
]
```

## Using it in CI

```yaml
- name: Check TLS configuration
  run: |
    pip install git+https://github.com/httpEduardo/tls-config-audit.git
    tls-config-audit deploy/nginx/*.conf --fail-on high
```

## Examples

The `examples/` folder has three configs to try:

| File | What it shows |
|------|---------------|
| `nginx-weak.conf` | Legacy protocols and a short HSTS lifetime |
| `apache-weak.conf` | RC4, 3DES, compression and the `all -SSLv2` trap |
| `nginx-hardened.conf` | A config based on the Mozilla "intermediate" profile — no findings |

## Development

```bash
python -m unittest discover -s tests -t .
```

The code lives in `src/tls_config_audit/`:

- `parser.py` — finds TLS directives and HSTS headers, normalizing nginx and Apache names
- `audit.py` — the rules and severity model
- `cli.py` — argument handling, output and exit codes

Rules are plain functions that take the parsed directives and return findings, so adding one is usually a few lines plus a test.

## Limitations

- The parser is line-based. It understands the directives above but doesn't follow `include` statements or resolve which `server` block a directive belongs to.
- It checks configuration, not certificates. Expiry, chain problems and key sizes still need a live scan.
- Cipher analysis is based on OpenSSL names and aliases. It won't know what a custom OpenSSL build expands `DEFAULT` to.

For a full picture, pair it with a live scan (SSL Labs, `testssl.sh`) once the change is deployed.

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

## License

[MIT](LICENSE)
