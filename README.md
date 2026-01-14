# TLS Config Audit

TLS Config Audit scans TLS/SSL configuration snippets for weak protocols and ciphers.

## Quick start

```bash
python tls_config_audit.py --input tls.conf
```

## Output

Findings list deprecated protocols, weak ciphers, and missing HSTS hints.
