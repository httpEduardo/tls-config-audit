# TLS Config Audit

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**Catch risky TLS settings in nginx and Apache configuration files.**

TLS Config Audit checks configuration files for outdated protocols, weak cipher settings, and missing or incomplete HSTS headers. It reports each finding with its source line and a suggested fix, making it useful in code review and deployment checks.

## Quick start

```bash
pip install git+https://github.com/httpEduardo/tls-config-audit.git
tls-config-audit /etc/nginx/conf.d/site.conf
```

Or try an included example from a clone:

```bash
git clone https://github.com/httpEduardo/tls-config-audit.git
cd tls-config-audit
PYTHONPATH=src python -m tls_config_audit examples/nginx-weak.conf
```

Audit several files or request JSON output with `--format json`:

```bash
tls-config-audit sites-enabled/*.conf --format json
```

## What it checks

- SSL and TLS protocol versions
- Weak cipher suites and TLS compression
- HSTS presence, duration, and subdomain settings

The checker reads configuration text; it does not validate certificates, follow included files, or replace a live TLS scan. Treat findings as review guidance for the server configuration.

## License

[MIT](LICENSE)
