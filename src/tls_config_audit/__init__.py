"""Static auditing of TLS settings in nginx and Apache configuration files."""

from .audit import Finding, Severity, audit_config, audit_file

__all__ = ["Finding", "Severity", "audit_config", "audit_file"]
__version__ = "1.0.0"
