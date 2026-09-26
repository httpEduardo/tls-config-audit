import unittest
from pathlib import Path

from tls_config_audit import Severity, audit_config, audit_file
from tls_config_audit.audit import resolve_protocols

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rules(findings):
    return {f.rule_id for f in findings}


class ProtocolTests(unittest.TestCase):
    def test_nginx_list(self):
        self.assertEqual(resolve_protocols("TLSv1.2 TLSv1.3"), {"TLSv1.2", "TLSv1.3"})

    def test_apache_additive_syntax(self):
        self.assertEqual(resolve_protocols("all -TLSv1 -TLSv1.1"), {"TLSv1.2", "TLSv1.3"})
        self.assertEqual(resolve_protocols("-all +TLSv1.2"), {"TLSv1.2"})

    def test_deprecated_protocol_is_high(self):
        findings = audit_config("ssl_protocols TLSv1 TLSv1.2 TLSv1.3;")
        tls003 = [f for f in findings if f.rule_id == "TLS003"]
        self.assertEqual(len(tls003), 1)
        self.assertEqual(tls003[0].severity, Severity.HIGH)
        self.assertEqual(tls003[0].line, 1)

    def test_sslv3_is_critical(self):
        findings = audit_config("SSLProtocol +SSLv3 +TLSv1.2")
        self.assertIn(Severity.CRITICAL, {f.severity for f in findings if f.rule_id == "TLS002"})

    def test_missing_protocol_directive(self):
        self.assertIn("TLS001", rules(audit_config("")))


class CipherTests(unittest.TestCase):
    def test_excluded_ciphers_are_not_reported(self):
        # "!MD5" and "!3DES" disable those suites and must not be flagged.
        findings = audit_config("ssl_ciphers HIGH:!aNULL:!MD5:!3DES;")
        self.assertFalse({"TLS005", "TLS006"} & rules(findings))

    def test_named_weak_suite(self):
        findings = audit_config("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA;")
        messages = [f.message for f in findings if f.rule_id == "TLS005"]
        self.assertEqual(len(messages), 1)
        self.assertIn("SWEET32", messages[0])

    def test_broad_alias_without_anull(self):
        self.assertIn("TLS006", rules(audit_config("ssl_ciphers HIGH;")))

    def test_modern_suites_are_clean(self):
        findings = audit_config("ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305;")
        self.assertFalse({"TLS005", "TLS006"} & rules(findings))


class HstsTests(unittest.TestCase):
    def test_short_max_age(self):
        findings = audit_config('add_header Strict-Transport-Security "max-age=86400";')
        self.assertIn(Severity.MEDIUM, {f.severity for f in findings if f.rule_id == "TLS008"})
        self.assertIn("TLS009", rules(findings))

    def test_apache_header(self):
        findings = audit_config('Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"')
        self.assertFalse({"TLS007", "TLS008", "TLS009"} & rules(findings))

    def test_commented_out_header_is_ignored(self):
        self.assertIn("TLS007", rules(audit_config('# add_header Strict-Transport-Security "max-age=31536000";')))


class ExampleTests(unittest.TestCase):
    def test_hardened_example_is_clean(self):
        self.assertEqual(audit_file(EXAMPLES / "nginx-hardened.conf"), [])

    def test_apache_example(self):
        found = rules(audit_file(EXAMPLES / "apache-weak.conf"))
        self.assertTrue({"TLS003", "TLS005", "TLS006", "TLS008", "TLS010"} <= found)

    def test_findings_sorted_by_severity(self):
        findings = audit_file(EXAMPLES / "apache-weak.conf")
        severities = [f.severity for f in findings]
        self.assertEqual(severities, sorted(severities, reverse=True))


if __name__ == "__main__":
    unittest.main()
