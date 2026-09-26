import io
import json
import unittest
from pathlib import Path

from tls_config_audit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_clean_file_exits_zero(self):
        code, out, _ = run(str(EXAMPLES / "nginx-hardened.conf"))
        self.assertEqual(code, EXIT_OK)
        self.assertIn("no findings", out)

    def test_weak_file_exits_one(self):
        code, _, _ = run(str(EXAMPLES / "nginx-weak.conf"))
        self.assertEqual(code, EXIT_FINDINGS)

    def test_fail_on_critical_ignores_high(self):
        code, _, _ = run(str(EXAMPLES / "nginx-weak.conf"), "--fail-on", "critical")
        self.assertEqual(code, EXIT_OK)

    def test_missing_file(self):
        code, _, err = run("does-not-exist.conf")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot read", err)

    def test_json_output(self):
        code, out, _ = run(str(EXAMPLES / "apache-weak.conf"), "--format", "json")
        payload = json.loads(out)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertEqual(payload[0]["file"], str(EXAMPLES / "apache-weak.conf"))
        self.assertEqual(payload[0]["summary"]["high"], 5)
        self.assertTrue(all("rule_id" in f and "line" in f for f in payload[0]["findings"]))


if __name__ == "__main__":
    unittest.main()
