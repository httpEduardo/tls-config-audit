import argparse
import re
import sys

TLS_RE = re.compile(r"ssl_protocols\s+([^;]+);", re.IGNORECASE)
CIPHER_RE = re.compile(r"ssl_ciphers\s+([^;]+);", re.IGNORECASE)
HSTS_RE = re.compile(r"strict-transport-security\s+\"?max-age=(\d+)", re.IGNORECASE)

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3"}
WEAK_CIPHERS = {"3DES", "RC4", "DES", "MD5", "NULL"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit TLS/SSL config snippets.")
    parser.add_argument("--input", required=True, help="Config file")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            content = handle.read()
    except OSError as exc:
        print(f"Failed to read {args.input}: {exc}", file=sys.stderr)
        return 1

    findings = []

    protocols_match = TLS_RE.search(content)
    if protocols_match:
        protocols = protocols_match.group(1).split()
        weak = [proto for proto in protocols if proto in WEAK_PROTOCOLS]
        if weak:
            findings.append(f"weak protocols enabled: {', '.join(weak)}")
    else:
        findings.append("ssl_protocols not found")

    cipher_match = CIPHER_RE.search(content)
    if cipher_match:
        cipher_str = cipher_match.group(1)
        weak_hits = [token for token in WEAK_CIPHERS if token in cipher_str]
        if weak_hits:
            findings.append(f"weak cipher tokens present: {', '.join(sorted(weak_hits))}")
    else:
        findings.append("ssl_ciphers not found")

    hsts_match = HSTS_RE.search(content)
    if hsts_match:
        max_age = int(hsts_match.group(1))
        if max_age < 15552000:
            findings.append("HSTS max-age below 15552000")
    else:
        findings.append("HSTS header not detected")

    if findings:
        print("Findings:")
        for item in findings:
            print(f"- {item}")
    else:
        print("No findings.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
