import argparse
import json
import sys
import urllib.request
import urllib.parse
import urllib.error


def _get(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _get_with_status(url: str) -> tuple[int, dict | None]:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        return e.code, body
    except Exception:
        return 0, None


def check_health(base_url: str) -> bool:
    data = _get(f"{base_url}/health")
    return data is not None and data.get("status") == "ok"


def search_vulnerable(base_url: str, domain: str) -> dict:
    params = urllib.parse.urlencode({"domain": domain})
    data = _get(f"{base_url}/api/ct/search?{params}")
    return data or {"certificates": [], "total": 0}


def search_safe(base_url: str, domain: str) -> tuple[int, dict]:
    params = urllib.parse.urlencode({"domain": domain})
    return _get_with_status(f"{base_url}/api/ct/search/safe?{params}")


def get_subdomains(base_url: str, domain: str) -> list[str]:
    domain_encoded = urllib.parse.quote(domain, safe="")
    data = _get(f"{base_url}/api/ct/subdomains/{domain_encoded}")
    return data.get("subdomains", []) if data else []


SENSITIVE_PATTERNS = ["admin", "secret", "vault", "internal", "vpn", "dev", "staging", "gitlab"]


def run_scan(base_url: str, domain: str) -> dict:
    findings = []
    subdomains: list[str] = []

    if not check_health(base_url):
        return {
            "target": base_url,
            "domain": domain,
            "subdomains_discovered": [],
            "findings": [],
            "summary": "Server unreachable. No findings.",
        }

    print(f"[*] Scanning CT log API at {base_url} for domain: {domain}", file=sys.stderr)

    # Collect subdomains from dedicated endpoint
    subdomains = get_subdomains(base_url, domain)
    if subdomains:
        print(f"[+] CT log reveals {len(subdomains)} subdomain(s): {', '.join(subdomains)}", file=sys.stderr)

    # Test wildcard injection on vulnerable endpoint
    wildcard = f"*.{domain}"
    normal_result = search_vulnerable(base_url, domain)
    wildcard_result = search_vulnerable(base_url, wildcard)
    normal_count = normal_result.get("total", 0)
    wildcard_count = wildcard_result.get("total", 0)

    # Verify safe endpoint rejects the same wildcard
    safe_status, safe_body = search_safe(base_url, wildcard)
    safe_rejected = safe_status == 400

    if wildcard_count > 0:
        safe_note = (
            f"Safe endpoint correctly rejects: {safe_body.get('detail', 'rejected')}"
            if safe_rejected
            else "Safe endpoint did not reject wildcard (also vulnerable)"
        )
        findings.append({
            "endpoint": "/api/ct/search",
            "vulnerability_type": "Wildcard Pattern Injection in CT Log Query",
            "evidence": (
                f"Wildcard query '{wildcard}' returned {wildcard_count} certificate(s) "
                f"(exact query returned {normal_count}). {safe_note}."
            ),
            "severity": "medium",
        })
        print(
            f"[!] VULNERABILITY: Wildcard Pattern Injection (MEDIUM) — "
            f"'{wildcard}' matched {wildcard_count} cert(s)",
            file=sys.stderr,
        )

    # Inspect SANs for sensitive subdomain exposure
    all_sans: set[str] = set()
    for cert in normal_result.get("certificates", []):
        all_sans.update(cert.get("sans", []))

    sensitive_found = sorted(s for s in all_sans if any(p in s.lower() for p in SENSITIVE_PATTERNS))
    if sensitive_found:
        findings.append({
            "endpoint": "/api/ct/search",
            "vulnerability_type": "Sensitive Subdomain Exposure via CT Log",
            "evidence": (
                f"Certificate SANs disclose potentially sensitive hostnames: "
                f"{', '.join(sensitive_found)}"
            ),
            "severity": "low",
        })
        print(
            f"[!] FINDING: Sensitive Subdomain Exposure (LOW) — {', '.join(sensitive_found)}",
            file=sys.stderr,
        )

    if safe_rejected:
        print("[+] Safe endpoint correctly rejects wildcard patterns", file=sys.stderr)

    summary_parts: list[str] = []
    if findings:
        summary_parts.append(f"Found {len(findings)} issue(s) on {base_url}")
        for f in findings:
            summary_parts.append(f"[{f['severity'].upper()}] {f['vulnerability_type']}")
    else:
        summary_parts.append(f"No vulnerabilities detected on {base_url}")

    if subdomains:
        summary_parts.append(
            f"CT log reveals {len(subdomains)} subdomain(s) for {domain}: {', '.join(subdomains)}"
        )

    return {
        "target": base_url,
        "domain": domain,
        "subdomains_discovered": subdomains,
        "findings": findings,
        "summary": " | ".join(summary_parts),
    }


def main():
    parser = argparse.ArgumentParser(description="Certificate Transparency Log Searcher")
    parser.add_argument("--target", default="http://localhost:3000", help="Target server base URL")
    parser.add_argument("--domain", default="example.com", help="Domain to search in CT logs")
    args = parser.parse_args()

    result = run_scan(args.target.rstrip("/"), args.domain)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
