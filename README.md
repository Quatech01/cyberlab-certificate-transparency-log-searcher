# Certificate Transparency Log Searcher

A Python tool that queries Certificate Transparency (CT) logs to enumerate subdomains and detect misconfigured CT log endpoints that accept wildcard pattern injection.

## What This Demonstrates

Certificate Transparency is a public audit mechanism for TLS certificates. Every certificate issued by a trusted CA must be logged in a publicly accessible CT log. This is great for monitoring, but it also means CT logs are a powerful reconnaissance resource — anyone can query them to enumerate all subdomains that have ever had a certificate issued.

This project demonstrates two related issues:

1. **Wildcard Pattern Injection** — A CT log API that blindly accepts `*.example.com` as a query pattern lets an attacker enumerate all subdomains in a single request, including internal or sensitive ones that were never intended to be publicly discoverable.

2. **Sensitive Subdomain Exposure** — Even a correctly validated CT log query reveals hostnames embedded in Subject Alternative Names (SANs): `admin.example.com`, `staging.example.com`, `vault.example.com`. This is expected behaviour from public CT logs, but developers should be aware that any hostname you put in a certificate becomes permanently public.

## How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│  Demo Server (FastAPI on port 3000)                              │
│                                                                  │
│  GET /api/ct/search?domain=*.example.com  ← VULNERABLE           │
│    Accepts wildcard patterns, returns all matching certs         │
│                                                                  │
│  GET /api/ct/search/safe?domain=*.example.com  ← SAFE (400)     │
│    Validates domain format with regex, rejects wildcards         │
│                                                                  │
│  GET /api/ct/certificates/{domain}  ← exact lookup              │
│  GET /api/ct/subdomains/{domain}    ← SAN enumeration           │
└──────────────────────────────────────────────────────────────────┘
              ↑ scanned by
┌─────────────────────────────────────────────────────────────────┐
│  Scanner Tool (tool/main.py)                                    │
│                                                                  │
│  1. Queries /api/ct/subdomains/{domain} for known subdomains    │
│  2. Tests *.domain wildcard on vulnerable vs safe endpoint      │
│  3. Inspects SANs for sensitive hostname patterns               │
│  4. Outputs structured JSON findings + human summary to stderr  │
└─────────────────────────────────────────────────────────────────┘
```

The tests verify:
- The vulnerable endpoint really does accept wildcard queries and return results
- The safe endpoint correctly rejects wildcard and special-character inputs with HTTP 400
- The tool accurately detects both vulnerability types and reports them with correct severity
- The tool handles unreachable servers gracefully (empty findings, no crash)

## Quick Start

**Requirements:** Python 3.11+

```bash
# Install server dependencies
cd server && pip install -r requirements.txt && cd ..

# Run the demo server
python server/main.py
# Server listening on http://127.0.0.1:3000

# In another terminal, run the scanner
python tool/main.py --target http://localhost:3000 --domain example.com

# Run the test suite
cd tests && pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "domain": "example.com",
  "subdomains_discovered": [
    "admin.example.com",
    "api.example.com",
    "dev.example.com",
    "mail.example.com",
    "secure.example.com",
    "secret-api.example.com",
    "staging.example.com",
    "vault.example.com",
    "www.example.com"
  ],
  "findings": [
    {
      "endpoint": "/api/ct/search",
      "vulnerability_type": "Wildcard Pattern Injection in CT Log Query",
      "evidence": "Wildcard query '*.example.com' returned 3 certificate(s) (exact query returned 2). Safe endpoint correctly rejects: Wildcards and special characters are not permitted.",
      "severity": "medium"
    },
    {
      "endpoint": "/api/ct/search",
      "vulnerability_type": "Sensitive Subdomain Exposure via CT Log",
      "evidence": "Certificate SANs disclose potentially sensitive hostnames: admin.example.com, dev.example.com, secret-api.example.com, staging.example.com, vault.example.com",
      "severity": "low"
    }
  ],
  "summary": "Found 2 issue(s) on http://localhost:3000 | [MEDIUM] Wildcard Pattern Injection in CT Log Query | [LOW] Sensitive Subdomain Exposure via CT Log | CT log reveals 9 subdomain(s) for example.com: admin.example.com, api.example.com, dev.example.com, mail.example.com, secure.example.com, secret-api.example.com, staging.example.com, vault.example.com, www.example.com"
}
```

## Key Takeaways

- **CT logs are permanent and public.** Once a certificate is logged, the hostnames in its SANs are discoverable forever. Never issue a certificate for an internal hostname you want to keep private.
- **Wildcard queries expose more than exact lookups.** A CT log API that accepts `*.example.com` as input returns certificates for all sub-domains in one round trip — useful for reconnaissance and pentest asset discovery.
- **Domain validation is non-trivial.** The safe endpoint uses a regex that only allows `label.tld` patterns. Any CT log proxy or internal API that forwards user-supplied domain strings to a backing log store should apply the same validation.
- **SAN sprawl is a real risk.** Multi-SAN certificates that bundle `dev`, `staging`, and `admin` subdomains alongside `www` broadcast your internal infrastructure layout to the world.

## Further Reading

- [Certificate Transparency RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)
- [crt.sh — public CT log search](https://crt.sh/) (real-world equivalent of this demo)
- [OWASP Testing Guide — Enumerate Application on Webserver](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)
