import re
import threading
import time
import urllib.request

import uvicorn
from fastapi import FastAPI, HTTPException, Query

app = FastAPI(title="Mock CT Log Server")

CT_LOG_DATA = [
    {
        "id": 1,
        "domain": "example.com",
        "issuer": "Let's Encrypt Authority X3",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2024-04-01T00:00:00Z",
        "sans": ["example.com", "www.example.com", "mail.example.com", "api.example.com"],
        "serial": "04:AB:12:CD:EF:56:78:90",
        "fingerprint": "sha256:abc123def456",
    },
    {
        "id": 2,
        "domain": "example.com",
        "issuer": "DigiCert SHA2 Secure Server CA",
        "not_before": "2024-03-15T00:00:00Z",
        "not_after": "2025-03-15T00:00:00Z",
        "sans": [
            "example.com",
            "www.example.com",
            "dev.example.com",
            "staging.example.com",
            "admin.example.com",
        ],
        "serial": "07:CD:89:AB:12:34:56:EF",
        "fingerprint": "sha256:789abc123def",
    },
    {
        "id": 3,
        "domain": "secure.example.com",
        "issuer": "Sectigo RSA Domain Validation Secure Server CA",
        "not_before": "2023-06-01T00:00:00Z",
        "not_after": "2024-06-01T00:00:00Z",
        "sans": ["secure.example.com", "vault.example.com", "secret-api.example.com"],
        "serial": "0A:BC:DE:F0:12:34:56:78",
        "fingerprint": "sha256:def789abc012",
    },
    {
        "id": 4,
        "domain": "testcorp.local",
        "issuer": "TestCorp Internal CA",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:00:00Z",
        "sans": [
            "testcorp.local",
            "internal.testcorp.local",
            "vpn.testcorp.local",
            "gitlab.testcorp.local",
        ],
        "serial": "01:23:45:67:89:AB:CD:EF",
        "fingerprint": "sha256:012345abcdef",
    },
    {
        "id": 5,
        "domain": "safeservice.com",
        "issuer": "Let's Encrypt Authority X3",
        "not_before": "2024-02-01T00:00:00Z",
        "not_after": "2024-05-01T00:00:00Z",
        "sans": ["safeservice.com", "www.safeservice.com"],
        "serial": "09:87:65:43:21:FE:DC:BA",
        "fingerprint": "sha256:fedcba987654",
    },
]

VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _domain_matches_vulnerable(entry_value: str, query: str) -> bool:
    """Vulnerable: accepts wildcard patterns like *.example.com directly."""
    if query.startswith("*."):
        suffix = query[1:]  # '.example.com'
        return entry_value.endswith(suffix) or entry_value == suffix.lstrip(".")
    return query in entry_value or entry_value == query


def _domain_matches_safe(entry_value: str, query: str) -> bool:
    """Safe: exact domain or legitimate subdomain matching only."""
    return entry_value == query or entry_value.endswith("." + query)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/ct/search")
def search_vulnerable(domain: str = Query(...)):
    """Vulnerable endpoint: accepts wildcard patterns without validation."""
    results = []
    for cert in CT_LOG_DATA:
        matched_sans = [s for s in cert["sans"] if _domain_matches_vulnerable(s, domain)]
        if matched_sans or _domain_matches_vulnerable(cert["domain"], domain):
            results.append({**cert, "matched_sans": matched_sans})
    return {
        "domain": domain,
        "certificates": results,
        "total": len(results),
        "endpoint": "vulnerable",
    }


@app.get("/api/ct/search/safe")
def search_safe(domain: str = Query(...)):
    """Safe endpoint: validates domain format before processing."""
    if not VALID_DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format. Wildcards and special characters are not permitted.",
        )
    results = []
    for cert in CT_LOG_DATA:
        matched_sans = [s for s in cert["sans"] if _domain_matches_safe(s, domain)]
        if matched_sans or _domain_matches_safe(cert["domain"], domain):
            results.append({**cert, "matched_sans": matched_sans})
    return {
        "domain": domain,
        "certificates": results,
        "total": len(results),
        "endpoint": "safe",
    }


@app.get("/api/ct/certificates/{domain}")
def get_certificates(domain: str):
    """Returns certificates whose primary domain exactly matches."""
    certs = [c for c in CT_LOG_DATA if c["domain"] == domain]
    return {"domain": domain, "certificates": certs, "total": len(certs)}


@app.get("/api/ct/subdomains/{domain}")
def get_subdomains(domain: str):
    """Extracts unique subdomains for a domain across all SAN fields."""
    subdomains: set[str] = set()
    for cert in CT_LOG_DATA:
        for san in cert["sans"]:
            if san.endswith("." + domain) or san == domain:
                subdomains.add(san)
    return {
        "domain": domain,
        "subdomains": sorted(subdomains),
        "total": len(subdomains),
    }


def start(port: int = 3000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)
    return server


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
