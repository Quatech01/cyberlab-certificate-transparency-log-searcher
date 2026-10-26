import json
import subprocess
import sys

import httpx
import pytest

sys.path.insert(0, "..")
from server.main import start

BASE_URL = None
_server = None


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server
    port = 3456
    BASE_URL = f"http://127.0.0.1:{port}"
    _server = start(port)
    yield
    _server.should_exit = True


# ---------------------------------------------------------------------------
# Group 1 — Server health
# ---------------------------------------------------------------------------

def test_health_returns_200():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.status_code == 200


def test_health_returns_ok_status():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.json()["status"] == "ok"


def test_health_is_json():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.headers["content-type"].startswith("application/json")


# ---------------------------------------------------------------------------
# Group 2 — True positives (tool detects vulnerabilities)
# ---------------------------------------------------------------------------

def test_vulnerable_endpoint_accepts_wildcard_pattern():
    r = httpx.get(f"{BASE_URL}/api/ct/search", params={"domain": "*.example.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["total"] > 0, "Vulnerable endpoint must accept wildcard and return results"


def test_vulnerable_endpoint_exposes_sensitive_subdomains():
    r = httpx.get(f"{BASE_URL}/api/ct/search", params={"domain": "example.com"})
    data = r.json()
    all_sans = []
    for cert in data["certificates"]:
        all_sans.extend(cert.get("sans", []))
    sensitive = [s for s in all_sans if any(p in s for p in ["admin", "dev", "staging", "vault", "secret"])]
    assert len(sensitive) > 0, "Vulnerable search must expose sensitive SANs"


def test_tool_detects_at_least_one_finding():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data["findings"]) > 0, "Tool must report at least one finding"


def test_tool_detects_wildcard_injection():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    vuln_types = [f["vulnerability_type"] for f in data["findings"]]
    assert any("Wildcard" in vt for vt in vuln_types), "Tool must detect wildcard pattern injection"


def test_tool_discovers_subdomains():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    assert len(data["subdomains_discovered"]) > 0, "Tool must discover subdomains from CT log"


def test_tool_detects_sensitive_subdomain_exposure():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    vuln_types = [f["vulnerability_type"] for f in data["findings"]]
    assert any("Sensitive" in vt for vt in vuln_types), "Tool must detect sensitive subdomain exposure"


# ---------------------------------------------------------------------------
# Group 3 — False positives (safe endpoints must not be flagged)
# ---------------------------------------------------------------------------

def test_safe_endpoint_rejects_wildcard():
    r = httpx.get(f"{BASE_URL}/api/ct/search/safe", params={"domain": "*.example.com"})
    assert r.status_code == 400, "Safe endpoint must reject wildcard queries"


def test_safe_endpoint_accepts_valid_domain():
    r = httpx.get(f"{BASE_URL}/api/ct/search/safe", params={"domain": "example.com"})
    assert r.status_code == 200


def test_safe_endpoint_rejects_special_characters():
    r = httpx.get(f"{BASE_URL}/api/ct/search/safe", params={"domain": "bad@domain!.com"})
    assert r.status_code == 400


def test_tool_does_not_flag_safe_endpoint():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    for finding in data["findings"]:
        assert "/safe" not in finding["endpoint"], "Tool must not flag the safe endpoint"


# ---------------------------------------------------------------------------
# Group 4 — Output format validation
# ---------------------------------------------------------------------------

def test_tool_output_is_valid_json():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    json.loads(result.stdout)  # must not raise


def test_tool_output_has_target_field():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    assert "target" in data


def test_tool_output_has_findings_field():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_tool_output_has_summary_field():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    assert "summary" in data
    assert isinstance(data["summary"], str)


def test_findings_have_required_fields():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    for finding in data["findings"]:
        assert "endpoint" in finding
        assert "vulnerability_type" in finding
        assert "evidence" in finding
        assert "severity" in finding


def test_severity_values_are_valid():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "example.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    valid_severities = {"low", "medium", "high", "critical"}
    for finding in data["findings"]:
        assert finding["severity"].lower() in valid_severities


# ---------------------------------------------------------------------------
# Group 5 — Edge cases
# ---------------------------------------------------------------------------

def test_unreachable_server_returns_empty_findings():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:19999"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, "Tool must not crash on unreachable server"
    data = json.loads(result.stdout)
    assert data["findings"] == [], "Findings must be empty for unreachable server"


def test_unreachable_server_summary_mentions_unreachable():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:19999"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    data = json.loads(result.stdout)
    assert "unreachable" in data["summary"].lower()


def test_unknown_domain_returns_zero_subdomains():
    r = httpx.get(f"{BASE_URL}/api/ct/subdomains/nonexistent-domain-xyz.com")
    assert r.status_code == 200
    data = r.json()
    assert data["subdomains"] == []
    assert data["total"] == 0


def test_safe_endpoint_returns_zero_for_unknown_domain():
    r = httpx.get(f"{BASE_URL}/api/ct/search/safe", params={"domain": "nosuchdomainxyz.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0


def test_tool_handles_domain_with_no_findings_gracefully():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL, "--domain", "safeservice.com"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data["findings"], list)
