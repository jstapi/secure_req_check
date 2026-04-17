import pytest
import requests
from secure_req_check.nvd_client import NVDClient
from secure_req_check.models.vulnerability import Vulnerability


def test_build_cpe():
    client = NVDClient()
    cpe = client._build_cpe("django", "3.2.12")
    assert cpe == "cpe:2.3:a:djangoproject:django:3.2.12:*:*:*:*:*:*:*"


def test_guess_vendor_known():
    client = NVDClient()
    assert client._guess_vendor("django") == "djangoproject"
    assert client._guess_vendor("flask") == "palletsprojects"
    assert client._guess_vendor("unknown") == "unknown"


def test_parse_cve(mock_nvd_response_django):
    client = NVDClient()
    cve_data = mock_nvd_response_django["vulnerabilities"][0]["cve"]
    vuln = client._parse_cve(cve_data, "3.2.12", "django")
    assert vuln.cve_id == "CVE-2022-28346"
    assert vuln.severity == "CRITICAL"
    assert vuln.package == "django"
    assert vuln.affected_version == "3.2.12"


def test_is_version_affected_true(mock_nvd_response_django):
    client = NVDClient()
    cve_data = mock_nvd_response_django["vulnerabilities"][0]["cve"]
    assert client._is_version_affected(cve_data, "3.2.12") is True
    assert client._is_version_affected(cve_data, "3.2.0") is True
    assert client._is_version_affected(cve_data, "3.2.13") is False


def test_get_vulnerabilities_integration(requests_mock, mock_nvd_response_django):
    client = NVDClient()
    cpe = "cpe:2.3:a:djangoproject:django:3.2.12:*:*:*:*:*:*:*"
    requests_mock.get(
        f"{client.BASE_URL}?cpeName={cpe}&resultsPerPage=2000",
        json=mock_nvd_response_django
    )
    vulns = client.get_vulnerabilities("django", "3.2.12")
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2022-28346"