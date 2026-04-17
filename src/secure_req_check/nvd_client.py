import time
import requests
from typing import List, Optional
from .models.vulnerability import Vulnerability


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30, verbose: bool = False):
        self.api_key = api_key
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "secure-req-check/0.1.0"})
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        self._last_request_time = 0
        self._rate_limit_delay = 0.6 if api_key else 6.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - elapsed)

    def _request(self, params: dict) -> dict:
        self._rate_limit()
        response = self.session.get(
            self.BASE_URL,
            params=params,
            timeout=self.timeout,
        )
        self._last_request_time = time.time()
        response.raise_for_status()
        return response.json()

    def get_vulnerabilities(self, package_name: str, version: str) -> List[Vulnerability]:
        cpe_name = self._build_cpe(package_name, version)
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": 2000,
        }
        try:
            data = self._request(params)
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"    NVD API error: {e}")
            return []

        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            vuln = self._parse_cve(cve, version, package_name)
            if vuln:
                vulns.append(vuln)
        return vulns

    def _build_cpe(self, package_name: str, version: str) -> str:
        vendor = self._guess_vendor(package_name)
        return f"cpe:2.3:a:{vendor}:{package_name}:{version}:*:*:*:*:*:*:*"

    def _guess_vendor(self, package_name: str) -> str:
        common_vendors = {
            "django": "djangoproject",
            "flask": "palletsprojects",
            "requests": "python-requests",
            "pillow": "python-pillow",
        }
        return common_vendors.get(package_name.lower(), package_name)

    def _parse_cve(self, cve_data: dict, target_version: str, package_name: str) -> Optional[Vulnerability]:
        cve_id = cve_data.get("id")
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        metrics = cve_data.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        severity = cvss_v3.get("baseSeverity", "UNKNOWN")
        score = cvss_v3.get("baseScore")

        if not self._is_version_affected(cve_data, target_version):
            return None

        return Vulnerability(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=score,
            package=package_name,
            affected_version=target_version,
        )

    def _is_version_affected(self, cve_data: dict, version: str) -> bool:
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        version_start = cpe_match.get("versionStartIncluding")
                        version_end = cpe_match.get("versionEndExcluding")
                        if version_start and version < version_start:
                            continue
                        if version_end and version >= version_end:
                            continue
                        return True
        return False