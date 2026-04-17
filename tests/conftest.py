import pytest
from pathlib import Path


@pytest.fixture
def sample_req_file(tmp_path):
    req_content = """
# Sample requirements
django==3.2.12
requests>=2.25.0
flask==0.12.2
"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(req_content)
    return req_file


@pytest.fixture
def mock_nvd_response_django():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2022-28346",
                    "descriptions": [{"lang": "en", "value": "SQL injection in Django"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseSeverity": "CRITICAL",
                                "baseScore": 9.8
                            }
                        }]
                    },
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": True,
                                "versionStartIncluding": "3.2",
                                "versionEndExcluding": "3.2.13"
                            }]
                        }]
                    }]
                }
            }
        ]
    }