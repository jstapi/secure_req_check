# tests/test_cli.py
import json
from click.testing import CliRunner
from secure_req_check.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "version" in result.output


def test_cli_scan_basic(sample_req_file, requests_mock, mock_nvd_response_django):
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=mock_nvd_response_django
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "-f", str(sample_req_file)])
    assert result.exit_code == 1
    assert "CVE-2022-28346" in result.output


def test_cli_scan_json_output(sample_req_file, requests_mock, mock_nvd_response_django):
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=mock_nvd_response_django
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "-f", str(sample_req_file), "-o", "json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert data[0]["cve_id"] == "CVE-2022-28346"


def test_cli_scan_quiet_no_output(sample_req_file, requests_mock, mock_nvd_response_django):
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        json=mock_nvd_response_django
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "-f", str(sample_req_file), "-o", "quiet"])
    assert result.exit_code == 1
    assert result.output == ""


def test_cli_config_show():
    runner = CliRunner()
    result = runner.invoke(main, ["config", "show"])
    assert result.exit_code == 0
    assert "API Key:" in result.output