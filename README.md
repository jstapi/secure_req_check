# secure-req-check

[![PyPI version](https://img.shields.io/pypi/v/secure-req-check.svg)](https://pypi.org/project/secure-req-check/)
[![Python versions](https://img.shields.io/pypi/pyversions/secure-req-check.svg)](https://pypi.org/project/secure-req-check/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A command‑line tool to scan Python `requirements.txt` files for known security vulnerabilities using the [NVD (National Vulnerability Database) API](https://nvd.nist.gov/developers/vulnerabilities).

## Features

- **Fast scanning** of `requirements.txt` with exact version matching (`package==version`).
- **Direct integration with NVD REST API** – no local vulnerability database required.
- **Flexible output formats**: table, JSON, CSV.
- **Severity filtering** – show only LOW, MEDIUM, HIGH, or CRITICAL findings.
- **Caching** – reduces API calls and speeds up repeated scans.
- **CI/CD ready** – returns non‑zero exit code when vulnerabilities are found.
- **Optional NVD API key** support for higher rate limits.

## Installation

### From PyPI (recommended)

```bash
pip install secure-req-check
```

### From source

```bash
git clone https://github.com/yourusername/secure-req-check.git
cd secure-req-check
pip install .
```

## Quick Start

1. Navigate to a directory containing a `requirements.txt` file (or create one).
2. Run the scanner:

   ```bash
   secure-req-check scan
   ```

3. Review the table of discovered vulnerabilities.

## Usage

### Scan Command

```bash
secure-req-check scan [OPTIONS] [REQUIREMENTS_FILE]
```

| Option | Description |
|--------|-------------|
| `-f, --file PATH` | Path to `requirements.txt` (default: `./requirements.txt`) |
| `-o, --output [table\|json\|csv\|quiet]` | Output format (default: `table`) |
| `--output-file PATH` | Write report to a file instead of stdout |
| `--severity [LOW\|MEDIUM\|HIGH\|CRITICAL]` | Minimum severity level to display |
| `--ignore-cve TEXT` | Ignore a specific CVE (repeatable) |
| `--ignore-package TEXT` | Ignore a package entirely (repeatable) |
| `--no-cache` | Disable local cache – always query the NVD API |
| `--timeout INTEGER` | Request timeout in seconds (default: 30) |
| `--verbose` | Print detailed progress information |

### Configuration Commands

```bash
secure-req-check config set-api-key YOUR_NVD_API_KEY   # Store API key
secure-req-check config show                           # Display current settings
secure-req-check config clear-cache                    # Remove all cached responses
```

The API key can also be provided via the environment variable `NVD_API_KEY`.

### Obtaining an NVD API Key

Public API requests are limited to **5 calls per 30 seconds**.  
To increase this limit to **50 calls per 30 seconds**, request a free API key at:  
[https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

## Example Output

### Table Format (default)

```
$ secure-req-check scan -f requirements.txt
+-----------+---------+----------------+------------+---------------------------------------------+
| Package   | Version | CVE ID         | Severity   | Description                                 |
+===========+=========+================+============+=============================================+
| django    | 3.2.12  | CVE-2022-28346 | CRITICAL   | SQL injection vulnerability in QuerySet...  |
| pillow    | 8.4.0   | CVE-2022-22817 | HIGH       | Buffer overflow in path handling...         |
+-----------+---------+----------------+------------+---------------------------------------------+

⚠️  Found 2 vulnerabilities (CRITICAL: 1, HIGH: 1)
💡 Consider upgrading affected packages.
```

### JSON Output

```bash
secure-req-check scan -o json --output-file report.json
```

### Quiet Mode for CI

```bash
secure-req-check scan --severity HIGH --output quiet
# Returns exit code 1 if any HIGH or CRITICAL vulnerabilities are present.
```

## Caching

By default, API responses are cached in `~/.cache/secure-req-check/` for 24 hours.  
Use `--no-cache` to force a fresh lookup, or `secure-req-check config clear-cache` to remove all cached data.

## CI/CD Integration

The tool exits with code `1` when at least one vulnerability is found. This behaviour makes it easy to block pipelines:

```yaml
# GitLab CI example
security_scan:
  script:
    - pip install secure-req-check
    - secure-req-check scan --severity HIGH --output quiet
```

## Limitations

- Currently supports only `package==version` syntax. Ranges (e.g., `>=`) are partially supported – the tool extracts a minimum version.
- Vendor mapping for CPE generation is based on a small built‑in list. If a package cannot be matched, you may see `N/A` in the output.

## Development

```bash
git clone https://github.com/yourusername/secure-req-check.git
cd secure-req-check
python -m venv venv
source venv/bin/activate
pip install -e .[dev]
pytest
```

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool relies on the accuracy and completeness of the NVD database. It does **not** guarantee detection of all vulnerabilities and should be used as part of a comprehensive security strategy.