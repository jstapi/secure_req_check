# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 - 2026-04-18

### Fixed
- Fixed `config show` command failing in CI/CD environments when configuration file doesn't exist
- Improved error handling in Config class for restricted filesystem access
- Fixed cache expiration test by using TTL override instead of monkeypatching system time
- Fixed JSON output format to exclude summary text for proper parsing

## 0.1.0 - 2026-04-17

### Added
- Initial release
- Scan requirements.txt for vulnerabilities using NVD API
- Support for table, JSON, and CSV output formats
- Configurable API key for higher rate limits
- Local caching of NVD responses
- Severity filtering (LOW, MEDIUM, HIGH, CRITICAL)
- CI/CD integration with exit codes