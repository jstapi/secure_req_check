from typing import List, Optional, Set
from .parser.requirements import parse_requirements
from .nvd_client import NVDClient
from .cache.manager import CacheManager
from .models.vulnerability import Vulnerability
from .config import Config


class Scanner:
    def __init__(self, config: Config, use_cache: bool = True, verbose: bool = False):
        self.config = config
        self.use_cache = use_cache
        self.verbose = verbose
        self.client = NVDClient(
            api_key=config.api_key,
            timeout=config.request_timeout,
            verbose=verbose,
        )
        self.cache = CacheManager(cache_dir=config.cache_dir) if use_cache else None

    def scan_file(
        self,
        file_path: str,
        min_severity: Optional[str] = None,
        ignore_cves: Optional[List[str]] = None,
        ignore_packages: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        packages = parse_requirements(file_path)
        if self.verbose:
            print(f"Loaded {len(packages)} packages from {file_path}")

        all_vulnerabilities = []
        ignore_cve_set = set(ignore_cves or [])
        ignore_pkg_set = set(ignore_packages or [])

        for pkg in packages:
            if pkg.name in ignore_pkg_set:
                if self.verbose:
                    print(f"Skipping ignored package: {pkg.name}")
                continue

            if self.verbose:
                print(f"Checking {pkg.name}=={pkg.version}...")

            cves = self._get_vulnerabilities(pkg.name, pkg.version)
            for cve in cves:
                if cve.cve_id in ignore_cve_set:
                    continue
                if min_severity:
                    if self._severity_less_than(cve.severity, min_severity):
                        continue
                all_vulnerabilities.append(cve)

        return all_vulnerabilities

    def _get_vulnerabilities(self, package_name: str, version: str) -> List[Vulnerability]:
        cache_key = f"{package_name}:{version}"
        if self.cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                if self.verbose:
                    print(f"  Cache hit for {package_name}")
                return cached

        try:
            vulns = self.client.get_vulnerabilities(package_name, version)
        except Exception as e:
            if self.verbose:
                print(f"  Error fetching data: {e}")
            return []

        if self.cache:
            self.cache.set(cache_key, vulns)
        return vulns

    @staticmethod
    def _severity_less_than(sev1: str, sev2: str) -> bool:
        levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        return levels.get(sev1, -1) < levels.get(sev2, -1)