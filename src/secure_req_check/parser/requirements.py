import re
from typing import List
from ..models.package import Package


def parse_requirements(file_path: str) -> List[Package]:
    packages = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                packages.append(Package(name=name.strip(), version=version.strip()))
            elif ">=" in line or "<=" in line or "~=" in line:
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)([~<>=!]=.*)$", line)
                if match:
                    name = match.group(1)
                    spec = match.group(2)
                    version = _extract_min_version(spec)
                    if version:
                        packages.append(Package(name=name, version=version))
    return packages


def _extract_min_version(spec: str) -> str:
    versions = re.findall(r"[0-9]+\.[0-9]+(?:\.[0-9]+)*", spec)
    if versions:
        return versions[0]
    return "unknown"