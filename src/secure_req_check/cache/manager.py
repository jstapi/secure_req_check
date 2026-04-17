import json
import hashlib
import time
from pathlib import Path
from typing import List, Optional
from ..models.vulnerability import Vulnerability


class CacheManager:
    TTL = 86400  # 24 hours

    def __init__(self, cache_dir: Optional[Path] = None):
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "secure-req-check"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_to_filename(self, key: str) -> Path:
        hash_digest = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hash_digest}.json"

    def get(self, key: str) -> Optional[List[Vulnerability]]:
        file_path = self._key_to_filename(key)
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            if time.time() - data.get("timestamp", 0) > self.TTL:
                file_path.unlink(missing_ok=True)
                return None
            return [Vulnerability.from_dict(v) for v in data.get("vulnerabilities", [])]
        except (json.JSONDecodeError, KeyError):
            return None

    def set(self, key: str, vulnerabilities: List[Vulnerability]):
        file_path = self._key_to_filename(key)
        data = {
            "timestamp": time.time(),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }
        with open(file_path, "w") as f:
            json.dump(data, f)

    def clear(self):
        for file in self.cache_dir.glob("*.json"):
            file.unlink()