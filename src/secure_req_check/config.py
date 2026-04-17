import os
import json
from pathlib import Path
from typing import Optional


class Config:
    def __init__(self):
        self.config_dir = Path.home() / ".config" / "secure-req-check"
        self.config_file = self.config_dir / "config.json"
        self.cache_dir = Path.home() / ".cache" / "secure-req-check"
        self._ensure_dirs()
        self._data = self._load()

    def _ensure_dirs(self):
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def _save(self):
        with open(self.config_file, "w") as f:
            json.dump(self._data, f, indent=2)

    @property
    def api_key(self) -> Optional[str]:
        env_key = os.environ.get("NVD_API_KEY")
        if env_key:
            return env_key
        return self._data.get("api_key")

    def set_api_key(self, key: str):
        self._data["api_key"] = key
        self._save()

    @property
    def request_timeout(self) -> int:
        return self._data.get("request_timeout", 30)

    @request_timeout.setter
    def request_timeout(self, value: int):
        self._data["request_timeout"] = value
        self._save()