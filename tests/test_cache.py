# tests/test_cache.py
import time
from secure_req_check.cache.manager import CacheManager
from secure_req_check.models.vulnerability import Vulnerability


def test_cache_set_get(tmp_path):
    cache = CacheManager(cache_dir=tmp_path)
    vulns = [
        Vulnerability(
            cve_id="CVE-123",
            description="Test",
            severity="HIGH",
            package="test",
            affected_version="1.0"
        )
    ]
    cache.set("test_key", vulns)
    retrieved = cache.get("test_key")
    assert len(retrieved) == 1
    assert retrieved[0].cve_id == "CVE-123"


def test_cache_expiration(tmp_path):
    cache = CacheManager(cache_dir=tmp_path)
    vulns = [Vulnerability(cve_id="CVE-123", description="Test", severity="HIGH")]

    # Set TTL to 0 to force immediate expiration
    cache.TTL = 0
    cache.set("expire_key", vulns)

    retrieved = cache.get("expire_key")
    assert retrieved is None


def test_cache_clear(tmp_path):
    cache = CacheManager(cache_dir=tmp_path)
    cache.set("key1", [])
    cache.set("key2", [])
    assert len(list(tmp_path.glob("*.json"))) == 2
    cache.clear()
    assert len(list(tmp_path.glob("*.json"))) == 0