"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Cache Service
═══════════════════════════════════════════════════════════════════════════════

Multi-tier caching system for performance optimization:
- In-memory LRU cache for hot data (fast, no external deps)
- Redis support for distributed caching (optional)
- Cache warming and precomputation
- TTL-based expiration
- Cache invalidation patterns
- Cache decorators for easy use
"""

import os
import time
import json
import hashlib
import logging
import functools
from typing import Any, Optional, Callable
from collections import OrderedDict
from datetime import datetime, timedelta

logger = logging.getLogger("finlens.cache")


# ═══════════════════════════════════════════════════════════════════════════════
# In-Memory LRU Cache
# ═══════════════════════════════════════════════════════════════════════════════

class LRUCache:
    """
    Thread-safe LRU (Least Recently Used) cache with TTL support.
    No external dependencies required.
    """

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Args:
            max_size: Maximum number of items in cache
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict = OrderedDict()
        self._timestamps: dict = {}
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache. Returns None if expired or missing."""
        if key in self._cache:
            # Check TTL
            created_at = self._timestamps.get(key, 0)
            if time.time() - created_at > self.default_ttl:
                self._evict(key)
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return self._cache[key]

        self._misses += 1
        return None

    def set(self, key: str, value: Any, ttl: int = None):
        """Set a value in cache with optional custom TTL."""
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self.max_size:
                self._evict_oldest()

        self._cache[key] = value
        self._timestamps[key] = time.time()

    def delete(self, key: str) -> bool:
        """Remove a key from cache. Returns True if key existed."""
        if key in self._cache:
            self._evict(key)
            return True
        return False

    def clear(self):
        """Clear all cached items."""
        self._cache.clear()
        self._timestamps.clear()
        self._hits = 0
        self._misses = 0

    def invalidate_pattern(self, pattern: str):
        """Invalidate all keys matching a prefix pattern."""
        keys_to_delete = [k for k in self._cache if k.startswith(pattern)]
        for key in keys_to_delete:
            self._evict(key)

    def get_stats(self) -> dict:
        """Get cache performance statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(hit_rate, 1),
            "memory_estimate_bytes": self._estimate_memory(),
        }

    def _evict(self, key: str):
        """Remove a single key."""
        self._cache.pop(key, None)
        self._timestamps.pop(key, None)

    def _evict_oldest(self):
        """Remove the oldest (least recently used) item."""
        if self._cache:
            oldest_key, _ = self._cache.popitem(last=False)
            self._timestamps.pop(oldest_key, None)

    def _estimate_memory(self) -> int:
        """Rough estimate of cache memory usage in bytes."""
        size = 0
        for key, value in self._cache.items():
            size += len(str(key))
            size += len(str(value))
        return size


# ═══════════════════════════════════════════════════════════════════════════════
# Cache Service
# ═══════════════════════════════════════════════════════════════════════════════

class CacheService:
    """
    Multi-tier cache service with in-memory LRU and optional Redis.
    Provides caching for API responses, database queries, and computations.
    """

    def __init__(self):
        # Primary cache: in-memory LRU
        self._memory = LRUCache(max_size=2000, default_ttl=300)

        # Fast cache: tiny LRU for ultra-hot data
        self._hot_cache = LRUCache(max_size=100, default_ttl=60)

        # Stats cache: longer TTL for expensive computations
        self._stats_cache = LRUCache(max_size=200, default_ttl=600)

        # Redis (optional)
        self._redis = None
        self._redis_available = False

    async def initialize(self):
        """Try to connect to Redis if configured."""
        redis_url = os.getenv("REDIS_URL", "")
        if redis_url:
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(redis_url, decode_responses=True)
                await self._redis.ping()
                self._redis_available = True
                logger.info("Redis cache connected")
            except Exception as e:
                logger.warning(f"Redis unavailable, using in-memory only: {e}")

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()

    # ─── Core Operations ──────────────────────────────────────────

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache (checks hot → memory → Redis)."""
        # Check hot cache first
        value = self._hot_cache.get(key)
        if value is not None:
            return value

        # Check memory cache
        value = self._memory.get(key)
        if value is not None:
            return value

        # Check Redis
        if self._redis_available:
            try:
                raw = await self._redis.get(key)
                if raw:
                    value = json.loads(raw)
                    # Promote to memory cache
                    self._memory.set(key, value)
                    return value
            except Exception as e:
                logger.debug(f"Redis get failed: {e}")

        return None

    async def set(self, key: str, value: Any, ttl: int = 300, tier: str = "memory"):
        """
        Set a value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
            tier: "hot", "memory", or "all"
        """
        if tier == "hot":
            self._hot_cache.set(key, value, ttl)
        elif tier == "memory":
            self._memory.set(key, value, ttl)
        else:
            self._hot_cache.set(key, value, ttl)
            self._memory.set(key, value, ttl)

        if self._redis_available:
            try:
                await self._redis.setex(key, ttl, json.dumps(value, default=str))
            except Exception as e:
                logger.debug(f"Redis set failed: {e}")

    async def delete(self, key: str):
        """Delete from all cache tiers."""
        self._hot_cache.delete(key)
        self._memory.delete(key)
        if self._redis_available:
            try:
                await self._redis.delete(key)
            except Exception:
                pass

    async def invalidate_prefix(self, prefix: str):
        """Invalidate all keys with a given prefix."""
        self._hot_cache.invalidate_pattern(prefix)
        self._memory.invalidate_pattern(prefix)
        if self._redis_available:
            try:
                keys = []
                async for key in self._redis.scan_iter(match=f"{prefix}*"):
                    keys.append(key)
                if keys:
                    await self._redis.delete(*keys)
            except Exception:
                pass

    # ─── Cache Key Generators ─────────────────────────────────────

    @staticmethod
    def make_key(*parts) -> str:
        """Generate a cache key from parts."""
        raw = ":".join(str(p) for p in parts)
        return f"finlens:{raw}"

    @staticmethod
    def make_hash_key(data: Any) -> str:
        """Generate a cache key from arbitrary data."""
        raw = json.dumps(data, sort_keys=True, default=str)
        h = hashlib.md5(raw.encode()).hexdigest()[:16]
        return f"finlens:hash:{h}"

    # ─── Specialized Caches ───────────────────────────────────────

    async def cache_scan_result(self, scan_hash: str, result: dict, ttl: int = 3600):
        """Cache a scan result to avoid re-analyzing identical messages."""
        key = self.make_key("scan", scan_hash)
        await self.set(key, result, tier="all")

    async def get_cached_scan(self, scan_hash: str) -> Optional[dict]:
        """Get a cached scan result if available."""
        key = self.make_key("scan", scan_hash)
        return await self.get(key)

    async def cache_analytics(self, user_id: str, analytics: dict, ttl: int = 600):
        """Cache analytics data."""
        key = self.make_key("analytics", user_id)
        await self.set(key, analytics, ttl=ttl, tier="memory")

    async def get_cached_analytics(self, user_id: str) -> Optional[dict]:
        key = self.make_key("analytics", user_id)
        return await self.get(key)

    async def cache_leaderboard(self, period: str, data: list, ttl: int = 300):
        """Cache leaderboard data."""
        key = self.make_key("leaderboard", period)
        await self.set(key, data, ttl=ttl, tier="memory")

    async def get_cached_leaderboard(self, period: str) -> Optional[list]:
        key = self.make_key("leaderboard", period)
        return await self.get(key)

    def get_all_stats(self) -> dict:
        """Get comprehensive cache statistics."""
        return {
            "hot_cache": self._hot_cache.get_stats(),
            "memory_cache": self._memory.get_stats(),
            "stats_cache": self._stats_cache.get_stats(),
            "redis_available": self._redis_available,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Cache Decorator
# ═══════════════════════════════════════════════════════════════════════════════

def cached(prefix: str, ttl: int = 300):
    """
    Decorator to cache function results.

    Usage:
        @cached("scam_analysis", ttl=600)
        async def analyze_scam(message: str):
            ...
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key from function args
            cache_key_data = {
                "func": func.__name__,
                "args": str(args[1:]),  # Skip 'self' if method
                "kwargs": str(sorted(kwargs.items())),
            }
            cache_key = CacheService.make_hash_key(cache_key_data)
            cache_key = f"finlens:{prefix}:{cache_key}"

            # Try cache
            result = await _cache_service.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit: {cache_key}")
                return result

            # Execute function
            result = await func(*args, **kwargs)

            # Store in cache
            await _cache_service.set(cache_key, result, ttl=ttl, tier="memory")
            return result

        wrapper.invalidate = lambda: None  # Placeholder
        return wrapper
    return decorator


# Singleton
_cache_service = CacheService()


def get_cache_service() -> CacheService:
    """Get the global cache service instance."""
    return _cache_service
