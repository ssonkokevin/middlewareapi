"""
Request counter service for tracking successful verifications per client IP.

Redis key format:
    stats:{year}:{month:02d}:{client_ip}:{service}:{environment}

Example:
    stats:2026:05:10.20.20.1:nira:prod   = 45
    stats:2026:05:10.20.20.1:refugee:test = 12

Counters persist for 2 years (63,072,000 seconds) and are used for
monthly billing and usage reporting per whitelisted client IP.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import redis.asyncio as redis

from app.core.config import settings

logger = logging.getLogger("middleware")

_EAT = timezone(timedelta(hours=3))

# Retain counters for 2 years
_COUNTER_TTL_SECONDS = 63_072_000


class CounterService:
    """Tracks successful API verification requests per IP, service, and month."""

    def __init__(self):
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        if self._redis is None:
            self._redis = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=30,
            )
        return self._redis

    async def increment(
        self,
        client_ip: str,
        service: str,
        environment: str,
    ) -> int:
        """
        Increment the successful request counter for a client IP.

        Args:
            client_ip   : Whitelisted IP address of the caller
            service     : "nira" or "refugee"
            environment : "prod" or "test"

        Returns:
            Updated count for this IP/service/env in the current month.
        """
        now = datetime.now(_EAT)
        key = f"stats:{now.year}:{now.month:02d}:{client_ip}:{service}:{environment}"

        r = await self._get_redis()
        count = await r.incr(key)

        # Set TTL only on first creation
        if count == 1:
            await r.expire(key, _COUNTER_TTL_SECONDS)

        logger.info(
            f"Counter incremented: {client_ip} → {service}/{environment} "
            f"= {count} ({now.strftime('%Y-%m')})"
        )
        return count

    async def get_monthly_summary(
        self,
        year: int,
        month: int,
    ) -> Dict[str, Any]:
        """
        Return all counters for a given month grouped by client IP.

        Args:
            year  : e.g. 2026
            month : 1–12

        Returns:
            {
              "period": "2026-05",
              "clients": {
                "10.20.20.1": {
                  "nira:prod": 45,
                  "refugee:prod": 30,
                  "total": 75
                },
                ...
              },
              "grand_total": 105
            }
        """
        r = await self._get_redis()
        pattern = f"stats:{year}:{month:02d}:*"
        keys = await r.keys(pattern)

        clients: Dict[str, Dict[str, Any]] = {}
        grand_total = 0

        for key in keys:
            # key format: stats:year:month:ip:service:env
            parts = key.split(":")
            if len(parts) < 6:
                continue

            client_ip = parts[3]
            service   = parts[4]
            env       = parts[5]
            count     = int(await r.get(key) or 0)

            if client_ip not in clients:
                clients[client_ip] = {"total": 0}

            clients[client_ip][f"{service}:{env}"] = count
            clients[client_ip]["total"] += count
            grand_total += count

        return {
            "period":      f"{year}-{month:02d}",
            "clients":     clients,
            "grand_total": grand_total,
        }

    async def get_client_monthly_summary(
        self,
        client_ip: str,
        year: int,
        month: int,
    ) -> Dict[str, Any]:
        """
        Return counters for a single client IP for a given month.

        Returns:
            {
              "period": "2026-05",
              "client_ip": "10.20.20.1",
              "breakdown": {
                "nira:prod": 45,
                "refugee:prod": 30
              },
              "total": 75
            }
        """
        r = await self._get_redis()
        pattern = f"stats:{year}:{month:02d}:{client_ip}:*"
        keys = await r.keys(pattern)

        breakdown: Dict[str, int] = {}
        total = 0

        for key in keys:
            parts = key.split(":")
            if len(parts) < 6:
                continue

            service = parts[4]
            env     = parts[5]
            count   = int(await r.get(key) or 0)

            breakdown[f"{service}:{env}"] = count
            total += count

        return {
            "period":    f"{year}-{month:02d}",
            "client_ip": client_ip,
            "breakdown": breakdown,
            "total":     total,
        }


# Application-wide singleton
counter_service = CounterService()
