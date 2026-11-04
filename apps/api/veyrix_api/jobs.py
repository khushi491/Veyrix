"""PostgreSQL is the durable queue; Redis is a best-effort wake-up signal."""

import logging

from redis import Redis, RedisError

from veyrix_api.config import settings

logger = logging.getLogger(__name__)
WAKE_KEY = "veyrix:worker:wake"


def redis_client() -> Redis:
    return Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=3)


def notify_worker() -> None:
    try:
        with redis_client() as client, client.pipeline() as pipe:
            pipe.lpush(WAKE_KEY, "1")
            pipe.ltrim(WAKE_KEY, 0, 99)
            pipe.expire(WAKE_KEY, 60)
            pipe.execute()
    except RedisError:
        # The committed database job remains discoverable by worker polling.
        logger.warning("worker_notification_unavailable")
