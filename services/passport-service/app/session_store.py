from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class SessionRecord:
    data: Dict[str, Any]
    expires_at: float


class InMemorySessionStore:
    """
    Simple store for dev/single-instance.
    Replace with Redis/Mongo for production HA.
    """
    def __init__(self) -> None:
        self._store: Dict[str, SessionRecord] = {}

    def get(self, sid: str) -> Optional[Dict[str, Any]]:
        rec = self._store.get(sid)
        if not rec:
            return None
        if rec.expires_at < time.time():
            self._store.pop(sid, None)
            return None
        return rec.data

    def set(self, sid: str, data: Dict[str, Any], ttl_seconds: int) -> None:
        self._store[sid] = SessionRecord(data=data, expires_at=time.time() + ttl_seconds)

    def delete(self, sid: str) -> None:
        self._store.pop(sid, None)
