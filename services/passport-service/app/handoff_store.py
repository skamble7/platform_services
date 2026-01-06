# services/passport-service/app/handoff_store.py
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional


class InMemoryHandoffStore:
    """
    One-time code exchange store for VS Code "handoff" flow.

    - /auth/vscode/finish creates a short-lived code mapped to a session id (sid)
    - extension POSTs code to /auth/handoff/exchange to obtain {sid, session}
    """
    def __init__(self) -> None:
        self._codes: Dict[str, Dict[str, Any]] = {}

    def issue_code(self, *, sid: str, ttl_seconds: int = 60) -> str:
        code = uuid.uuid4().hex
        now = int(time.time())
        self._codes[code] = {
            "sid": sid,
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }
        return code

    def pop_sid(self, code: str) -> Optional[str]:
        rec = self._codes.pop(code, None)
        if not rec:
            return None
        if int(time.time()) > int(rec.get("expires_at") or 0):
            return None
        return rec.get("sid")
