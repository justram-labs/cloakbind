"""
Recent-activity history for the dashboard.

A fixed-size in-memory ring buffer (nothing is written to disk; the log file
remains the permanent record). Account names are stored as received and masked
when served, unless [status] show_account_names = true.
"""

import collections
import threading
import time

KINDS = {
    # kind: (level, label shown on the dashboard)
    "bind_ok": ("ok", "Signed in"),
    "bind_failed": ("fail", "Sign-in failed"),
    "bind_refused": ("fail", "Refused by proxy"),
    "client_rejected": ("warn", "Client not allowed"),
    "write_blocked": ("warn", "Write blocked"),
    "no_dc": ("fail", "No DC available"),
    "dc_down": ("fail", "DC went down"),
    "dc_up": ("ok", "DC came up"),
}


class EventLog:
    def __init__(self, size=200):
        self._lock = threading.Lock()
        self._items = collections.deque(maxlen=size)
        self._seq = 0

    def resize(self, size):
        with self._lock:
            self._items = collections.deque(self._items, maxlen=max(10, size))

    def add(self, kind, account=None, client=None, dc=None, listener=None, detail=None):
        level, label = KINDS.get(kind, ("info", kind))
        with self._lock:
            self._seq += 1
            self._items.append({
                "id": self._seq,
                "ts": time.time(),
                "kind": kind,
                "level": level,
                "label": label,
                "account": account,
                "client": client,
                "dc": dc,
                "listener": listener,
                "detail": detail,
            })

    def snapshot(self, show_account_names=False, limit=None):
        """Newest first, with account names masked unless show_account_names."""
        with self._lock:
            items = list(self._items)
        items.reverse()
        if limit:
            items = items[:limit]
        out = []
        for e in items:
            e = dict(e)
            if e["account"] and not show_account_names:
                e["account"] = mask_account(e["account"])
            out.append(e)
        return out

    def clear(self):
        with self._lock:
            self._items.clear()


EVENTS = EventLog()


def _mask(s):
    if not s:
        return s
    if len(s) <= 2:
        return "•" * len(s)
    # Fixed-length mask so the name's length isn't revealed either.
    return s[0] + "•••" + s[-1]


def mask_account(name):
    """
    Hide the personal part of an account name but keep its shape, so admins
    can still tell formats and domains apart:
        jdoe@corp.example.com                      -> j•••e@corp.example.com
        CORP\\jdoe                            -> CORP\\j•••e
        CN=John Doe,OU=Users,DC=corp,DC=example,DC=com -> CN=J•••e,OU=Users,DC=corp,DC=example,DC=com
        jdoe                                   -> j•••e
    """
    if not name or name == "(anonymous)":
        return name
    if "=" in name:
        first, sep, rest = name.partition(",")
        attr, eq, value = first.partition("=")
        return attr + eq + _mask(value.strip()) + sep + rest
    if "\\" in name:
        dom, _, user = name.partition("\\")
        return dom + "\\" + _mask(user)
    if "@" in name:
        user, _, dom = name.rpartition("@")
        return _mask(user) + "@" + dom
    return _mask(name)
