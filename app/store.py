import time

class SessionStore:
    """
    In-memory state manager for Round-Trip Restoration.
    Maps placeholders (<PERSON_123>) to real values for the duration of a session.
    """
    _store = {}
    _ttl_seconds = 3600  # Expire keys after 1 hour to prevent memory bloat

    @classmethod
    def save(cls, placeholder: str, real_value: str):
        cls._store[placeholder] = {
            "value": real_value,
            "expires_at": time.time() + cls._ttl_seconds
        }

    @classmethod
    def get(cls, placeholder: str) -> str | None:
        item = cls._store.get(placeholder)
        if not item:
            return None
            
        # Check if expired
        if time.time() > item["expires_at"]:
            del cls._store[placeholder]
            return None
            
        return item["value"]

    @classmethod
    def cleanup(cls):
        """Called by main.py background task to clear old keys"""
        now = time.time()
        expired_keys = [k for k, v in cls._store.items() if now > v["expires_at"]]
        for k in expired_keys:
            del cls._store[k]