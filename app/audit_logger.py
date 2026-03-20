import json
from datetime import datetime

LOG_FILE = "audit_log.jsonl"  # JSON Lines format (easy to parse/stream)

def log_audit_event(event_type: str, original: str, sanitized: str, entities: list):
    """
    Logs security events to a file for enterprise auditing.
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event_type,
        "risk_detected": len(entities) > 0,
        "entities_blocked": entities,
        # Truncate snippets to keep log file size manageable
        "original_snippet": (original[:100] + '...') if len(original) > 100 else original,
        "sanitized_snippet": (sanitized[:100] + '...') if len(sanitized) > 100 else sanitized
    }
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Audit Log Error] Failed to write log: {e}")