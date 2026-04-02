"""
QuiGuard Audit Logger - Phase 3: Secure Ledger
Writes audit events to Supabase Postgres instead of local .jsonl
Maintains backward compatibility with local file logging as fallback.
"""

import json
import os
import asyncio
from datetime import datetime, timezone
from typing import Optional

# Supabase client (lazy-loaded to avoid import-time errors)
_supabase_client = None

def _get_supabase_client():
    """
    Lazy-initialize the Supabase client.
    Uses the service role key for server-side writes (bypasses RLS).
    Falls back to local file logging if Supabase is not configured.
    """
    global _supabase_client
    
    if _supabase_client is not None:
        return _supabase_client
    
    try:
        from supabase import create_client, Client
        
        supabase_url = os.getenv("SUPABASE_URL", "")
        supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        
        if not supabase_url or not supabase_key:
            print("[Audit Logger] ⚠️  SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set. Falling back to local file.")
            return None
        
        _supabase_client = create_client(supabase_url, supabase_key)
        print("[Audit Logger] ✅ Connected to Supabase.")
        return _supabase_client
        
    except ImportError:
        print("[Audit Logger] ⚠️  'supabase' package not installed. Falling back to local file.")
        print("[Audit Logger] Run: pip install supabase")
        return None
    except Exception as e:
        print(f"[Audit Logger] ⚠️  Failed to connect to Supabase: {e}. Falling back to local file.")
        return None


# Legacy local file logging (kept as fallback)
LOG_FILE = "audit_log.jsonl"

def _write_to_local_file(event_type: str, original: str, sanitized: str, entities: list):
    """Legacy: Write to local JSONL file (fallback mode)."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "risk_detected": len(entities) > 0,
        "entities_blocked": entities,
        "original_snippet": (original[:100] + '...') if len(original) > 100 else original,
        "sanitized_snippet": (sanitized[:100] + '...') if len(sanitized) > 100 else sanitized
    }
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Audit Log Error] Failed to write to local file: {e}")


def log_audit_event(
    event_type: str,
    original: str,
    sanitized: str,
    entities: list,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    model: Optional[str] = None,
    provider: Optional[str] = None,
):
    """
    Logs a security audit event.
    
    Primary: Writes to Supabase Postgres (async, non-blocking).
    Fallback: Writes to local audit_log.jsonl if Supabase is unavailable.
    
    Args:
        event_type: Type of event (e.g., "prompt_sanitized", "request_blocked")
        original: The original (unsanitized) text snippet
        sanitized: The sanitized text snippet (with placeholders)
        entities: List of entity types that were detected (e.g., ["EMAIL_ADDRESS", "PERSON"])
        user_id: Optional Supabase user UUID (for multi-tenancy)
        session_id: Optional session identifier
        request_id: Optional request identifier for tracing
        model: Optional LLM model name used
        provider: Optional LLM provider (openai, anthropic, etc.)
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    log_entry = {
        "timestamp": timestamp,
        "event": event_type,
        "risk_detected": len(entities) > 0,
        "entities_blocked": entities,
        "original_snippet": (original[:500] + '...') if len(original) > 500 else original,
        "sanitized_snippet": (sanitized[:500] + '...') if len(sanitized) > 500 else sanitized,
        "user_id": user_id,
        "session_id": session_id,
        "request_id": request_id,
        "model": model,
        "provider": provider,
    }
    
    # Try Supabase first
    client = _get_supabase_client()
    
    if client is not None:
        try:
            # Clean up the entry — remove None values to avoid Postgres issues
            clean_entry = {k: v for k, v in log_entry.items() if v is not None}
            
            # Fire-and-forget insert (non-blocking)
            client.table("audit_logs").insert(clean_entry).execute()
            
        except Exception as e:
            print(f"[Audit Logger] ⚠️  Supabase write failed: {e}. Falling back to local file.")
            _write_to_local_file(event_type, original, sanitized, entities)
    else:
        # No Supabase — write locally
        _write_to_local_file(event_type, original, sanitized, entities)


# ============================================================
# Utility: Migrate existing local .jsonl logs to Supabase
# Run this ONCE to migrate historical data
# ============================================================

def migrate_local_logs_to_supabase():
    """
    Reads all entries from audit_log.jsonl and inserts them into Supabase.
    Run this as a one-time migration script:
        python -c "from app.audit_logger import migrate_local_logs_to_supabase; migrate_local_logs_to_supabase()"
    """
    client = _get_supabase_client()
    
    if client is None:
        print("[Migration] ❌ Cannot migrate — Supabase not configured.")
        return
    
    if not os.path.exists(LOG_FILE):
        print(f"[Migration] ❌ No local log file found: {LOG_FILE}")
        return
    
    entries = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # Map old format to new table schema
                clean_entry = {
                    "timestamp": entry.get("timestamp"),
                    "event": entry.get("event"),
                    "risk_detected": entry.get("risk_detected", False),
                    "entities_blocked": entry.get("entities_blocked", []),
                    "original_snippet": entry.get("original_snippet"),
                    "sanitized_snippet": entry.get("sanitized_snippet"),
                }
                entries.append(clean_entry)
            except json.JSONDecodeError:
                continue
    
    if not entries:
        print("[Migration] No valid entries found in local log file.")
        return
    
    # Insert in batches of 100 (Supabase limit)
    batch_size = 100
    total_inserted = 0
    
    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        try:
            client.table("audit_logs").insert(batch).execute()
            total_inserted += len(batch)
            print(f"[Migration] Inserted batch {i // batch_size + 1}: {len(batch)} entries")
        except Exception as e:
            print(f"[Migration] ❌ Batch {i // batch_size + 1} failed: {e}")
    
    print(f"[Migration] ✅ Complete. Migrated {total_inserted} entries to Supabase.")
