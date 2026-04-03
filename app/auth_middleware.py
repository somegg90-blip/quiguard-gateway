"""
QuiGuard Phase 4: API Key Authentication Middleware
Validates incoming requests against Supabase-stored API keys.
"""

import os
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple
from dataclasses import dataclass

# Supabase client (lazy-loaded)
_supabase_client = None

def _get_supabase():
    """Lazy-initialize Supabase client."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client
    try:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL", "")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        if not url or not key:
            return None
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception as e:
        print(f"[Auth] Failed to init Supabase: {e}")
        return None


# ============================================================
# Data Classes
# ============================================================

@dataclass
class APIKeyInfo:
    """Validated API key with associated user and subscription info."""
    api_key_id: int
    user_id: str
    key_prefix: str
    plan: str
    status: str
    monthly_request_count: int
    monthly_request_limit: Optional[int]
    is_active: bool


# ============================================================
# API Key Generation
# ============================================================

def generate_api_key() -> Tuple[str, str, str]:
    """
    Generates a new API key.
    
    Returns:
        (raw_key, key_hash, key_prefix)
        
    Example:
        raw_key = "qg_sk_a3f2e8b1c4d9..."
        key_hash = "sha256:abc123..."  (stored in DB)
        key_prefix = "qg_sk_a3f2"  (shown to user for identification)
    """
    raw_key = f"qg_sk_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]  # "qg_sk_a3f2"
    return raw_key, key_hash, key_prefix


# ============================================================
# API Key Validation (called on every request)
# ============================================================

def validate_api_key(raw_key: str) -> Optional[APIKeyInfo]:
    """
    Validates an API key against Supabase.
    
    Args:
        raw_key: The raw API key from the request header
        
    Returns:
        APIKeyInfo if valid, None if invalid
        
    Flow:
        1. Hash the incoming key
        2. Look up the hash in api_keys table
        3. Check if the key is active
        4. Fetch the user's subscription
        5. Check if the subscription is active
        6. Return all info needed for rate limiting
    """
    if not raw_key:
        return None
    
    supabase = _get_supabase()
    if supabase is None:
        # No Supabase = auth disabled (dev mode)
        print("[Auth] No Supabase configured - API key auth DISABLED (dev mode)")
        return APIKeyInfo(
            api_key_id=0,
            user_id="dev",
            key_prefix="dev_mode",
            plan="community",
            status="active",
            monthly_request_count=0,
            monthly_request_limit=None,
            is_active=True,
        )
    
    # 1. Hash the incoming key
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    # 2. Look up the hash
    try:
        response = supabase.table("api_keys").select(
            "id, user_id, key_prefix, is_active, last_used_at, request_count"
        ).eq("key_hash", key_hash).eq("is_active", True).limit(1).execute()
        
        if not response.data:
            print("[Auth] Invalid API key")
            return None
        
        key_row = response.data[0]
        
    except Exception as e:
        print(f"[Auth] Error looking up API key: {e}")
        return None
    
    # 3. Fetch subscription
    try:
        sub_response = supabase.table("subscriptions").select(
            "plan, status, monthly_request_count, monthly_request_limit"
        ).eq("user_id", key_row["user_id"]).eq("status", "active").limit(1).execute()
        
        if not sub_response.data:
            print(f"[Auth] No active subscription for user {key_row['user_id']}")
            return None
        
        sub_row = sub_response.data[0]
        
    except Exception as e:
        print(f"[Auth] Error fetching subscription: {e}")
        return None
    
    # 4. Build and return
    return APIKeyInfo(
        api_key_id=key_row["id"],
        user_id=key_row["user_id"],
        key_prefix=key_row["key_prefix"],
        plan=sub_row["plan"],
        status=sub_row["status"],
        monthly_request_count=sub_row["monthly_request_count"],
        monthly_request_limit=sub_row["monthly_request_limit"],
        is_active=key_row["is_active"],
    )


# ============================================================
# API Key CRUD Operations
# ============================================================

def create_api_key_for_user(user_id: str, name: str = "Default Key") -> Optional[dict]:
    """
    Creates a new API key for a user.
    Only called from the management API, not on proxy requests.
    
    Args:
        user_id: Supabase user UUID
        name: Human-readable name for the key
        
    Returns:
        dict with key info, or None on failure
        
    Note: The raw key is ONLY returned here - it cannot be retrieved again.
    """
    supabase = _get_supabase()
    if supabase is None:
        return None
    
    # Check subscription limits
    try:
        sub_response = supabase.table("subscriptions").select(
            "plan, max_api_keys"
        ).eq("user_id", user_id).eq("status", "active").limit(1).execute()
        
        if not sub_response.data:
            return {"error": "No active subscription"}
        
        sub = sub_response.data[0]
        
        # Count existing active keys
        keys_response = supabase.table("api_keys").select(
            "id", count="exact"
        ).eq("user_id", user_id).eq("is_active", True).execute()
        
        key_count = keys_response.count if hasattr(keys_response, 'count') else len(keys_response.data)
        
        if key_count >= sub["max_api_keys"]:
            return {"error": f"API key limit reached ({sub['max_api_keys']} keys for {sub['plan']} plan)"}
    except Exception as e:
        print(f"[API Keys] Error checking limits: {e}")
        return {"error": "Failed to check limits"}
    
    # Generate key
    raw_key, key_hash, key_prefix = generate_api_key()
    
    # Store in Supabase
    try:
        response = supabase.table("api_keys").insert({
            "user_id": user_id,
            "key_hash": key_hash,
            "key_prefix": key_prefix,
            "name": name,
        }).execute()
        
        return {
            "id": response.data[0]["id"],
            "name": name,
            "key": raw_key,  # ONLY shown once!
            "key_prefix": key_prefix,
            "created_at": response.data[0].get("created_at"),
        }
    except Exception as e:
        print(f"[API Keys] Error creating key: {e}")
        return {"error": "Failed to create API key"}


def list_api_keys_for_user(user_id: str) -> list:
    """Lists all API keys for a user (never returns the raw key or hash)."""
    supabase = _get_supabase()
    if supabase is None:
        return []
    
    try:
        response = supabase.table("api_keys").select(
            "id, name, key_prefix, is_active, last_used_at, request_count, created_at, expires_at"
        ).eq("user_id", user_id).order("created_at", desc=True).execute()
        
        return response.data
    except Exception as e:
        print(f"[API Keys] Error listing keys: {e}")
        return []


def revoke_api_key(key_id: int, user_id: str) -> bool:
    """Revokes (deactivates) an API key. Returns True on success."""
    supabase = _get_supabase()
    if supabase is None:
        return False
    
    try:
        response = supabase.table("api_keys").update({
            "is_active": False
        }).eq("id", key_id).eq("user_id", user_id).execute()
        
        return len(response.data) > 0
    except Exception as e:
        print(f"[API Keys] Error revoking key: {e}")
        return False


# ============================================================
# Rate Limit Check
# ============================================================

def check_rate_limit(key_info: APIKeyInfo) -> Tuple[bool, str]:
    """
    Checks if a request should be allowed based on plan limits.
    
    Returns:
        (allowed: bool, message: str)
    """
    # Enterprise = unlimited
    if key_info.plan == "enterprise":
        return True, "OK"
    
    # Community plan: enforce default limit of 1,000/month
    limit = key_info.monthly_request_limit
    if limit is None:
        if key_info.plan == "community":
            limit = 1000
        else:
            return True, "OK"
    
    count = key_info.monthly_request_count or 0
    if count >= limit:
        return False, f"Monthly request limit reached ({count}/{limit}). Upgrade your plan at quiguard.ai/pricing"
    
    return True, f"OK ({count}/{limit} used this month)"