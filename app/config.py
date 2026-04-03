import os
import yaml
import copy
from contextvars import ContextVar
from pydantic_settings import BaseSettings, SettingsConfigDict


# ============================================================
# Utility Functions (used by policy system)
# ============================================================

def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries. Override values take precedence."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def compute_policy_diff(default: dict, current: dict) -> dict:
    """Compute the difference between default and current policy (only changes)."""
    diff = {}
    for key, value in current.items():
        if key not in default:
            diff[key] = value
        elif isinstance(value, dict) and isinstance(default[key], dict):
            sub_diff = compute_policy_diff(default[key], value)
            if sub_diff:
                diff[key] = sub_diff
        elif value != default[key]:
            diff[key] = value
    return diff


# Context variable for per-request policy (safe in asyncio)
_request_policy_var: ContextVar[dict | None] = ContextVar('_request_policy', default=None)


def set_request_policy(policy: dict | None):
    """Set the policy for the current request context."""
    _request_policy_var.set(policy)


def get_active_policy() -> dict:
    """Get the active policy for the current request (user-specific or default)."""
    user_policy = _request_policy_var.get()
    if user_policy:
        return user_policy
    return settings.load_policy()


# ============================================================
# Settings
# ============================================================

class Settings(BaseSettings):
    # API Configuration
    PROVIDER: str = "openrouter"
    API_KEY: str = ""
    OPENAI_API_KEY: str = ""

    # Token Limits (Safe defaults)
    MAX_INPUT_TOKENS: int = 8000
    MAX_OUTPUT_TOKENS: int = 2000

    # --- FREE MODELS ONLY ---
    MODEL_REASONING: str = "liquid/lfm-2.5-1.2b-thinking:free"
    MODEL_FAST: str = "arcee-ai/trinity-large-preview:free"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def base_url(self):
        if self.PROVIDER == "openrouter":
            return "https://openrouter.ai/api"
        elif self.PROVIDER == "groq":
            return "https://api.groq.com/openai"
        else:
            return "https://api.openai.com"

    @property
    def headers(self):
        return {
            "HTTP-Referer": "https://quiguard.ai",
            "X-Title": "QuiGuard-Security-Gateway"
        }

    def load_policy(self):
        """Load the default policy from policy.yaml."""
        try:
            with open("policy.yaml", "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print("Warning: policy.yaml not found. Using defaults.")
            return {"pii": {"enabled": True}, "custom_patterns": [], "agent_security": {}}

    def load_user_policy(self, user_id: str) -> dict:
        """Load user's policy overrides from Supabase and merge with default."""
        default_policy = self.load_policy()
        try:
            supabase_url = os.getenv("SUPABASE_URL", "")
            supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
            if not supabase_url or not supabase_key:
                return default_policy
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            response = client.table("user_policies").select("policy").eq("user_id", user_id).limit(1).execute()
            if response.data and response.data[0].get("policy"):
                user_overrides = response.data[0]["policy"]
                return deep_merge(default_policy, user_overrides)
        except Exception as e:
            print(f"[Policy] Error loading user policy for {user_id}: {e}")
        return default_policy

    def save_user_policy(self, user_id: str, full_policy: dict) -> dict:
        """Save user policy. Computes diff from default and stores only overrides."""
        default_policy = self.load_policy()
        overrides = compute_policy_diff(default_policy, full_policy)
        try:
            supabase_url = os.getenv("SUPABASE_URL", "")
            supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
            if not supabase_url or not supabase_key:
                raise Exception("Supabase not configured")
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            client.table("user_policies").upsert(
                {"user_id": user_id, "policy": overrides},
                on_conflict="user_id"
            ).execute()
            return {"status": "saved", "overrides_count": len(overrides)}
        except Exception as e:
            print(f"[Policy] Error saving: {e}")
            raise

    def reset_user_policy(self, user_id: str) -> dict:
        """Delete user's policy overrides, resetting to defaults."""
        try:
            supabase_url = os.getenv("SUPABASE_URL", "")
            supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
            if not supabase_url or not supabase_key:
                raise Exception("Supabase not configured")
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            client.table("user_policies").delete().eq("user_id", user_id).execute()
            return {"status": "reset"}
        except Exception as e:
            print(f"[Policy] Error resetting: {e}")
            raise


settings = Settings()