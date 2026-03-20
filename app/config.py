import os
import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # API Configuration
    PROVIDER: str = "openrouter"
    API_KEY: str = ""
    OPENAI_API_KEY: str = "" 
    
    # Token Limits (Safe defaults)
    MAX_INPUT_TOKENS: int = 8000
    MAX_OUTPUT_TOKENS: int = 2000
    
    # --- FREE MODELS ONLY ---
    # Reasoning: Liquid LFM (Specializes in thinking)
    MODEL_REASONING: str = "liquid/lfm-2.5-1.2b-thinking:free"
    
    # Fast: Arcee Trinity (Fast responses)
    MODEL_FAST: str = "arcee-ai/trinity-large-preview:free"

    # Configure Pydantic
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
            "HTTP-Referer": "https://ironlayer.ai", 
            "X-Title": "IronLayer-Security-Gateway"
        }

    def load_policy(self):
        try:
            with open("policy.yaml", "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print("Warning: policy.yaml not found. Using defaults.")
            return {"pii": {"enabled": True}, "custom_patterns": [], "agent_security": {}}

settings = Settings()