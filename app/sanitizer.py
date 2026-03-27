from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from .store import SessionStore
from .config import settings
import hashlib
import json

# Load Policy
policy = settings.load_policy()

# --- Custom Exception for Blocking ---
class PolicyBlockedException(Exception):
    """Raised when content violates the security policy in 'block' mode."""
    pass

# --- Engine Setup ---
analyzer = AnalyzerEngine(supported_languages=["en"])
anonymizer = AnonymizerEngine()

# Add Custom Patterns
if "custom_patterns" in policy:
    for p in policy['custom_patterns']:
        pattern = Pattern(name=p['name'], regex=p['regex'], score=p['score'])
        recognizer = PatternRecognizer(
            supported_entity=p['name'], 
            patterns=[pattern],
            context=p.get('context', [])
        )
        analyzer.registry.add_recognizer(recognizer)

# --- Helper Functions ---

def generate_deterministic_placeholder(entity_type: str, sensitive_text: str) -> str:
    """
    Generates a unique placeholder based on the content of the sensitive text.
    Ensures "John" -> <PERSON_abc12> and "Jane" -> <PERSON_xyz99>.
    """
    fmt_config = policy.get('placeholder_format', {})
    mode = fmt_config.get('mode', 'default')
    
    # Use a hash of the sensitive text for uniqueness
    unique_id = hashlib.md5(sensitive_text.encode()).hexdigest()[:6]
    
    if mode == "numeric":
        return f"({entity_type.lower()}_{unique_id[:4]})"
    elif mode == "redacted":
        return "[REDACTED]"
    else:
        return f"<{entity_type}_{unique_id}>"

def sanitize_text(text: str) -> str:
    if not text:
        return text

    policy = settings.load_policy() # Hot reload
    
    original_text = text
    detected_entities = []
    action_mode = policy.get('action_mode', 'mask')

    results = analyzer.analyze(text=text, language='en')
    
    if results:
        if action_mode == "block":
            from app.audit_logger import log_audit_event
            log_audit_event("request_blocked", original_text, "", [r.entity_type for r in results])
            raise PolicyBlockedException(
                f"Security Policy Violation: Blocked {len(results)} sensitive items."
            )

        if action_mode == "warn":
            print(f"[QuiGuard WARNING] Detected {len(results)} items but allowing passage.")
            from app.audit_logger import log_audit_event
            log_audit_event("request_warned", original_text, "", [r.entity_type for r in results])
            return text

        # MASK MODE
        # Sort results by start index in reverse order to handle indices correctly
        results = sorted(results, key=lambda x: x.start, reverse=True)
        
        for result in results:
            entity_type = result.entity_type
            sensitive_text = text[result.start:result.end]
            
            placeholder = generate_deterministic_placeholder(entity_type, sensitive_text)
            
            SessionStore.save(placeholder, sensitive_text)
            detected_entities.append(entity_type)

            # Perform replacement manually
            text = text[:result.start] + placeholder + text[result.end:]

    if detected_entities:
        print(f"[QuiGuard] Scrubbed {len(detected_entities)} items: {list(set(detected_entities))}")
        from app.audit_logger import log_audit_event
        log_audit_event("prompt_sanitized", original_text, text, detected_entities)

    return text

# --- NEW: Recursive JSON Handling ---

def sanitize_tool_arguments(args_str: str) -> str:
    """
    Safely sanitizes JSON arguments by parsing them first.
    Handles nested structures and stringified JSON.
    """
    try:
        # 1. Parse the JSON string into a Python dict
        args_dict = json.loads(args_str)
        
        # 2. Recursively scrub values in the dict
        scrubbed_dict = _recursive_scrub(args_dict)
        
        # 3. Convert back to string
        return json.dumps(scrubbed_dict)
        
    except json.JSONDecodeError:
        # Fallback: If it's not valid JSON, treat as raw text
        return sanitize_text(args_str)

def _recursive_scrub(data):
    """
    Recursively walks through JSON data and scrubs strings.
    """
    if isinstance(data, dict):
        return {k: _recursive_scrub(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_recursive_scrub(item) for item in data]
    elif isinstance(data, str):
        # It's a string. Is it stringified JSON? Try to parse.
        try:
            nested_data = json.loads(data)
            # It was JSON! Scrub it recursively.
            scrubbed_nested = _recursive_scrub(nested_data)
            return json.dumps(scrubbed_nested)
        except json.JSONDecodeError:
            # Not JSON, just a normal string. Scrub PII.
            return sanitize_text(data)
    else:
        # Int, Bool, Float, None - return as is
        return data

# --- NEW: Phase 2 - Inbound Tool Response Scrubbing ---

def sanitize_tool_response(content: str) -> str:
    """
    Sanitizes the content of a tool response (e.g., a Jira ticket or SQL result)
    before it enters the agent's context window.
    """
    if not content:
        return content
    
    print("[QuiGuard] Sanitizing Inbound Tool Response...")
    
    # Tool responses are often stringified JSON or plain text.
    # We use the same recursive logic as arguments.
    try:
        data = json.loads(content)
        scrubbed_data = _recursive_scrub(data)
        return json.dumps(scrubbed_data)
    except json.JSONDecodeError:
        # Not JSON, just treat as text
        return sanitize_text(content)

def desanitize_text(text: str) -> str:
    if not text:
        return text
            
    import re
    candidates = re.findall(r'<[A-Z_]+_[a-z0-9]+>|\([a-z]+_[a-z0-9]+\)', text)
    
    for candidate in candidates:
        real_value = SessionStore.get(candidate)
        if real_value:
            text = text.replace(candidate, real_value)
            
    return text