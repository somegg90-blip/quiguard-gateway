from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from .store import SessionStore
from .config import settings, get_active_policy
import hashlib
import json

# Load Default Policy (for startup custom pattern registration)
_default_policy = settings.load_policy()

# --- Custom Exception for Blocking ---
class PolicyBlockedException(Exception):
    """Raised when content violates the security policy in 'block' mode."""
    pass

# --- Engine Setup ---
analyzer = AnalyzerEngine(supported_languages=["en"])
anonymizer = AnonymizerEngine()

# Track registered custom patterns to avoid duplicates
_registered_custom_patterns = set()


def _register_custom_patterns(policy: dict):
    """Register custom patterns from policy. Updates existing patterns if changed."""
    for p in policy.get("custom_patterns", []):
        name = p.get("name")
        if not name:
            continue
        try:
            if name in _registered_custom_patterns:
                # Remove old recognizer so we can re-register with updated regex
                try:
                    analyzer.registry.remove_recognizer(name)
                except Exception:
                    pass
            pattern = Pattern(name=name, regex=p["regex"], score=p["score"])
            recognizer = PatternRecognizer(
                supported_entity=name,
                patterns=[pattern],
                context=p.get("context", [])
            )
            analyzer.registry.add_recognizer(recognizer)
            _registered_custom_patterns.add(name)
        except Exception as e:
            print(f"[Sanitizer] Error registering pattern {name}: {e}")


# Register default custom patterns at startup
_register_custom_patterns(_default_policy)


# --- Helper Functions ---

def generate_deterministic_placeholder(entity_type: str, sensitive_text: str) -> str:
    """
    Generates a unique placeholder based on the content of the sensitive text.
    Ensures "John" -> <PERSON_abc12> and "Jane" -> <PERSON_xyz99>.
    """
    policy = get_active_policy()
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

    policy = get_active_policy()

    # Sync any new or updated custom patterns from the active policy
    _register_custom_patterns(policy)

    original_text = text
    detected_entities = []

    # Determine action mode (check multiple locations for compatibility)
    action_mode = (
        policy.get('action_mode') or
        policy.get('settings', {}).get('default_action', 'mask')
    )

    # Get confidence threshold from policy
    settings_cfg = policy.get('settings', {})
    confidence_threshold = settings_cfg.get('confidence_threshold', 0.0)

    results = analyzer.analyze(text=text, language='en')

    # --- Filter 1: Confidence threshold ---
    if confidence_threshold > 0:
        results = [r for r in results if r.score >= confidence_threshold]

    # --- Filter 2: Entity filtering ---
    # Build set of currently active custom entity names
    active_custom = set(
        p.get("name") for p in policy.get("custom_patterns", [])
        if p.get("name")
    )
    enabled_entities = policy.get('pii', {}).get('enabled_entities')

    filtered = []
    for r in results:
        if r.entity_type in _registered_custom_patterns:
            # Custom entity: only include if it's in the active policy
            if r.entity_type in active_custom:
                filtered.append(r)
        else:
            # Standard entity: filter by enabled_entities (if specified)
            if enabled_entities is None or r.entity_type in enabled_entities:
                filtered.append(r)
    results = filtered

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

        # --- REMOVE OVERLAPPING ENTITIES ---
        results = sorted(results, key=lambda x: x.start)
        non_overlapping = []
        last_end = 0
        for r in results:
            if r.start >= last_end:
                non_overlapping.append(r)
                last_end = r.end
        results = sorted(non_overlapping, key=lambda x: x.start, reverse=True)

        # MASK MODE
        for result in results:
            entity_type = result.entity_type
            sensitive_text = text[result.start:result.end]

            placeholder = generate_deterministic_placeholder(entity_type, sensitive_text)

            SessionStore.save(placeholder, sensitive_text)
            detected_entities.append(entity_type)

            text = text[:result.start] + placeholder + text[result.end:]

    if detected_entities:
        print(f"[QuiGuard] Scrubbed {len(detected_entities)} items: {list(set(detected_entities))}")
        from app.audit_logger import log_audit_event
        log_audit_event("prompt_sanitized", original_text, text, detected_entities)

    return text

# --- Recursive JSON Handling ---

def sanitize_tool_arguments(args_str: str) -> str:
    """
    Safely sanitizes JSON arguments by parsing them first.
    Handles nested structures and stringified JSON.
    """
    try:
        args_dict = json.loads(args_str)
        scrubbed_dict = _recursive_scrub(args_dict)
        return json.dumps(scrubbed_dict)
    except json.JSONDecodeError:
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
        try:
            nested_data = json.loads(data)
            scrubbed_nested = _recursive_scrub(nested_data)
            return json.dumps(scrubbed_nested)
        except json.JSONDecodeError:
            return sanitize_text(data)
    else:
        return data

# --- Phase 2: Inbound Tool Response Scrubbing ---

def sanitize_tool_response(content: str) -> str:
    """
    Sanitizes the content of a tool response (e.g., a Jira ticket or SQL result)
    before it enters the agent's context window.
    """
    if not content:
        return content

    print("[QuiGuard] Sanitizing Inbound Tool Response...")

    try:
        data = json.loads(content)
        scrubbed_data = _recursive_scrub(data)
        return json.dumps(scrubbed_data)
    except json.JSONDecodeError:
        return sanitize_text(content)

def desanitize_text(text: str) -> str:
    """
    Restores original values for the end-user based on placeholders.
    """
    if not text:
        return text

    import re
    candidates = re.findall(r'<[A-Z_]+_[a-z0-9]+>|\([a-z]+_[a-z0-9]+\)', text)

    for candidate in candidates:
        real_value = SessionStore.get(candidate)
        if real_value:
            text = text.replace(candidate, real_value)

    return text