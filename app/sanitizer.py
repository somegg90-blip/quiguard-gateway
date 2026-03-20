from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from .store import SessionStore
from .config import settings
import uuid
import hashlib

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
    # Get format config
    fmt_config = policy.get('placeholder_format', {})
    mode = fmt_config.get('mode', 'default')
    
    # Use a hash of the sensitive text for uniqueness
    # We take first 6 chars of MD5 hash for a short unique ID
    unique_id = hashlib.md5(sensitive_text.encode()).hexdigest()[:6]
    
    if mode == "numeric":
        # For numeric, we can't be deterministic easily without state, 
        # so we just use the hash ID as the number substitute or stick to default
        return f"({entity_type.lower()}_{unique_id[:4]})"
    elif mode == "redacted":
        return "[REDACTED]"
    else:
        return f"<{entity_type}_{unique_id}>"

def sanitize_text(text: str) -> str:
    if not text:
        return text

    # Reload policy to allow hot-reloading
    policy = settings.load_policy()
    
    original_text = text
    detected_entities = []

    # 1. Analyze
    results = analyzer.analyze(text=text, language='en')
    
    # 2. Handle Policy Modes
    action_mode = policy.get('action_mode', 'mask')

    if results:
        # A. BLOCK MODE
        if action_mode == "block":
            from app.audit_logger import log_audit_event
            log_audit_event("request_blocked", original_text, "", [r.entity_type for r in results])
            raise PolicyBlockedException(
                f"Security Policy Violation: Blocked {len(results)} sensitive items."
            )

        # B. WARN MODE
        if action_mode == "warn":
            print(f"[IronLayer WARNING] Detected {len(results)} items but allowing passage (Warn Mode).")
            from app.audit_logger import log_audit_event
            log_audit_event("request_warned", original_text, "", [r.entity_type for r in results])
            return text

        # C. MASK MODE (Default)
        operators = {}
        
        # We iterate results to create a specific replacement for EACH instance
        # Note: To handle overlaps correctly, we rely on the Anonymizer engine.
        # We simply map the Entity Type to a function that generates the placeholder.
        
        # Since we can't pass dynamic args easily to the operator, 
        # we will use the standard "replace" operator, but we construct the mapping manually first?
        # No, the anonymizer needs the operator config.
        
        # STRATEGY: Use the "replace" operator. 
        # Since "replace" takes a static string, we cannot use it for unique IDs per word easily 
        # unless we map specific text instances.
        
        # SAFEST STRATEGY: Sort reverse and replace manually (as we did before), 
        # but use the Deterministic Placeholder function.
        
        # Sort results by start index in reverse order to handle indices correctly
        results = sorted(results, key=lambda x: x.start, reverse=True)
        
        for result in results:
            entity_type = result.entity_type
            sensitive_text = text[result.start:result.end]
            
            # Generate Unique Placeholder
            placeholder = generate_deterministic_placeholder(entity_type, sensitive_text)
            
            # Save Mapping
            SessionStore.save(placeholder, sensitive_text)
            detected_entities.append(entity_type)

            # Perform replacement manually
            text = text[:result.start] + placeholder + text[result.end:]

    # 3. Audit Logging for Mask Mode
    if detected_entities:
        print(f"[IronLayer] Scrubbed {len(detected_entities)} items: {list(set(detected_entities))}")
        from app.audit_logger import log_audit_event
        log_audit_event("prompt_sanitized", original_text, text, detected_entities)

    return text

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