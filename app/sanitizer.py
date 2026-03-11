from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from .store import SessionStore
from .config import settings
import uuid

# --- Load Policy and Initialize Engines ---
policy = settings.load_policy()
registry = RecognizerRegistry()

# 1. Add Custom Patterns from YAML
if "custom_patterns" in policy:
    for p in policy["custom_patterns"]:
        pattern = Pattern(name=p['name'], regex=p['regex'], score=p['score'])
        recognizer = PatternRecognizer(
            supported_entity=p['name'], 
            patterns=[pattern],
            context=p.get('context', []) 
        )
        registry.add_recognizer(recognizer)

# 2. Enable Context Awareness (Smart Detection)
context_enhancer = LemmaContextAwareEnhancer(
    context_similarity_factor=0.45,
    min_score_with_context_similarity=0.4
)

# 3. Initialize Analyzer & Anonymizer
analyzer = AnalyzerEngine(
    registry=registry,
    context_aware_enhancer=context_enhancer,
    supported_languages=["en"]
)
anonymizer = AnonymizerEngine()

def generate_placeholder(entity_type: str) -> str:
    unique_id = uuid.uuid4().hex[:6]
    return f"<{entity_type}_{unique_id}>"

def sanitize_text(text: str) -> str:
    if not text:
        return text

    original_text = text
    detected_entities = []

    # 1. Handle Custom Secrets (IP Protection)
    # Note: Presidio handles these via the registry we loaded, so one analyze call covers both built-in and custom.
    
    # 2. Analyze Text
    # If policy disabled PII, we only check custom patterns (handled by registry logic)
    entities_to_check = None 
    if not policy.get('pii', {}).get('enabled', True):
        entities_to_check = [p['name'] for p in policy.get('custom_patterns', [])]

    results = analyzer.analyze(text=text, language='en', entities=entities_to_check)
    
    # 3. Anonymize
    if results:
        operators = {}
        for result in results:
            entity_type = result.entity_type
            placeholder = generate_placeholder(entity_type)
            sensitive_text = text[result.start:result.end]
            SessionStore.save(placeholder, sensitive_text)
            operators[entity_type] = OperatorConfig("replace", {"new_value": placeholder})
            detected_entities.append(entity_type)

        text = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).text

    # 4. Logging
    if detected_entities:
        print(f"[IronLayer] Scrubbed {len(detected_entities)} items: {list(set(detected_entities))}")

    return text

def desanitize_text(text: str) -> str:
    if not text:
        return text
            
    import re
    placeholders = re.findall(r'<[A-Z_]+_[a-z0-9]+>', text)
    
    for ph in placeholders:
        real_value = SessionStore.get(ph)
        if real_value:
            text = text.replace(ph, real_value)
            
    return text