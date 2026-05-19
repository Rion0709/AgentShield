# agentshield/config.py
import re

class ShieldConfig:
    def __init__(self):
        # General security toggles
        self.enable_rules_check = True
        self.enable_homoglyph_normalization = True
        self.enable_decoding_analysis = True
        self.enable_output_redaction = True
        
        # New advanced security flags (Backward compatible, default settings)
        self.enable_split_token_check = True
        self.enable_prompt_leakage_check = True
        self.enable_structured_input_check = True
        self.enable_ml_classifier = False  # Disabled by default (requires scikit-learn training)
        self.enable_anomaly_detection = True
        self.ml_threshold = 0.55  # Confidence threshold for ML classifier (0.0 to 1.0)
        
        # Base64 substring length threshold (to avoid false positives on short random strings)
        self.min_base64_length = 8
        
        # Hex substring length threshold
        self.min_hex_length = 8
        
        # Redaction patterns for output guardrails (API keys, secrets, auth headers, private keys)
        self.redaction_patterns = [
            (r"(?i)(api[-_]?key|secret|password|auth[-_]?token)[\s:=]+([a-zA-Z0-9_\-\.]{16,})", r"\1: [REDACTED_API_KEY]"),
            (r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.\~]{16,})", r"\1[REDACTED_TOKEN]"),
            (r"-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s\n]+-----END PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
        ]
        
        # Custom malicious patterns that the user can append dynamically
        self.custom_malicious_patterns = []

    def add_malicious_pattern(self, pattern: str):
        """Allows dynamic configuration of new threat patterns."""
        self.custom_malicious_patterns.append(re.compile(pattern, re.IGNORECASE))
