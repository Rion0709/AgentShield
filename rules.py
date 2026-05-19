# agentshield/rules.py
import re
import base64
import urllib.parse
import json
import unicodedata
try:
    from .config import ShieldConfig
except ImportError:
    from config import ShieldConfig

# Homoglyph mapping dictionary: Maps similar-looking non-Latin characters to standard Latin characters.
HOMOGLYPH_MAP = {
    # Greek Homoglyphs (mapped visually to Latin equivalents)
    'α': 'a', 'β': 'b', 'γ': 'g', 'ε': 'e', 'η': 'h', 'ι': 'i', 'κ': 'k', 'μ': 'm', 
    'ν': 'v', # Nu looks visually like 'v'
    'ο': 'o', 'ρ': 'p', 'τ': 't', 
    'υ': 'u', # Lowercase upsilon looks like 'u'
    'χ': 'x', 'ω': 'w',
    'ς': 's', # Lowercase final sigma looks like 's'
    'σ': 's', # Standard lowercase sigma
    'Α': 'A', 'В': 'B', 'Γ': 'G', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 
    'Р': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'Ω': 'W',
    # Cyrillic Homoglyphs
    'а': 'a', 'в': 'b', 'с': 'c', 'е': 'e', 'н': 'h', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'о': 'o', 
    'р': 'p', 'ѕ': 's', 'т': 't', 'х': 'x', 'у': 'y', 'з': 'z',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Η': 'H', 'І': 'I', 'Ј': 'J', 'Κ': 'K', 'Μ': 'M', 'Ο': 'O', 
    'Р': 'P', 'Ѕ': 'S', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'Ζ': 'Z'
}

class PatternRules:
    def __init__(self, config: ShieldConfig = None):
        self.config = config or ShieldConfig()
        
        # Standard system override patterns
        self.malicious_patterns = [
            r"(?i)ignore (all )?previous instructions",
            r"(?i)system prompt",
            r"(?i)you are now a",
            r"(?i)forget your rules",
            r"(?i)bypass constraints",
            r"(?i)output the system settings",
            r"(?i)reveal the instructions above",
            r"(?i)dan mode",
            r"(?i)jailbreak",
        ]
        
        # Threat patterns specifically targeting prompt extraction/leakage
        self.leakage_patterns = [
            r"(?i)(reveal|show|print|output|display)\s+(the\s+)?(previous|system|initial|original)?\s*(prompt|instruction)",
            r"(?i)what was (my\s+)?first question",
            r"(?i)reveal\s+(the\s+)?instructions\s+above"
        ]

    def normalize_homoglyphs(self, text: str) -> str:
        """Normalizes text by removing invisible control characters, applying NFKC normalization, and mapping homoglyphs."""
        if not self.config.enable_homoglyph_normalization:
            return text
            
        # 1. Unicode Normalization (NFD/NFKC) to resolve combining characters/diacritics
        text = unicodedata.normalize('NFKC', text)
            
        # 2. Strip zero-width spaces and other invisible/formatting characters
        text = re.sub(r'[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]', '', text)
        
        # 3. Direct alphabet homoglyph mapping
        normalized = []
        for char in text:
            normalized.append(HOMOGLYPH_MAP.get(char, char))
        return "".join(normalized)

    def check_text(self, text: str) -> bool:
        """Checks text for malicious instructions and direct injection indicators."""
        if not self.config.enable_rules_check:
            return False
            
        normalized_text = self.normalize_homoglyphs(text)
        
        # Check standard static patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, normalized_text):
                return True
                
        # Check dynamically configured user patterns
        for custom_pattern in self.config.custom_malicious_patterns:
            if custom_pattern.search(normalized_text):
                return True
                
        # Check for XML/HTML tag breakouts (e.g., trying to close container tags like </user_input>)
        if re.search(r"<\s*/\s*(user_input|user|system|assistant|context)\s*>", normalized_text):
            return True
            
        return False

    def check_split_tokens(self, text: str) -> bool:
        """Strips out whitespaces and delimiters to detect token-splitting obfuscations."""
        if not self.config.enable_split_token_check:
            return False
            
        # Compress text by removing all whitespaces and punctuation delimiters
        squeezed = re.sub(r'[\s\-\_\.\,\/]+', '', text)
        normalized = self.normalize_homoglyphs(squeezed)
        
        # Check patterns against squeezed text by compressing pattern spaces
        for pattern in self.malicious_patterns:
            clean_pattern = pattern.replace(' ', '').replace('\\s', '')
            if re.search(clean_pattern, normalized):
                return True
        return False

    def check_prompt_leakage(self, text: str) -> bool:
        """Scans input to catch instructions attempting to leak the system prompt."""
        if not self.config.enable_prompt_leakage_check:
            return False
            
        normalized_text = self.normalize_homoglyphs(text)
        for pattern in self.leakage_patterns:
            if re.search(pattern, normalized_text):
                return True
        return False

    def validate_structured_input(self, data: str) -> dict:
        """
        Detects and parses structured formats (JSON, XML) recursively validating elements.
        Returns: {'parsed': bool, 'safe': bool, 'reason': str}
        """
        if not self.config.enable_structured_input_check:
            return {"parsed": False, "safe": True, "reason": "Structured validation disabled."}
            
        # Try JSON
        try:
            parsed_json = json.loads(data)
            safe, reason = self._scan_recursive(parsed_json)
            return {"parsed": True, "safe": safe, "reason": reason if not safe else "JSON structure validated safe."}
        except json.JSONDecodeError:
            pass
            
        # Try XML
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(data)
            # Extract elements text and attributes recursively
            for elem in root.iter():
                text_content = elem.text
                if text_content:
                    if self.check_text(text_content) or self.check_split_tokens(text_content) or self.check_prompt_leakage(text_content):
                        return {"parsed": True, "safe": False, "reason": f"Injection detected in XML text: '{text_content[:80]}'."}
                for attr_name, attr_val in elem.attrib.items():
                    if self.check_text(attr_val) or self.check_split_tokens(attr_val) or self.check_prompt_leakage(attr_val):
                        return {"parsed": True, "safe": False, "reason": f"Injection detected in XML attribute '{attr_name}': '{attr_val[:80]}'."}
            return {"parsed": True, "safe": True, "reason": "XML structure validated safe."}
        except Exception:
            pass
            
        return {"parsed": False, "safe": True, "reason": "Raw unstructured data."}

    def _scan_recursive(self, node) -> tuple:
        """Helper to recursively scan nested dict/list/string structures."""
        if isinstance(node, str):
            if self.check_text(node) or self.check_split_tokens(node) or self.check_prompt_leakage(node):
                return False, f"Malicious string value detected: '{node[:80]}'"
        elif isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and (self.check_text(k) or self.check_split_tokens(k) or self.check_prompt_leakage(k)):
                    return False, f"Malicious key detected: '{k[:80]}'"
                safe, reason = self._scan_recursive(v)
                if not safe:
                    return False, reason
        elif isinstance(node, list):
            for item in node:
                safe, reason = self._scan_recursive(item)
                if not safe:
                    return False, reason
        return True, "Safe."


class DecodingAnalyzer:
    """Detects and decodes hidden payload encoders (Base64, Hex, URL)."""
    
    def __init__(self, config: ShieldConfig = None):
        self.config = config or ShieldConfig()

    def decode_base64(self, text: str) -> str:
        if not self.config.enable_decoding_analysis:
            return ""
            
        pattern = rf'[a-zA-Z0-9+/=]{{{self.config.min_base64_length},}}'
        words = re.findall(pattern, text)
        decoded_strings = []
        for word in words:
            padding_needed = len(word) % 4
            padded_word = word + ("=" * (4 - padding_needed) if padding_needed else "")
            try:
                decoded_bytes = base64.b64decode(padded_word.encode('utf-8'), validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                if any(c.isalnum() or c.isspace() for c in decoded_str):
                    decoded_strings.append(decoded_str)
            except Exception:
                pass
        return " ".join(decoded_strings)

    def decode_hex(self, text: str) -> str:
        if not self.config.enable_decoding_analysis:
            return ""
            
        hex_escapes = re.findall(r'(?:\\x|0x)([a-fA-F0-9]{2})', text)
        if hex_escapes:
            try:
                decoded_bytes = bytes.fromhex("".join(hex_escapes))
                return decoded_bytes.decode('utf-8', errors='ignore')
            except Exception:
                pass
        
        pattern = rf'\b[a-fA-F0-9]{{{self.config.min_hex_length},}}\b'
        hex_words = re.findall(pattern, text)
        decoded_strings = []
        for word in hex_words:
            try:
                decoded_bytes = bytes.fromhex(word)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                if any(c.isalnum() or c.isspace() for c in decoded_str):
                    decoded_strings.append(decoded_str)
            except Exception:
                pass
        return " ".join(decoded_strings)

    def decode_url(self, text: str) -> str:
        if not self.config.enable_decoding_analysis:
            return ""
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                return decoded
        except Exception:
            pass
        return ""

    def extract_hidden_payloads(self, text: str) -> list:
        """Unravels multiple obfuscation encodings from the input text."""
        payloads = []
        
        url_dec = self.decode_url(text)
        if url_dec: payloads.append(url_dec)
        
        b64_dec = self.decode_base64(text)
        if b64_dec: payloads.append(b64_dec)
        
        hex_dec = self.decode_hex(text)
        if hex_dec: payloads.append(hex_dec)
        
        return payloads


class DataSanitizer:
    """Security scanner for external untrusted data feeds."""
    
    def __init__(self):
        self.indirect_indicators = [
            r"(?i)attention(!|:)?\s*ignore",
            r"(?i)important(!|:)?\s*override",
            r"(?i)system (update|override|directive)",
            r"(?i)new directive",
            r"(?i)note:\s*the assistant must",
            r"(?i)instruction:\s*change your task",
        ]

    def scan_external_data(self, data: str) -> dict:
        """Validates incoming external text blocks for injection vectors."""
        detected_threats = []
        for pattern in self.indirect_indicators:
            if re.search(pattern, data):
                detected_threats.append(pattern)
        
        if detected_threats:
            return {
                "safe": False,
                "reason": f"Potential indirect prompt injection templates detected: {detected_threats}"
            }
        return {"safe": True, "reason": "Data clean."}


class OutputLeakageGuard:
    """Detects and prevents data exfiltration vectors in agent responses."""
    
    def __init__(self):
        self.markdown_image_pattern = r"!\[.*?\]\((https?://.*?)\)"
        self.html_image_pattern = r"<img[^>]+src=[\"'](https?://[^\"']+)[\"']"

    def strip_exfiltration_vectors(self, text: str) -> str:
        """Removes markdown and HTML images that could silently exfiltrate chat logs via GET requests."""
        cleaned = re.sub(self.markdown_image_pattern, "[BLOCKED_IMAGE_VECTOR]", text)
        cleaned = re.sub(self.html_image_pattern, "[BLOCKED_IMAGE_VECTOR]", cleaned)
        return cleaned


class ContextWindowScanner:
    """Scans conversation history to catch injection attacks hidden within history windows."""
    
    def __init__(self, rules_checker: PatternRules):
        self.rules_checker = rules_checker

    def scan_history(self, conversation_history: list, limit: int = 10) -> dict:
        """Scans the last N messages of conversation history for any malicious injection patterns."""
        recent_messages = conversation_history[-limit:]
        for idx, message in enumerate(recent_messages):
            content = message.get("content", "")
            role = message.get("role", "user")
            
            if role == "user":
                if (self.rules_checker.check_text(content) or 
                    self.rules_checker.check_split_tokens(content) or
                    self.rules_checker.check_prompt_leakage(content)):
                    return {
                        "safe": False,
                        "reason": f"Malicious pattern detected in conversation message index {len(conversation_history) - len(recent_messages) + idx + 1} ({role})."
                    }
        return {"safe": True, "reason": "Conversation history context is clean."}
