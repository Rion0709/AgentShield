# agentshield/firewall.py
try:
    from .rules import PatternRules, DecodingAnalyzer, DataSanitizer, OutputLeakageGuard, ContextWindowScanner
    from .config import ShieldConfig
    from .logger import security_logger
    from .exceptions import PromptInjectionError
    from .ml_classifier import MLInjectionDetector
    from .anomaly import AnomalyDetector
    from .auth import IdentityManager
    from .encrypted_memory import EncryptedMemory
except ImportError:
    from rules import PatternRules, DecodingAnalyzer, DataSanitizer, OutputLeakageGuard, ContextWindowScanner
    from config import ShieldConfig
    from logger import security_logger
    from exceptions import PromptInjectionError
    from ml_classifier import MLInjectionDetector
    from anomaly import AnomalyDetector
    from auth import IdentityManager
    from encrypted_memory import EncryptedMemory
import re

class ToolCallGuard:
    """Monitors and intercepts unsafe tool parameters or execution commands."""
    
    def __init__(self, rules_checker: PatternRules):
        self.rules_checker = rules_checker
        self.dangerous_tools = {
            "subprocess.run", "subprocess.Popen", "os.system", "os.popen",
            "shutil.rmtree", "builtins.eval", "builtins.exec",
            "requests.post", "urllib.request.urlopen"
        }

    def validate_tool_call(self, tool_name: str, tool_args: dict) -> dict:
        """Verifies if the tool execution name and argument contents are safe."""
        if tool_name in self.dangerous_tools:
            return {
                "safe": False,
                "reason": f"Dangerous execution tool execution blocked: {tool_name}"
            }
            
        for key, value in tool_args.items():
            if isinstance(value, str):
                if (self.rules_checker.check_text(value) or 
                    self.rules_checker.check_split_tokens(value) or 
                    self.rules_checker.check_prompt_leakage(value)):
                    return {
                        "safe": False,
                        "reason": f"Prompt injection pattern detected inside tool argument key '{key}'."
                    }
        return {"safe": True, "reason": "Tool call parameters verified."}


class AgentShieldFirewall:
    def __init__(self, config: ShieldConfig = None, require_auth: bool = True):
        self.config = config or ShieldConfig()
        self.rules_checker = PatternRules(self.config)
        self.decoding_analyzer = DecodingAnalyzer(self.config)
        self.data_sanitizer = DataSanitizer()
        self.leakage_guard = OutputLeakageGuard()
        self.context_scanner = ContextWindowScanner(self.rules_checker)
        self.tool_guard = ToolCallGuard(self.rules_checker)
        
        # New ML & Anomaly modules
        self.ml_detector = MLInjectionDetector()
        self.anomaly_detector = AnomalyDetector()
        
        # Auth katmanı
        self.require_auth = require_auth
        self.identity = None
        self.memory = None
        
        if require_auth:
            self.identity = IdentityManager()
            if self.identity.is_configured():
                try:
                    master_key = self.identity.verify_identity()
                    self.memory = EncryptedMemory(master_key)
                    security_logger.info("AgentShield: Authentication successful, memory unlocked.")
                except PermissionError as e:
                    security_logger.critical(f"Authentication failed: {e}")
                    raise
            else:
                security_logger.warning("No auth profile found. Run setup_auth.py first.")

    def is_input_safe(self, user_input: str, user_id: str = "anonymous") -> dict:
        """
        Analyzes user input. Returns a classification dictionary.
        Does not raise exceptions. Ideal for simple conditional checks.
        """
        try:
            self.validate_input(user_input, user_id)
            return {"safe": True, "reason": "Input passed all security checks."}
        except PromptInjectionError as e:
            return {"safe": False, "reason": str(e)}

    def validate_input(self, user_input: str, user_id: str = "anonymous"):
        """
        Validates user input. Raises PromptInjectionError if a threat is found.
        Enables professional try-catch middleware integration.
        """
        threat_score = 0.0
        
        # 1. Structure Verification (JSON/XML)
        struct_res = self.rules_checker.validate_structured_input(user_input)
        if struct_res["parsed"] and not struct_res["safe"]:
            security_logger.warning(f"Structured injection blocked: {struct_res['reason']}")
            raise PromptInjectionError(struct_res["reason"], payload=user_input)
            
        # 2. Direct rules check
        if self.rules_checker.check_text(user_input):
            security_logger.warning(f"Direct prompt injection blocked. Input: '{user_input[:100]}'")
            threat_score = 1.0
            self._log_anomaly(user_id, threat_score)
            raise PromptInjectionError("Direct prompt injection pattern detected.", payload=user_input)
            
        # 3. Split token check
        if self.rules_checker.check_split_tokens(user_input):
            security_logger.warning(f"Split token injection blocked. Input: '{user_input[:100]}'")
            threat_score = 1.0
            self._log_anomaly(user_id, threat_score)
            raise PromptInjectionError("Obfuscated split token prompt injection detected.", payload=user_input)
            
        # 4. Prompt leakage check
        if self.rules_checker.check_prompt_leakage(user_input):
            security_logger.warning(f"Prompt leakage attempt blocked. Input: '{user_input[:100]}'")
            threat_score = 0.8
            self._log_anomaly(user_id, threat_score)
            raise PromptInjectionError("Prompt extraction leakage attempt detected.", payload=user_input)
            
        # 5. Encoding payloads check
        decoded_payloads = self.decoding_analyzer.extract_hidden_payloads(user_input)
        for payload in decoded_payloads:
            if (self.rules_checker.check_text(payload) or 
                self.rules_checker.check_split_tokens(payload) or 
                self.rules_checker.check_prompt_leakage(payload)):
                security_logger.warning(f"Hidden prompt injection blocked. Decoded threat payload: '{payload[:100]}'")
                threat_score = 1.0
                self._log_anomaly(user_id, threat_score)
                raise PromptInjectionError("Hidden prompt injection payload detected within encoded text.", payload=payload)
                
        # 6. ML Prediction (if enabled and trained)
        if self.config.enable_ml_classifier and self.ml_detector.is_trained:
            ml_res = self.ml_detector.predict(user_input)
            if ml_res["is_harmful"]:
                security_logger.warning(f"ML Classifier blocked input. Confidence: {ml_res['confidence']:.2f}")
                threat_score = max(threat_score, ml_res["confidence"])
                self._log_anomaly(user_id, threat_score)
                raise PromptInjectionError(f"ML Classifier flagged prompt as harmful (confidence: {ml_res['confidence']:.2f}).", payload=user_input)
                
        # Log normal event threat score to anomaly tracking
        self._log_anomaly(user_id, threat_score)
        
    def _log_anomaly(self, user_id: str, threat_score: float):
        """Helper to register query event to anomaly tracker and raise error on detection."""
        if self.config.enable_anomaly_detection:
            anomaly_res = self.anomaly_detector.log_event(user_id, threat_score)
            if anomaly_res["anomaly_detected"]:
                security_logger.critical(f"Security anomaly flagged for user '{user_id}': {anomaly_res['reason']}")
                raise PromptInjectionError(f"Security anomaly blocked: {anomaly_res['reason']}", payload=None)

    def is_history_safe(self, conversation_history: list, limit: int = 10) -> dict:
        """Validates the conversation context window (RAG history scan)."""
        result = self.context_scanner.scan_history(conversation_history, limit)
        if not result["safe"]:
            security_logger.warning(f"Context poisoning detected: {result['reason']}")
        return result

    def is_tool_call_safe(self, tool_name: str, tool_args: dict) -> dict:
        """Validates tool execution before letting the agent make the system call."""
        result = self.tool_guard.validate_tool_call(tool_name, tool_args)
        if not result["safe"]:
            security_logger.warning(f"Tool execution attempt blocked: {result['reason']}")
        return result

    def is_external_data_safe(self, data: str) -> dict:
        """Scrapes and verifies data coming from external sources."""
        sanitizer_result = self.data_sanitizer.scan_external_data(data)
        if not sanitizer_result["safe"]:
            security_logger.warning(f"Indirect prompt injection template blocked in external data: {sanitizer_result['reason']}")
            return sanitizer_result
            
        decoded_payloads = self.decoding_analyzer.extract_hidden_payloads(data)
        for payload in decoded_payloads:
            if (self.rules_checker.check_text(payload) or 
                self.rules_checker.check_split_tokens(payload) or 
                self.rules_checker.check_prompt_leakage(payload)):
                security_logger.warning(f"Hidden indirect prompt injection blocked in external data: '{payload[:100]}'")
                return {
                    "safe": False,
                    "reason": "Hidden indirect prompt injection payload detected within encoded external data."
                }
                
        return {
            "safe": True,
            "reason": "External data is safe to process."
        }

    def sanitize_output(self, assistant_response: str) -> str:
        """Filters and redacts sensitive data and exfiltration vectors from the response."""
        cleaned_text = assistant_response
        
        # 1. Strip markdown image / HTML image exfiltration channels
        cleaned_text = self.leakage_guard.strip_exfiltration_vectors(cleaned_text)
        
        # 2. Mask passwords, keys, tokens using configured patterns
        if self.config.enable_output_redaction:
            for pattern, replacement in self.config.redaction_patterns:
                cleaned_text = re.sub(pattern, replacement, cleaned_text)
                
        return cleaned_text
