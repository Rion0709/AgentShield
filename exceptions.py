# agentshield/exceptions.py

class AgentShieldError(Exception):
    """Base exception class for AgentShield."""
    pass

class PromptInjectionError(AgentShieldError):
    """Raised when a direct or indirect prompt injection attempt is detected."""
    def __init__(self, message: str = "Prompt injection attempt blocked.", payload: str = None):
        super().__init__(message)
        self.payload = payload

class SensitiveDataLeakageError(AgentShieldError):
    """Raised when sensitive data is detected in the model's output and cannot be safely redacted."""
    pass

class RateLimitError(AgentShieldError):
    """Raised when rate limit constraints are violated."""
    pass
