# agentshield/wrappers.py
import time
from functools import wraps
from collections import defaultdict
try:
    from .firewall import AgentShieldFirewall
    from .exceptions import PromptInjectionError, RateLimitError
except ImportError:
    from firewall import AgentShieldFirewall
    from exceptions import PromptInjectionError, RateLimitError

def secure_agent(firewall: AgentShieldFirewall = None):
    """
    Decorator to protect any agent or LLM interaction function.
    Automatically validates the input prompt and sanitizes the output response.
    
    Usage:
        @secure_agent()
        def call_llm(prompt):
            # Your normal LLM call code here
            return response_text
    """
    shield = firewall or AgentShieldFirewall()
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Locate input prompt string within arguments
            prompt = None
            
            # Check popular prompt keyword parameters
            for key in ['prompt', 'user_input', 'text', 'message', 'query']:
                if key in kwargs:
                    prompt = kwargs[key]
                    break
            
            # Fallback to the first positional argument if no keyword argument matches
            if prompt is None and len(args) > 0:
                prompt = args[0]
                
            # Validate if input is a string
            if isinstance(prompt, str):
                shield.validate_input(prompt)
                
            # Call the target function
            response = func(*args, **kwargs)
            
            # Sanitize output response if it's a string
            if isinstance(response, str):
                return shield.sanitize_output(response)
                
            return response
        return wrapper
    return decorator


def rate_limit(max_attempts: int = 5, window_seconds: int = 60):
    """
    Decorator to apply client-level rate limiting based on 'user_id'.
    Raises RateLimitError if client requests exceed max_attempts inside window_seconds.
    
    Usage:
        @rate_limit(max_attempts=3, window_seconds=10)
        def handle_user_query(prompt, user_id="user_1"):
            return "response"
    """
    # Track timestamps of attempts per user_id
    attempts = defaultdict(list)
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Retrieve user identity or default to anonymous
            user_id = kwargs.get("user_id")
            if user_id is None:
                # Attempt to extract user_id from positional args
                # We look at the function's signature or assume if a second arg is passed
                if len(args) > 1:
                    user_id = args[1]
                else:
                    user_id = "anonymous"
                    
            now = time.time()
            
            # Flush out timestamps older than the window
            attempts[user_id] = [t for t in attempts[user_id] if now - t < window_seconds]
            
            # Check violation
            if len(attempts[user_id]) >= max_attempts:
                raise RateLimitError(
                    f"Rate limit exceeded for client '{user_id}'. Max {max_attempts} attempts allowed every {window_seconds}s."
                )
                
            # Log successful attempt timestamp
            attempts[user_id].append(now)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator
