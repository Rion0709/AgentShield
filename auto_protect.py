# agentshield/auto_protect.py
import os
import sys
import logging

try:
    from .firewall import AgentShieldFirewall
    from .auth import IdentityManager
    from .logger import security_logger
except ImportError:
    from firewall import AgentShieldFirewall
    from auth import IdentityManager
    from logger import security_logger

class AutoProtect:
    """Manages explicit runtime interception and automated protection of popular AI libraries."""
    
    def __init__(self, require_auth: bool = True, auth_file: str = "agent_shield_auth.json"):
        self.require_auth = require_auth
        self.auth_file = auth_file
        self.firewall = None
        self.flag_file = "agent_shield_verified.flag"

    def init(self):
        """Initializes firewall protections and applies monkey patches to supported libraries."""
        # 1. First-time Authentication Verification
        if self.require_auth:
            manager = IdentityManager(auth_file=self.auth_file)
            if manager.is_configured():
                if not os.path.exists(self.flag_file):
                    print("\n🔐 [AgentShield] First-time runtime initialization detected.")
                    print("Please authenticate using your security answer to authorize this session.")
                    try:
                        # This prompts user for answer and derives master key
                        manager.verify_identity()
                        # Create verified flag file
                        with open(self.flag_file, "w") as f:
                            f.write("verified")
                        print("✅ [AgentShield] Identity verified. Auto-protection active.")
                    except Exception as e:
                        security_logger.critical(f"Session authorization failed: {e}")
                        raise PermissionError(f"AgentShield initialization aborted: {e}")
            else:
                security_logger.warning("No authentication profile configured. Call setup_auth.py first.")

        # 2. Instantiate Firewall
        # Pass require_auth=False to the firewall init because we just handled validation above
        self.firewall = AgentShieldFirewall(require_auth=False)
        
        # 3. Apply Monkey Patches
        self._patch_openai()
        self._patch_requests()
        security_logger.info("AgentShield: AutoProtect initialization completed.")

    def _patch_openai(self):
        """Patches OpenAI ChatCompletion endpoint to automatically filter prompts and responses."""
        try:
            import openai
            # Check v1.x+ API
            if hasattr(openai, "resources") and hasattr(openai.resources, "chat"):
                from openai.resources.chat import completions
                original_create = completions.Completions.create
                
                def secure_create(resource_self, *args, **kwargs):
                    messages = kwargs.get("messages", [])
                    prompt_text = "\n".join([m.get("content", "") for m in messages if isinstance(m, dict) and "content" in m])
                    
                    if prompt_text:
                        self.firewall.validate_input(prompt_text)
                        
                    response = original_create(resource_self, *args, **kwargs)
                    
                    # Sanitize output content
                    try:
                        if hasattr(response, "choices") and response.choices:
                            choice = response.choices[0]
                            if hasattr(choice, "message") and choice.message and choice.message.content:
                                choice.message.content = self.firewall.sanitize_output(choice.message.content)
                    except Exception:
                        pass
                    return response
                
                completions.Completions.create = secure_create
                security_logger.info("AgentShield: OpenAI ChatCompletion patches applied successfully.")
        except ImportError:
            pass
        except Exception as e:
            security_logger.error(f"Failed to patch openai: {e}")

    def _patch_requests(self):
        """Intercepts outgoing requests to AI service endpoints to scan structured JSON payloads."""
        try:
            import requests
            original_request = requests.api.request
            
            def secure_request(method, url, **kwargs):
                # Detect AI API service endpoints
                is_ai_endpoint = any(domain in url for domain in ["api.openai.com", "api.anthropic.com", "huggingface.co"])
                
                if is_ai_endpoint:
                    json_payload = kwargs.get("json")
                    if json_payload:
                        res = self.firewall.is_input_safe(str(json_payload))
                        if not res["safe"]:
                            raise ValueError(f"AgentShield Blocked Outgoing Threat: {res['reason']}")
                            
                return original_request(method, url, **kwargs)
                
            requests.api.request = secure_request
            requests.request = secure_request
            security_logger.info("AgentShield: Network requests patches applied successfully.")
        except ImportError:
            pass
        except Exception as e:
            security_logger.error(f"Failed to patch requests: {e}")

# Global initialization function
def init(require_auth: bool = True):
    protector = AutoProtect(require_auth=require_auth)
    protector.init()
