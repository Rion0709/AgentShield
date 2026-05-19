# agentshield/auth.py
import json
import os
import hashlib
import secrets
from datetime import datetime

try:
    from .logger import security_logger
except ImportError:
    from logger import security_logger

class IdentityManager:
    """Manages secure identity setup, validation, lockouts, and cryptographic key generation."""
    
    def __init__(self, auth_file: str = "agent_shield_auth.json"):
        self.auth_file = auth_file
        self.max_attempts = 3

    def _hash_value(self, value: str, salt: str) -> str:
        """Generates a secure SHA-256 hash using a salt value."""
        hasher = hashlib.sha256()
        hasher.update(salt.encode('utf-8'))
        hasher.update(value.encode('utf-8'))
        return hasher.hexdigest()

    def _generate_recovery_code(self) -> str:
        """Generates a random 16-character recovery code in BBBB-BBBB-BBBB-BBBB format."""
        blocks = [secrets.token_hex(2).upper() for _ in range(4)]
        return "-".join(blocks)

    def is_configured(self) -> bool:
        """Checks if the identity manager is already configured."""
        return os.path.exists(self.auth_file)

    def setup_identity(self, question: str = None, answer: str = None) -> dict:
        """
        Sets up the authentication profile. Prompts user if values are not provided.
        Returns: {'recovery_code': str, 'success': bool}
        """
        if not question:
            question = input("Enter a custom security question (e.g., Mother's maiden name?): ").strip()
        if not answer:
            answer = input("Enter the answer to your security question: ").strip()

        if not question or not answer:
            raise ValueError("Question and answer cannot be empty.")

        salt = secrets.token_hex(16)
        recovery_code = self._generate_recovery_code()
        
        # Salted hashing for recovery code & answer
        answer_hash = self._hash_value(answer, salt)
        recovery_hash = self._hash_value(recovery_code, salt)

        auth_data = {
            "version": 1,
            "question": question,
            "answer_hash": answer_hash,
            "salt": salt,
            "recovery_code_hash": recovery_hash,
            "failed_attempts": 0,
            "is_locked": False,
            "created_at": datetime.now().isoformat(),
            "last_verified_at": None
        }

        with open(self.auth_file, "w") as f:
            json.dump(auth_data, f, indent=2)

        security_logger.info("IdentityManager setup completed successfully.")
        return {
            "success": True,
            "recovery_code": recovery_code
        }

    def get_question(self) -> str:
        """Retrieves the configured security question."""
        if not self.is_configured():
            raise FileNotFoundError("AgentShield Auth configuration file not found. Run setup first.")
        
        with open(self.auth_file, "r") as f:
            data = json.load(f)
        return data["question"]

    def is_locked(self) -> bool:
        """Checks if the user account is locked due to excess login failures."""
        if not self.is_configured():
            return False
            
        with open(self.auth_file, "r") as f:
            data = json.load(f)
        return data.get("is_locked", False)

    def get_remaining_attempts(self) -> int:
        """Returns the number of verification attempts remaining before lock out."""
        if not self.is_configured():
            return self.max_attempts
            
        with open(self.auth_file, "r") as f:
            data = json.load(f)
        return max(0, self.max_attempts - data.get("failed_attempts", 0))

    def verify_identity(self, answer: str = None) -> bytes:
        """
        Validates the security answer. Prompts via stdin if not provided.
        Returns: master_key (bytes) if correct.
        Raises: PermissionError if verification fails or account is locked.
        """
        if not self.is_configured():
            raise FileNotFoundError("No authentication profile exists. Run setup first.")

        with open(self.auth_file, "r") as f:
            data = json.load(f)

        if data.get("is_locked", False):
            security_logger.error("Authentication rejected: Account is locked.")
            raise PermissionError("Access Blocked: Account is locked. Use recovery code to reset.")

        if not answer:
            print(f"\n[SECURITY VERIFICATION] Soru: {data['question']}")
            answer = input("Cevap: ").strip()

        salt = data["salt"]
        hashed_attempt = self._hash_value(answer, salt)

        if hashed_attempt == data["answer_hash"]:
            # Successful validation
            data["failed_attempts"] = 0
            data["last_verified_at"] = datetime.now().isoformat()
            
            with open(self.auth_file, "w") as f:
                json.dump(data, f, indent=2)

            # Derive cryptographic master key using PBKDF2
            master_key = hashlib.pbkdf2_hmac(
                'sha256',
                answer.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            security_logger.info("Identity verification successful. Master key derived.")
            return master_key
        else:
            # Failed validation
            data["failed_attempts"] += 1
            if data["failed_attempts"] >= self.max_attempts:
                data["is_locked"] = True
                security_logger.critical("Account locked due to consecutive verification failures.")
                
            with open(self.auth_file, "w") as f:
                json.dump(data, f, indent=2)

            remaining = self.max_attempts - data["failed_attempts"]
            raise PermissionError(f"Incorrect answer. Remaining attempts: {max(0, remaining)}")

    def recover_identity(self, recovery_code: str = None, new_question: str = None, new_answer: str = None) -> dict:
        """
        Resets authentication profile using the recovery code.
        Generates a new recovery code and resets locks.
        Returns: {'success': bool, 'new_recovery_code': str}
        """
        if not self.is_configured():
            raise FileNotFoundError("No authentication profile exists. Run setup first.")

        with open(self.auth_file, "r") as f:
            data = json.load(f)

        if not recovery_code:
            recovery_code = input("Enter recovery code (e.g. F7A2-9C44-D881-E3B9): ").strip()

        salt = data["salt"]
        hashed_attempt = self._hash_value(recovery_code, salt)

        if hashed_attempt != data["recovery_code_hash"]:
            security_logger.warning("Invalid recovery code attempt.")
            raise PermissionError("Invalid recovery code.")

        # Unlock and configure new credentials
        print("\n[RECOVERY SUCCESSFUL] Please configure your new credentials.")
        res = self.setup_identity(question=new_question, answer=new_answer)
        security_logger.info("Identity recovered and profile reset successfully.")
        return {
            "success": True,
            "new_recovery_code": res["recovery_code"]
        }
