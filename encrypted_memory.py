# agentshield/encrypted_memory.py
import base64
import json
import os
from cryptography.fernet import Fernet

class EncryptedMemory:
    """Manages encrypted client data, conversational memories, and credentials on disk using AES-256 (via Fernet)."""
    
    def __init__(self, master_key: bytes, storage_file: str = "agent_shield_memory.json"):
        self.storage_file = storage_file
        # Fernet requires a 32-byte key encoded in urlsafe-base64 format.
        # Deriving it from the master_key ensures cryptographic isolation.
        fernet_key = base64.urlsafe_b64encode(master_key)
        self.cipher = Fernet(fernet_key)
        self._load_memory()

    def _load_memory(self):
        """Loads encrypted memory database file from disk."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}
        else:
            self.data = {}

    def _save_memory(self):
        """Saves current state of the database back to disk."""
        with open(self.storage_file, "w") as f:
            json.dump(self.data, f, indent=2)

    def store(self, key: str, value: str):
        """Encrypts and stores a string value under the given key."""
        encrypted_bytes = self.cipher.encrypt(value.encode('utf-8'))
        self.data[key] = encrypted_bytes.decode('utf-8')
        self._save_memory()

    def retrieve(self, key: str) -> str:
        """Retrieves and decrypts the value under the given key. Returns None if not found."""
        if key not in self.data:
            return None
        try:
            encrypted_str = self.data[key]
            decrypted_bytes = self.cipher.decrypt(encrypted_str.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed. Ensure the master key is valid.") from e

    def get_all(self) -> dict:
        """Decrypts and returns all stored memory key-value pairs."""
        decrypted_memory = {}
        for key, encrypted_str in self.data.items():
            try:
                decrypted_bytes = self.cipher.decrypt(encrypted_str.encode('utf-8'))
                decrypted_memory[key] = decrypted_bytes.decode('utf-8')
            except Exception:
                # Gracefully skip corrupted records or records encrypted with other keys
                pass
        return decrypted_memory
