# agentshield/setup_auth.py
import sys
import os

# Ensure local package import works
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from auth import IdentityManager

def run_setup():
    print("=" * 60)
    print("      🛡️ AGENTSHIELD AUTH SETUP WIZARD")
    print("=" * 60)
    
    manager = IdentityManager()
    if manager.is_configured():
        print("⚠️  AgentShield Auth is already configured!")
        overwrite = input("Do you want to overwrite it and create a new identity? (y/N): ").strip().lower()
        if overwrite != 'y':
            print("Setup cancelled.")
            return

    try:
        print("\nPlease enter a custom security question and answer.")
        print("Note: The answer will be used to derive your cryptographic master key.")
        print("-" * 60)
        res = manager.setup_identity()
        if res["success"]:
            print("\n" + "=" * 60)
            print("🎉 IDENTITY CONFIGURED SUCCESSFULLY!")
            print("=" * 60)
            print("IMPORTANT: Keep your recovery code safe. If you forget your answer,")
            print("this recovery code is the ONLY way to reset your account.")
            print(f"\n🔑 RECOVERY CODE: {res['recovery_code']}")
            print("=" * 60 + "\n")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")

if __name__ == "__main__":
    run_setup()
