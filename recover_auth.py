# agentshield/recover_auth.py
import sys
import os

# Ensure local package import works
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from auth import IdentityManager

def run_recovery():
    print("=" * 60)
    print("      🛡️ AGENTSHIELD ACCOUNT RECOVERY TOOL")
    print("=" * 60)
    
    manager = IdentityManager()
    if not manager.is_configured():
        print("❌ AgentShield is not configured yet. Run setup_auth.py first.")
        return

    try:
        recovery_code = input("Enter recovery code (e.g. F7A2-9C44-D881-E3B9): ").strip()
        print("\nLet's configure a new security question and answer.")
        new_q = input("New Security Question: ").strip()
        new_a = input("New Answer: ").strip()
        
        res = manager.recover_identity(
            recovery_code=recovery_code,
            new_question=new_q,
            new_answer=new_a
        )
        
        if res["success"]:
            print("\n" + "=" * 60)
            print("🎉 ACCOUNT RECOVERED & RESET SUCCESSFULLY!")
            print("=" * 60)
            print("IMPORTANT: Keep your new recovery code safe.")
            print(f"\n🔑 NEW RECOVERY CODE: {res['new_recovery_code']}")
            print("=" * 60 + "\n")
    except Exception as e:
        print(f"\n❌ Recovery failed: {e}")

if __name__ == "__main__":
    run_recovery()
