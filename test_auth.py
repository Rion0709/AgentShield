# agentshield/test_auth.py
import sys
import os

# Ensure local package import works
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from auth import IdentityManager
from encrypted_memory import EncryptedMemory

def run_auth_tests():
    # Temporary files for testing to prevent pollution
    auth_file = "test_shield_auth.json"
    memory_file = "test_shield_memory.json"
    
    # Cleanup previous test runs
    for f in [auth_file, memory_file]:
        if os.path.exists(f):
            os.remove(f)

    print("=" * 60)
    print("      🛡️ AGENTSHIELD AUTHENTICATION LAYER TESTS")
    print("=" * 60)
    
    passed = 0
    total = 0
    
    # Test 1: Setup identity profile
    total += 1
    print("\n[Test 1] Initial Setup Profile Creation")
    manager = IdentityManager(auth_file=auth_file)
    res = manager.setup_identity(question="Who is your favorite developer?", answer="Antigravity")
    if res["success"] and len(res["recovery_code"]) == 19:
        print("  - Status: ✅ PASSED (Identity profile created, recovery code generated)")
        passed += 1
        recovery_code = res["recovery_code"]
    else:
        print("  - Status: ❌ FAILED")
        recovery_code = None

    # Test 2: Successful authentication & Master Key Derivation
    total += 1
    print("\n[Test 2] Successful Authentication and Key Derivation")
    try:
        master_key_1 = manager.verify_identity(answer="Antigravity")
        if isinstance(master_key_1, bytes) and len(master_key_1) == 32:
            print("  - Status: ✅ PASSED (Master key derived, exactly 32 bytes)")
            passed += 1
        else:
            print("  - Status: ❌ FAILED (Invalid key shape)")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 3: Failed authentication (Incorrect answer)
    total += 1
    print("\n[Test 3] Failed Authentication Attempt")
    try:
        manager.verify_identity(answer="WrongAnswer")
        print("  - Status: ❌ FAILED (Allowed incorrect credentials)")
    except PermissionError as e:
        print(f"  - Status: ✅ PASSED (Authentication blocked: {e})")
        passed += 1
    except Exception as e:
        print(f"  - Status: ❌ FAILED (Wrong exception type: {e})")

    # Test 4: Check remaining attempts decrementing
    total += 1
    print("\n[Test 4] Verify Remaining Attempts Decrementing")
    remaining = manager.get_remaining_attempts()
    if remaining == 2:
        print("  - Status: ✅ PASSED (Remaining attempts decremented to 2)")
        passed += 1
    else:
        print(f"  - Status: ❌ FAILED (Remaining: {remaining})")

    # Test 5: Verify Lockout Mechanism
    total += 1
    print("\n[Test 5] Trigger Verification Lockout")
    try:
        # We need 2 more failures to trigger lockout (since max is 3 and we already have 1)
        try:
            manager.verify_identity(answer="IncorrectAgain")
        except PermissionError:
            pass
            
        try:
            manager.verify_identity(answer="IncorrectLastTime")
        except PermissionError:
            pass
            
        # Verify it's locked
        if manager.is_locked():
            print("  - Status: ✅ PASSED (Account locked after 3 failures)")
            passed += 1
        else:
            print("  - Status: ❌ FAILED (Account not locked)")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 6: Block authentication when locked
    total += 1
    print("\n[Test 6] Verification Blocked on Locked Profile")
    try:
        manager.verify_identity(answer="Antigravity")
        print("  - Status: ❌ FAILED (Allowed login on locked account)")
    except PermissionError as e:
        if "locked" in str(e).lower():
            print("  - Status: ✅ PASSED (Login correctly blocked with account locked error)")
            passed += 1
        else:
            print(f"  - Status: ❌ FAILED (Wrong error message: {e})")

    # Test 7: Account recovery & reset credentials
    total += 1
    print("\n[Test 7] Account Recovery and Reset Credentials")
    try:
        res_rec = manager.recover_identity(
            recovery_code=recovery_code,
            new_question="New question?",
            new_answer="NewAnswer"
        )
        if res_rec["success"] and not manager.is_locked() and manager.get_remaining_attempts() == 3:
            print("  - Status: ✅ PASSED (Profile unlocked and reset with new question)")
            passed += 1
            new_recovery_code = res_rec["new_recovery_code"]
        else:
            print("  - Status: ❌ FAILED")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 8: Verify authentication with new credentials
    total += 1
    print("\n[Test 8] Validate New Credentials and Derive Master Key")
    try:
        master_key_2 = manager.verify_identity(answer="NewAnswer")
        if isinstance(master_key_2, bytes) and len(master_key_2) == 32:
            print("  - Status: ✅ PASSED (New credentials verified successfully)")
            passed += 1
        else:
            print("  - Status: ❌ FAILED")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 9: Encrypted Memory storage & retrieval (AES-256 Fernet check)
    total += 1
    print("\n[Test 9] Encrypted Memory Storage & Retrieval")
    try:
        mem = EncryptedMemory(master_key=master_key_2, storage_file=memory_file)
        mem.store("system_password", "super_secret_db_password_123")
        mem.store("api_token", "jwt_token_example")
        
        # Verify read
        dec_pw = mem.retrieve("system_password")
        dec_token = mem.retrieve("api_token")
        
        if dec_pw == "super_secret_db_password_123" and dec_token == "jwt_token_example":
            print("  - Status: ✅ PASSED (Values successfully encrypted and decrypted)")
            passed += 1
        else:
            print(f"  - Status: ❌ FAILED (Decrypted values mismatch: {dec_pw}, {dec_token})")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 10: Verify raw data file contains ciphertext (No leak of plaintext to disk)
    total += 1
    print("\n[Test 10] Plaintext Leak Prevention Check")
    try:
        with open(memory_file, "r") as f:
            raw_content = f.read()
        if "super_secret_db_password_123" not in raw_content:
            print("  - Status: ✅ PASSED (Plaintext not leaked to database file)")
            passed += 1
        else:
            print("  - Status: ❌ FAILED (Plaintext leaked in raw file content!)")
    except Exception as e:
        print(f"  - Status: ❌ FAILED ({e})")

    # Test 11: Cryptographic Isolation (Old key cannot decrypt new memory)
    total += 1
    print("\n[Test 11] Cryptographic Isolation Check")
    try:
        # master_key_1 was derived from "Antigravity", master_key_2 is derived from "NewAnswer"
        bad_mem = EncryptedMemory(master_key=master_key_1, storage_file=memory_file)
        try:
            bad_mem.retrieve("system_password")
            print("  - Status: ❌ FAILED (Successfully decrypted value with incorrect master key)")
        except ValueError:
            print("  - Status: ✅ PASSED (Correctly rejected decryption using invalid key)")
            passed += 1
    except Exception as e:
        print(f"  - Status: ❌ FAILED (Wrong exception: {e})")

    print("\n" + "=" * 60)
    print(f"📈 RESULTS: {passed}/{total} tests completed successfully.")
    print("=" * 60)

    # Cleanup temporary test files after success
    for f in [auth_file, memory_file]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    run_auth_tests()
