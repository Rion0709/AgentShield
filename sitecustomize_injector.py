# agentshield/sitecustomize_injector.py
import sys
import os
import site

def get_sitecustomize_path():
    """Locates the system or user site-packages directory to find sitecustomize.py."""
    # Try system site packages first
    try:
        site_packages_dirs = site.getsitepackages()
        for path in site_packages_dirs:
            if os.access(path, os.W_OK):
                return os.path.join(path, "sitecustomize.py")
    except Exception:
        pass
        
    # Fallback to user-level site packages
    try:
        user_site = site.getusersitepackages()
        os.makedirs(user_site, exist_ok=True)
        return os.path.join(user_site, "sitecustomize.py")
    except Exception:
        pass
        
    return None

def inject() -> bool:
    """Appends AgentShield auto-protection imports to the target sitecustomize.py."""
    path = get_sitecustomize_path()
    if not path:
        print("❌ Error: Could not locate a writable site-packages directory to configure auto-protect.")
        return False
        
    os.makedirs(os.path.dirname(path), exist_ok=True)
    injection_block = (
        "\n# AgentShield Auto-Protect Hook\n"
        "try:\n"
        "    import agentshield\n"
        "    agentshield.init()\n"
        "except Exception:\n"
        "    pass\n"
    )
    
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        if "agentshield.init()" in content:
            print(f"ℹ️  AgentShield auto-protection is already registered in: {path}")
            return True
            
    with open(path, "a", encoding="utf-8") as f:
        f.write(injection_block)
        
    print(f"✅ Success: Registered AgentShield auto-protection in: {path}")
    return True

def remove() -> bool:
    """Removes all AgentShield registration hooks from sitecustomize.py."""
    path = get_sitecustomize_path()
    if not path or not os.path.exists(path):
        print("ℹ️  No custom configurations found. Nothing to remove.")
        return True
        
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Parse and strip the custom injection block
    cleaned_content = []
    lines = content.splitlines()
    skip = False
    
    for line in lines:
        if "# AgentShield Auto-Protect Hook" in line:
            skip = True
            continue
        if skip:
            # Skip the lines within the try-except injection block
            if line.strip() in ["try:", "import agentshield", "agentshield.init()", "except Exception:", "pass", ""]:
                continue
            else:
                skip = False
        cleaned_content.append(line)
        
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(cleaned_content) + "\n")
        
    print(f"✅ Success: Removed AgentShield auto-protection configurations from: {path}")
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--remove":
        remove()
    else:
        inject()
