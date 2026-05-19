# setup.py
from setuptools import setup
from setuptools.command.install import install
import subprocess
import sys
import os

class CustomInstallCommand(install):
    """Post-installation command to register auto-protect hooks."""
    def run(self):
        # Execute normal install steps
        install.run(self)
        
        # Execute sitecustomize_injector configuration script
        try:
            injector_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sitecustomize_injector.py")
            if os.path.exists(injector_path):
                print("Running AgentShield auto-protection registration...")
                subprocess.check_call([sys.executable, injector_path])
        except Exception as e:
            print(f"Warning: Failed to automatically register AgentShield auto-protection: {e}")

setup(
    name="agentshield-firewall",
    version="1.0.0",
    description="AgentShield Enterprise AI Agent Security Firewall",
    author="Antigravity",
    packages=["agentshield"],
    package_dir={"agentshield": "."},
    install_requires=[
        "cryptography>=40.0.0"
    ],
    cmdclass={
        'install': CustomInstallCommand,
    }
)
