# agentshield/logger.py
import logging
import os

def setup_logger(log_file="agentshield.log"):
    """Configures a standardized audit and security logger for AgentShield."""
    logger = logging.getLogger("AgentShield")
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if the logger is re-initialized
    if not logger.handlers:
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [AgentShield] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File Handler (Audit Log)
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            # Fallback in case of write permission issues
            print(f"[AgentShield Warning] Failed to initialize log file handler: {e}")
            
    return logger

# Globally accessible logger instance
security_logger = setup_logger()
