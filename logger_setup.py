import logging
import os

def setup_logger():
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger("ZeroTrustSim")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        handler = logging.FileHandler("logs/activity.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
    return logger