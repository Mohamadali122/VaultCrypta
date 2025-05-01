# env_loader.py

import os
from dotenv import load_dotenv

def load_environment(dotenv_path="./.env"):
    """Load environment variables and validate."""
    if not os.path.exists(dotenv_path):
        raise FileNotFoundError(f"{dotenv_path} not found.")

    load_dotenv(dotenv_path)

    encryption_key = os.getenv("ENCRYPTION_KEY")
    if encryption_key is None:
        raise ValueError("ENCRYPTION_KEY missing in .env")

    return {
        "encryption_key": encryption_key,
        "watch_directory": os.getenv("WATCH_DIRECTORY", "./watch"),
        "staging_directory": os.getenv("STAGING_DIRECTORY", "./staging"),
        "output_directory": os.getenv("OUTPUT_DIRECTORY", "./decrypted_files"),
        "sleep_interval_min": int(os.getenv("SLEEP_INTERVAL_MIN", "60")),
        "sleep_interval_max": int(os.getenv("SLEEP_INTERVAL_MAX", "300")),
        "file_extensions": os.getenv("FILE_EXTENSIONS", "csv").lower().split(",")
    }