#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
from dotenv import set_key

def generate_encryption_key():
    """Generate a secure 32-byte key for AES-256."""
    key = os.urandom(32)
    return base64.b64encode(key).decode('utf-8')

def update_env_file(dotenv_path=".env"):
    """Rotate encryption key in .env file."""
    new_key = generate_encryption_key()
    set_key(dotenv_path, "ENCRYPTION_KEY", new_key)
    print(f"🔑 ENCRYPTION_KEY rotated and updated in {dotenv_path}")

if __name__ == "__main__":
    update_env_file()
