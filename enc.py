#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import gzip
import os
import socket
import time
import random
from pathlib import Path
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from env_loader import load_environment
from logging_system import logger
from tqdm import tqdm

AES_BLOCK_SIZE_BYTES = algorithms.AES.block_size // 8

def get_device_name() -> str:
    return socket.gethostname()

def encrypt_and_compress_file(filepath: str, encryption_key_b64: str, staging_dir: str) -> None:
    path = Path(filepath)
    if not path.is_file():
        logger.error(f"File not found or not a regular file: {filepath}")
        return

    try:
        key = base64.b64decode(encryption_key_b64)
    except Exception as e:
        logger.error(f"Invalid base64 encryption key: {e}")
        return
    if len(key) not in (16, 24, 32):
        logger.error(f"Invalid AES key length: {len(key)} bytes. Expected 16, 24, or 32.")
        return

    iv = os.urandom(AES_BLOCK_SIZE_BYTES)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    filename_bytes = path.name.encode('utf-8') + b'\0'
    block_size = 64 * 1024  # 64KB

    timestamp = time.strftime("%Y%m%d-%H%M%S-")
    device = get_device_name()
    rand_id = random.randint(1000, 9999)
    out_name = f"{device}-{timestamp}{rand_id}.enc"

    staging_path = Path(staging_dir)
    staging_path.mkdir(parents=True, exist_ok=True)
    out_path = staging_path / out_name

    try:
        with open(filepath, 'rb') as fin, open(out_path, 'wb') as fout:
            # Write IV first
            fout.write(iv)

            # Prepare a pipe: compress -> encrypt -> write
            # We need to prepend the filename header to the compressed stream
            # We'll use a BytesIO buffer for the header, then stream the rest
            import io
            header = filename_bytes
            # Use a pipe: gzip compresses from fin, prepend header, encrypt in blocks
            class HeaderThenFile(io.RawIOBase):
                def __init__(self, header, fileobj):
                    self.header = header
                    self.fileobj = fileobj
                    self.header_sent = False
                def read(self, size=-1):
                    if not self.header_sent:
                        self.header_sent = True
                        if size == -1:
                            return self.header + self.fileobj.read()
                        else:
                            h = self.header[:size]
                            rest = self.header[size:]
                            if rest:
                                self.header = rest
                                return h
                            else:
                                self.header = b''
                                return h or self.fileobj.read(size - len(h))
                    else:
                        return self.fileobj.read(size)
            header_file = HeaderThenFile(header, fin)
            with gzip.GzipFile(fileobj=header_file, mode='rb') as gzipped:
                # We need to compress the file and encrypt in blocks
                # But gzip.GzipFile does not support reading from a file-like and writing to another file-like directly
                # So we use a buffer
                buffer = b''
                while True:
                    chunk = gzipped.read(block_size)
                    if not chunk:
                        break
                    buffer += chunk
                # Now buffer contains the header+compressed data
                # Pad for AES block size
                pad_len = AES_BLOCK_SIZE_BYTES - (len(buffer) % AES_BLOCK_SIZE_BYTES)
                padded = buffer + bytes([pad_len] * pad_len)
                # Encrypt in blocks
                encrypted = encryptor.update(padded) + encryptor.finalize()
                fout.write(encrypted)
        logger.info(f"Encrypted and saved: '{out_path}'")
    except Exception as e:
        logger.error(f"Failed to encrypt/write file '{filepath}' to '{out_path}': {e}")

def encryption_service() -> None:
    config: Dict[str, Any] = load_environment()
    watch_dir = config.get('watch_directory')
    staging_dir = config.get('staging_directory')
    key_b64 = config.get('encryption_key')
    extensions = config.get('file_extensions')
    extensions = [f".{ext.strip()}" for ext in extensions]
    sleep_min = int(config.get('sleep_interval_min', 60))
    sleep_max = int(config.get('sleep_interval_max', 120))

    if not watch_dir or not staging_dir or not key_b64:
        logger.error("Missing required configuration for encryption. Check .env values.")
        return

    logger.info("Encryption service started.")
    try:
        while True:
            try:
                files = [f for f in os.listdir(watch_dir) if any(f.lower().endswith(ext) for ext in extensions)]
                print(files)
            except Exception as e:
                logger.error(f"Failed to list directory '{watch_dir}': {e}")
                break

            if not files:
                logger.debug(f"No matching files found to encrypt in '{watch_dir}'.")
            else:
                for fname in tqdm(files, desc="Encrypting files", unit="file"):

                    src_path = Path(watch_dir) / fname
                    try:
                        encrypt_and_compress_file(str(src_path), key_b64, staging_dir)
                        src_path.unlink()
                        logger.info(f"Deleted original file after encryption: '{src_path}'")
                    except Exception as e:
                        logger.error(f"Unexpected error processing '{src_path}': {e}")

            snooze = random.randint(sleep_min, sleep_max)
            logger.info(f"Sleeping {snooze}s before next cycle.")
            time.sleep(snooze)
    except KeyboardInterrupt:
        logger.info("Encryption service interrupted and shutting down.")

def main() -> None:
    encryption_service()

if __name__ == '__main__':
    main()
