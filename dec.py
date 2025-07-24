#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import gzip
import os
from pathlib import Path
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
from env_loader import load_environment
from logging_system import logger

AES_BLOCK_SIZE_BYTES = algorithms.AES.block_size // 8

def decrypt_and_decompress_file(enc_path: str, encryption_key_b64: str, output_dir: str) -> None:
    path = Path(enc_path)
    if not path.is_file():
        logger.error(f"File not found or not a regular file: {enc_path}")
        return

    try:
        key = base64.b64decode(encryption_key_b64)
    except Exception as e:
        logger.error(f"Invalid base64 encryption key: {e}")
        return
    if len(key) not in (16, 24, 32):
        logger.error(f"Invalid AES key length: {len(key)} bytes. Expected 16, 24, or 32.")
        return

    block_size = 64 * 1024  # 64KB

    try:
        with open(enc_path, 'rb') as fin:
            iv = fin.read(AES_BLOCK_SIZE_BYTES)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            # Read and decrypt in chunks
            decrypted_data = b''
            while True:
                chunk = fin.read(block_size)
                if not chunk:
                    break
                decrypted_data += decryptor.update(chunk)
            decrypted_data += decryptor.finalize()
            if not decrypted_data:
                logger.error(f"Decrypted data is empty for '{enc_path}'")
                return
            pad_len = decrypted_data[-1]
            decrypted = decrypted_data[:-pad_len]
            # Extract original filename
            sep_index = decrypted.find(b'\0')
            if sep_index == -1:
                logger.error(f"No filename found in decrypted payload for '{enc_path}'")
                return
            filename_bytes = decrypted[:sep_index]
            original_name = filename_bytes.decode('utf-8')
            payload = decrypted[sep_index + 1:]
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            out_file = output_path / original_name
            # Decompress in chunks
            import io
            with open(out_file, 'wb') as fout:
                with gzip.GzipFile(fileobj=io.BytesIO(payload), mode='rb') as gzipped:
                    while True:
                        chunk = gzipped.read(block_size)
                        if not chunk:
                            break
                        fout.write(chunk)
            logger.info(f"Decrypted and decompressed '{enc_path}' → '{out_file}'")
    except Exception as e:
        logger.error(f"Failed to decrypt/decompress '{enc_path}': {e}")

def decryption_service() -> None:
    config: Dict[str, Any] = load_environment()
    staging_dir = config.get('staging_directory')
    output_dir = config.get('output_directory')
    key_b64 = config.get('encryption_key')

    if not staging_dir or not output_dir or not key_b64:
        logger.error("Missing required configuration for decryption. Check .env values.")
        return

    logger.info("Decryption service started.")
    try:
        try:
            files = [f for f in os.listdir(staging_dir) if f.lower().endswith('.enc')]
        except Exception as e:
            logger.error(f"Failed to list directory '{staging_dir}': {e}")
            return

        if not files:
            logger.warning(f"No '.enc' files found to decrypt in '{staging_dir}'.")
            return

        for fname in tqdm(files, desc="Decrypting files", unit="file"):
            enc_path = Path(staging_dir) / fname
            try:
                decrypt_and_decompress_file(str(enc_path), key_b64, output_dir)
                enc_path.unlink()
                logger.info(f"Deleted encrypted file after decryption: '{enc_path}'")
            except Exception as e:
                logger.error(f"Unexpected error processing '{enc_path}': {e}")
    except KeyboardInterrupt:
        logger.info("Decryption service interrupted and shutting down.")

def main() -> None:
    decryption_service()

if __name__ == '__main__':
    main()
