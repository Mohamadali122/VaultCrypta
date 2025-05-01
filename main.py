#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI runner: choose to start encryption or decryption service."""
import argparse
from logging_system import logger
from enc import main as encrypt_main
from dec import main as decrypt_main

def main() -> None:
    parser = argparse.ArgumentParser(description="Secure File Encrypt/Decrypt Service")
    subparsers = parser.add_subparsers(dest='command', required=True, help='Select mode')

    subparsers.add_parser('encrypt', help='Start encryption service')
    subparsers.add_parser('decrypt', help='Run decryption service')

    args = parser.parse_args()

    try:
        if args.command == 'encrypt':
            logger.info('Starting encryption service via CLI')
            encrypt_main()
        elif args.command == 'decrypt':
            logger.info('Starting decryption service via CLI')
            decrypt_main()
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()