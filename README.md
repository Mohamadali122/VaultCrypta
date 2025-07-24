#  VaultCrypta

This project provides a secure system for encrypting and decrypting files using AES-256 in CBC mode. It compresses files with GZIP, embeds the original filename, and restores it during decryption.

## ✨ Features

- ✅ Supports multiple file extensions (e.g., `.csv`, `.json`, `.txt`)
- ✅ Automatically compresses and encrypts new files in a watch directory
- ✅ Adds timestamp + random ID to encrypted file names
- ✅ Decryption restores the original filename and extension
- ✅ Uses AES encryption with PKCS7 padding
- ✅ Logs activity and errors for auditing
- ✅ Real-time file monitoring using `watchdog`
- ✅ CLI interface to select encryption or decryption mode
- ✅ **Efficient chunked I/O for large files** (processes files in blocks, not all at once)

---

## 📦 Requirements

- Python 3.7+
- `cryptography` library
- `watchdog` library
- `.env` file with the following config keys:

```env
watch_directory=./input
staging_directory=./staging
output_directory=./output
encryption_key=BASE64_ENCODED_AES_KEY
file_extensions=csv,txt,json
sleep_interval_min=60
sleep_interval_max=120
```

Use a **base64-encoded** AES key (16, 24, or 32 bytes after decoding).

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

### 🧭 CLI Interface

Run the main script to choose between encryption or decryption:

```bash
python main.py encrypt
```

or

```bash
python main.py decrypt
```

This uses a command-line interface with subcommands for flexibility.

---

## ⚡ Performance & Large File Support

**VaultCrypta now processes files in memory-efficient blocks (default: 64KB) instead of loading entire files at once.**

- **Chunked I/O:** Both encryption and decryption stream data through compression and encryption/decompression and decryption, minimizing memory usage.
- **Handles very large files:** Suitable for files much larger than available RAM.
- **Fast and scalable:** Performance is improved for all file sizes, especially large ones.

---

## 🧪 Testing

1. Place a sample `.csv`, `.json`, or `.txt` file in the `watch_directory`.
2. Run `python main.py encrypt` — it will be encrypted and moved to `staging_directory`.
3. Run `python main.py decrypt` — it will decrypt it back into the `output_directory`.

---

## 📁 Folder Structure

```
.
├── enc.py
├── dec.py
├── main.py
├──env_loader.py
├──key_rotation.py
├──logging_system.py
├── .env
├── setup.py
├── requirements.txt
├── LICENSE
├── /input
├── /staging
└── /output
```

---

## 🛡️ Security Notes

- Encryption uses AES-CBC with a securely generated IV.
- Original filenames are embedded in encrypted files for reliable restoration.
- Decrypted files are only saved if decryption and decompression succeed.

---

## ✅ Recommendations

-  Rotate the AES key periodically using key_rotation.py, KEEP A COPY OF YOUR KEY to be able to decrypt your old files.
-  Use `watchdog` for real-time directory monitoring.

---

## 📃 License

MIT — free to use and modify. See `LICENSE` file.

---

## 👨‍💻 Author

[Mohamadali122]

