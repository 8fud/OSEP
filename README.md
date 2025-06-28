# OSEP -- Encryptor.py

A flexible XOR + AES (AES-256-CTR) encryptor for shellcode, payloads, or strings — designed for use in offensive security, including OSEP-level scenarios.

## Features
- XOR or AES-256-CTR encryption
- Input from file or string
- Output formats: raw bytes, hex string, C array, PowerShell array, C# array
- Random key generation
- Auto SHA-256 key derivation for AES
- Simple decryption stub suggestion for XOR (C)

## Requirements
- Python 3
- `pycryptodome` (`pip install pycryptodome`)

## Example Usage

### XOR with random key, C array output
