#!/usr/bin/env python3
"""
CipherVault - Simple Encryption & Decryption Module
Supports Caesar Cipher and ROT13 techniques.
"""

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypts plaintext using Caesar Cipher with specified shift value."""
    result = []
    shift = shift % 26
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypts ciphertext using Caesar Cipher with specified shift value."""
    return caesar_encrypt(ciphertext, -shift)


def rot13(text: str) -> str:
    """Applies ROT13 substitution cipher."""
    return caesar_encrypt(text, 13)


def main():
    print("=" * 60)
    print("      🔐 CIPHERVAULT - SIMPLE ENCRYPTION & DECRYPTION 🔐     ")
    print("=" * 60)
    
    sample_text = "Hello, DecodeLabs Cryptography Task!"
    shift_key = 3

    print(f"\nOriginal Input Text:  {sample_text}")
    print(f"Shift Amount (Key):  {shift_key}")

    # 1. Caesar Cipher Demonstration
    encrypted_caesar = caesar_encrypt(sample_text, shift_key)
    decrypted_caesar = caesar_decrypt(encrypted_caesar, shift_key)

    print("\n--- CAESAR CIPHER RESULT ---")
    print(f"Encrypted Output:    {encrypted_caesar}")
    print(f"Decrypted Output:    {decrypted_caesar}")

    # 2. ROT13 Demonstration
    encrypted_rot13 = rot13(sample_text)
    decrypted_rot13 = rot13(encrypted_rot13)

    print("\n--- ROT13 CIPHER RESULT ---")
    print(f"Encrypted Output:    {encrypted_rot13}")
    print(f"Decrypted Output:    {decrypted_rot13}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
