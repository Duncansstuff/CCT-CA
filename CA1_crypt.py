#!/usr/bin/env python3
"""
Cryptography Theory and Practice CA 1, assessment task 3
Author: Duncan M
File Encryptor and Decryptor using AES with PBKDF2 key derivation

Usage:
    To encrypt a file:
        python CA1_crypt.py <file_path> --encrypt
    
    To decrypt a file:
        python CA1_crypt.py <file_path.encrypted> --decrypt
    
    A password will be prompted for encryption/decryption.
"""

import base64
import os
import argparse
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureEncryption:
    def __init__(self):
        self.salt = os.urandom(16)  # Generate a random salt
        
    def generate_key(self, password: str) -> bytes:  ## Generate a secure key using password and salt
        pbkdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(pbkdf.derive(password.encode()))
        return key

    def encrypt_data(self, data: bytes, password: str) -> tuple: #Encrypt the provided data using Fernet (AES)
        key = self.generate_key(password)
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        return encrypted_data, self.salt

    def decrypt_data(self, encrypted_data: bytes, password: str, salt: bytes) -> bytes: # Decrypt the encrypted data using the provided password and salt
        self.salt = salt
        key = self.generate_key(password)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data

def main():  
    parser = argparse.ArgumentParser(description='File encryption/decryption tool')
    parser.add_argument('file', help='File to encrypt/decrypt')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Encrypt the file')
    group.add_argument('--decrypt', action='store_true', help='Decrypt the file')
    args = parser.parse_args()
    
    # Create encryption instance
    encryptor = SecureEncryption()
    
    # Get the password
    password = getpass.getpass('Enter password: ')
    
    try:
        if args.encrypt:
            # Read the input file in binary mode
            with open(args.file, 'rb') as f:
                data = f.read()

            # Encrypt the data
            encrypted_data, salt = encryptor.encrypt_data(data, password)

            # Save encrypted data and salt
            with open(args.file + '.encrypted', 'wb') as f:
                f.write(salt)  # First 16 bytes will be the salt
                f.write(encrypted_data)
            print(f"File encrypted successfully. Output saved to {args.file}.encrypted")

        elif args.decrypt:
            # Read the encrypted file
            with open(args.file, 'rb') as f:
                salt = f.read(16)  # First 16 bytes are the salt
                encrypted_data = f.read()  # Rest is the encrypted data

            # Decrypt the data
            decrypted_data = encryptor.decrypt_data(encrypted_data, password, salt)

            # Save decrypted data in binary mode
            output_file = args.file.replace('.encrypted', '.decrypted')
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            print(f"File decrypted successfully. Output saved to {output_file}")

    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()