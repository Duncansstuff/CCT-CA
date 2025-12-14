# This example demonstrates AES-GCM operating in AEAD (Authenticated Encryption with Associated Data) mode.
# AEAD provides both confidentiality (encryption) and integrity/authentication in a single operation.

from secrets import token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Generate a random AES key
# In production, this key would typically come from a secure Key Management System (KMS).
key = token_bytes(32)  # AES-256 key
print(f"Generated AES-256 key: {key.hex()}")

# Generate a nonce / IV (Initialization Vector)
# AES-GCM requires a unique nonce for each encryption operation.
nonce = token_bytes(12)  # Random nonce per message
print(f"Generated 96-bit nonce: {nonce.hex()}")

# Define Associated Authenticated Data (AAD)
# AAD is additional data that is authenticated but not encrypted.
aad = b"customer_id:89789714298743;table:secret_pii_records"
print(f"Associated Authenticated Data (AAD): {aad.decode()}")

# Prepare plaintext for encryption
# This is the data that we want to protect.
plaintext = b"email=john@example.com; card_token=token_abc123"  # sample plaintext
print(f"\nOriginal plaintext: {plaintext.decode()}")

# Encrypt using AES-GCM
# The encrypt() method combines encryption and authentication.
# It returns ciphertext concatenated with the authentication tag.
aesgcm = AESGCM(key)
ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
print(f"Encrypted (ciphertext||tag): {ciphertext_with_tag.hex()}")

# Decrypt and verify
# The decrypt() method checks the authentication tag.
# If verification fails (e.g., wrong key, nonce, or AAD), it raises an exception.
print(f"\nDecrypting with same key, nonce, and AAD")
decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
print(f"Decrypted plaintext: {decrypted.decode()}")
