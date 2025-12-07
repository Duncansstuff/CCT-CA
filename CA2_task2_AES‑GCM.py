
# --- AES-GCM ---
from secrets import token_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#Key - this would potentially come from a KMS in  a production envoronement
key = token_bytes(32)               # AES-256 key
print(f"Generated AES-256 key: {key.hex()}")

# Nonce (IV) management
# Use 96-bit nonces (12 bytes)
nonce = token_bytes(12)  # Random nonce per message
print(f"Generated 96-bit nonce: {nonce.hex()}")

# Associated Data (AAD)
# AAD is authenticated but not encrypted use to used to bind context like ID's resource, headers
aad = b"customer_id:89789714298743;table:secret_pii_records"
print(f"Associated Authenticated Data (AAD): {aad.decode()}")

# Encrypt: returns ciphertext and tag, stores nonce and ciphertext as output
aesgcm = AESGCM(key)
plaintext = b"email=john@example.com; card_token=token_abc123"
print(f"\nOriginal plaintext: {plaintext.decode()}")
ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
print(f"Encrypted (ciphertext||tag): {ciphertext_with_tag.hex()}")

# Decryption:  verify tag on failure it raises an exception
print(f"\nDecrypting with same key, nonce, and AAD")
decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
print(f"Decrypted plaintext: {decrypted.decode()}")
assert decrypted == plaintext

