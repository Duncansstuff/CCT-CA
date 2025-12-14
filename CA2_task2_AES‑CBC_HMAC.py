
# AES-CBC with HMAC
# Confidentiality and Integrity
# The code below shows confidentiality (AES CBC) and integrity (HMAC SHA 256). 
# It Uses PKCS#7 padding, stores Initialization vector, cipher text and tag.


from secrets import token_bytes               # CSPRNG for keys, IVs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad    # PKCS#7 padding for block alignment
import hmac, hashlib

#### Encryption
# Key generation:
# Use independent keys for encryption and MAC to avoid cross alorigm leakage.
enc_key = token_bytes(32)     # AES-256 (32 bytes)
mac_key = token_bytes(32)     # HMAC-SHA-256 key (also 32 bytes)
print(f"Generated AES-256 encryption key: {enc_key.hex()}")
print(f"Generated HMAC-SHA-256 key: {mac_key.hex()}")

# Example plaintext data to protect:
plaintext = b"customer_creditcard: {id: 12345, name: 'Bob, 'no: '1234123412341234', ccv: '123'}"
print(f"\n Original plaintext ({len(plaintext)} bytes):")
print(f"   {plaintext.decode()}")

# Generate a fresh unpredictable 128-bit Initialization vector (IV) for the AES CBC 
iv = token_bytes(16)          # 16 bytes = 128-bit IV
print(f"\nGenerated 128-bit IV: {iv.hex()}")
cipher = AES.new(enc_key, AES.MODE_CBC, iv)
# PKCS#7 padding ensures the plaintext is a multiple of the AES block size (16 bytes).
padded_plaintext = pad(plaintext, AES.block_size)
print(f"\nEncrypting with AES-256-CBC...")
print(f"Plaintext length: {len(plaintext)} bytes")
print(f"After PKCS#7 padding: {len(padded_plaintext)} bytes")
ciphertext = cipher.encrypt(padded_plaintext)
print(f"Ciphertext: {ciphertext.hex()[:64]}...")

#### Integrity (HMAC)
# Compute the MAC over IV and ciphertext
# Store the HMAC tag with the ciphertext
print(f"\nComputing HMAC-SHA-256 authentication tag...")
tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
print(f"Auth tag: {tag.hex()}")
print(f"Tag size: {len(tag)} bytes")

#Persistantante bundle
bundle = iv + ciphertext + tag
print(f"\nBundle created (IV|ciphertext|tag): {len(bundle)} bytes total")

###### Decryption 
# Parse bundle: first 16 bytes IV, last 32 bytes tag, remainder ciphertext.
print(f"\nDecrypting from bundle...")
iv2, ct2, tag2 = bundle[:16], bundle[16:-32], bundle[-32:]
print(f"Extracted IV: {iv2.hex()}")
print(f"Extracted ciphertext size: {len(ct2)} bytes")
print(f"Extracted tag: {tag2.hex()}")

# Verify integrity before decryption
# If verification fails, abort; do not attempt to decrypt corrupted data.
print(f"\nVerifying HMAC-SHA-256 authentication tag...")
computed_tag = hmac.new(mac_key, iv2 + ct2, hashlib.sha256).digest()
if hmac.compare_digest(computed_tag, tag2):
    print(f"Authentication tag verified - data integrity confirmed")
else:
    raise ValueError("Authentication tag verification failed - data corrupted")

# Decrypt only after successful MAC verification
print(f"\nDecrypting with AES-256-CBC...")
pt = unpad(AES.new(enc_key, AES.MODE_CBC, iv2).decrypt(ct2), AES.block_size)
print(f"After unpadding: {len(pt)} bytes")
print(f"Decrypted plaintext: {pt.decode()}")
assert pt == plaintext
print(f"\nSuccess,  Decrypted plaintext matches original.")
