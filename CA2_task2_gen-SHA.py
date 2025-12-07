
import hashlib

# Specify the file path to compute the hash for
file_path = 'CA2.docx'

def compute_file_hash(file_path, algorithm='sha256'):
   
    
    # Create a new hash object using SHA-256
    # haslib also supports:  SHA-512, SHA-3-256, SHA-1
    hash_func = hashlib.new(algorithm)
    
    # Open the file in binary mode to ensure raw bytes are read.
    with open(file_path, 'rb') as f:
        # Read the file in chunks (8 KB here) to handle large files efficiently.
        # "iter(lambda: f.read(8192), b'')" creates an iterator that reads until EOF.
        for chunk in iter(lambda: f.read(8192), b''):
            # Update the hash object with each chunk.
            hash_func.update(chunk)
    
    # Return the final digest in hex
    return hash_func.hexdigest()

print(f"Computing hashes for file: {file_path}")
# Compute SHA-256 hash (recommended for integrity checks)
print(f"SHA-256 hash: {compute_file_hash(file_path, 'sha256')}")

