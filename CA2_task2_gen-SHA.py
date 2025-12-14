

# Generate SHA-256 hash, good for file integrity checks 
# Example usese: verifying a download or detecting accidental/unauthorized changes

import hashlib
import os

# Specify the file path to compute the hash for
file_path = 'CA2.docx'  # Change to your target file

def compute_file_hash(file_path, algorithm='sha256'):
    # Compute the hexadecimal digest for a file using the given hashing algorithm.
    # Args:
    # file_path (str): Path to the file to be hashed. File is read in binary mode.
    # algorithm (str): Name of the hashing algorithm (default 'sha256').

    # Returns:
    # Hexadecimal string of the final digest.

    available = {a.lower() for a in hashlib.algorithms_available}
    if algorithm.lower() not in available:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Available: {', '.join(sorted(available))}"
        )

    # Create a new hash function by name.
    hash_func = hashlib.new(algorithm)

    # Reading in fixed-size chunks avoids loading large files into memory.
    # Binary mode ('rb') ensures raw bytes are hashed, not text-decoded data.
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'rb') as f:
        # Iterate until EOF by repeatedly reading 8 KiB blocks.
        # The sentinel b'' indicates end-of-file for the iterator.
        for chunk in iter(lambda: f.read(8192), b''):
            # Feed each chunk into the hash function’s state.
            hash_func.update(chunk)

    # hexdigest() converts the binary digest to a readable hexadecimal string.
    return hash_func.hexdigest()

# Example use case
print(f"Computing hashes for file: {file_path}")

# Compute SHA-256 hash
try:
    sha256_hex = compute_file_hash(file_path, 'sha256')
    print(f"SHA-256 hash: {sha256_hex}")
except (FileNotFoundError, ValueError, OSError) as e:
    # Error output without crashing the entire script.
    print(f"Error: {e}")


