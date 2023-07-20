import hashlib
import os

def calculate_hash(file_path, algorithm="sha256"):
    """Calculate the hash of a file using the specified algorithm."""
    if not os.path.isfile(file_path):
        print("Error: The specified file does not exist.")
        return None

    hash_object = hashlib.new(algorithm)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_object.update(chunk)
    except Exception as e:
        print(f"Error: Failed to calculate {algorithm.upper()} hash - {e}")
        return None

    return hash_object.hexdigest()

def verify_hash(file_path, expected_hash, algorithm="sha256"):
    """Verify the hash of a file against the expected hash."""
    calculated_hash = calculate_hash(file_path, algorithm)
    if calculated_hash is None:
        return False

    return calculated_hash == expected_hash

if __name__ == "__main__":
    file_path = input("Enter the file path: ")

    print("Calculating MD5 hash...")
    md5_hash = calculate_hash(file_path, "md5")
    if md5_hash:
        print("MD5 Hash:", md5_hash)

    print("Calculating SHA-256 hash...")
    sha256_hash = calculate_hash(file_path, "sha256")
    if sha256_hash:
        print("SHA-256 Hash:", sha256_hash)

    expected_md5_hash = input("Enter the expected MD5 hash for verification: ")
    if verify_hash(file_path, expected_md5_hash, "md5"):
        print("File integrity verified. MD5 Hash matches the expected MD5 hash.")
    else:
        print("File integrity verification failed. MD5 Hash does not match the expected MD5 hash.")

    expected_sha256_hash = input("Enter the expected SHA-256 hash for verification: ")
    if verify_hash(file_path, expected_sha256_hash, "sha256"):
        print("File integrity verified. SHA-256 Hash matches the expected SHA-256 hash.")
    else:
        print("File integrity verification failed. SHA-256 Hash does not match the expected SHA-256 hash.")
