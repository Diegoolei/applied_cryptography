#!/usr/bin/env python3
"""
Timerand Challenge Solver - Educational Version
Solves the cryptographic challenge where a key is generated from timestamp + microsecond precision
"""

import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend

def parse_timestamp(date_str):
    """Parse Unix timestamp from date header"""
    date_str = date_str.replace("Date: ", "")
    dt = datetime.strptime(date_str, "%a %b %d %H:%M:%S UTC %Y")
    return int(dt.timestamp())

def generate_key(timestamp_seconds, microsecond_offset):
    """Generate MD5 key from timestamp + microsecond offset"""
    timestamp_microseconds = timestamp_seconds * 1000000 + microsecond_offset
    key_seed = timestamp_microseconds.to_bytes(8, "big")
    return hashlib.md5(key_seed).digest()

def decrypt_aes(encrypted_data, key, iv):
    """Decrypt AES-128-CBC message with PKCS7 padding"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt and remove padding
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

def is_valid_text(data):
    """Check if decrypted data is valid ASCII text"""
    try:
        text = data.decode('utf-8')
        return len(text) > 5 and all(ord(c) >= 32 and ord(c) <= 126 for c in text[:20])
    except:
        return False

def brute_force_attack(encrypted_message, iv, timestamp_seconds):
    """Brute force microsecond precision to find correct key"""
    print(f"Brute forcing {1000000} possible microsecond offsets...")
    
    for microsecond in range(1000000):
        if microsecond % 100000 == 0:
            print(f"Progress: {microsecond}/1000000")
        
        # Generate candidate key
        key = generate_key(timestamp_seconds, microsecond)
        
        # Try to decrypt
        try:
            decrypted = decrypt_aes(encrypted_message, key, iv)
            if is_valid_text(decrypted):
                print(f"SUCCESS! Found key at microsecond: {microsecond}")
                return key, microsecond, decrypted.decode('utf-8')
        except:
            continue
    
    return None, None, None

def solve_challenge(message_text):
    """Main solver function"""
    lines = message_text.strip().split('\n')
    
    # Extract timestamp
    date_line = next(line for line in lines if line.startswith("Date:"))
    timestamp_seconds = parse_timestamp(date_line)
    print(f"Timestamp: {timestamp_seconds}")
    
    # Extract encrypted data
    base64_content = ""
    in_content = False
    for line in lines:
        if line.strip() == "":
            in_content = True
            continue
        if in_content:
            base64_content += line.strip()
    
    # Decode and extract components
    encrypted_data = base64.b64decode(base64_content)
    encrypted_key = encrypted_data[:128]    # RSA-encrypted AES key
    iv = encrypted_data[128:144]           # AES IV
    encrypted_message = encrypted_data[144:] # AES-encrypted message
    
    print(f"Data lengths - Key: {len(encrypted_key)}, IV: {len(iv)}, Message: {len(encrypted_message)}")
    
    # Brute force attack
    found_key, microsecond, message = brute_force_attack(encrypted_message, iv, timestamp_seconds)
    
    if found_key:
        print(f"Key: {found_key.hex()}")
        print(f"Message:\n{message}")
        return message
    else:
        print("Attack failed - no valid key found")
        return None
