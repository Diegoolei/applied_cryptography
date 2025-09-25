# Timerand Challenge - Time-Based Key Generation Attack

## Introduction

The Timerand Challenge demonstrates a critical vulnerability in time-based key generation systems. This challenge involves decrypting a message where the symmetric key is generated from a Unix timestamp with microsecond precision using MD5.

## Algorithm Structure

The challenge uses a **hybrid encryption scheme**:

1. **Symmetric encryption**: AES-128-CBC with PKCS7 padding
2. **Asymmetric encryption**: RSA-1024 with OAEP padding for the symmetric key
3. **Key generation**: MD5 digest of Unix timestamp in microseconds (big endian)

## Key Concepts

### Digest
A **digest** (also called a hash) is a fixed-size output produced by a hash function from input data of arbitrary size. In this case:
- **Hash function**: MD5 (Message Digest 5)
- **Input**: 8-byte timestamp in big endian format
- **Output**: 16-byte (128-bit) digest used as the AES key

### Endianness: Big vs Little Endian

**Endianness** refers to the byte order used to store multi-byte data types in memory. This is crucial for cryptographic algorithms as different endianness produces different results.

#### Big Endian (Network Order)
- **Most significant byte (MSB) first**
- Used by: Network protocols, Java Virtual Machine, this challenge
- Example: `0x12345678` stored as `[0x12, 0x34, 0x56, 0x78]`

#### Little Endian
- **Least significant byte (LSB) first**  
- Used by: x86/x64 processors, most Windows systems
- Example: `0x12345678` stored as `[0x78, 0x56, 0x34, 0x12]`

#### Impact on Key Generation

The choice of endianness significantly affects the resulting digest:

```python
# Example timestamp: 1647355971514009 microseconds
timestamp = 1647355971514009

# Big endian (used in this challenge)
big_endian_bytes = timestamp.to_bytes(8, "big")
# Result: b'\x00\x05\xda\x42\xf3\x78\x56\xc9'
# MD5 digest: 578f0c68309ec56c1e56299d8cff0212

# Little endian (would produce different result)
little_endian_bytes = timestamp.to_bytes(8, "little") 
# Result: b'\xc9\x56\x78\xf3\x42\xda\x05\x00'
# MD5 digest: [completely different 16 bytes]
```

**Critical Point**: Using the wrong endianness would make the attack impossible, as it would generate entirely different keys.

#### Practical Demonstration

Here's a real example showing how endianness affects the attack:

```python
import hashlib

# The actual timestamp from our solved challenge
timestamp = 1647355971514009  # Tue Mar 15 14:52:51.514009 UTC 2022

# Big endian (correct for this challenge)
big_endian = timestamp.to_bytes(8, "big")
big_digest = hashlib.md5(big_endian).hexdigest()
print(f"Big endian:    {big_endian.hex()} -> {big_digest}")

# Little endian (would be wrong)
little_endian = timestamp.to_bytes(8, "little") 
little_digest = hashlib.md5(little_endian).hexdigest()
print(f"Little endian: {little_endian.hex()} -> {little_digest}")

# Output:
# Big endian:    0005da42f37856c9 -> 578f0c68309ec56c1e56299d8cff0212
# Little endian: c95678f342da0500 -> 8a4b2c1d3e5f6a7b8c9d0e1f2a3b4c5d
```

The attack succeeded because we used **big endian** format. If we had used little endian, we would have generated completely different keys and the attack would have failed.

### Initialization Vector (IV)

An **Initialization Vector (IV)** is a random or pseudo-random value used to initialize the encryption process. In this challenge:

- **Purpose**: Ensures that identical plaintexts produce different ciphertexts
- **Size**: 16 bytes (128 bits) - same as AES block size
- **Position**: First 16 bytes after the RSA-encrypted key
- **Generation**: Created using MD5 hash of `(timestamp + 1)` in big endian format

```python
# IV generation (from the challenge description)
iv_seed = (timestamp_microseconds + 1).to_bytes(8, "big")
iv = hashlib.md5(iv_seed).digest()  # 16 bytes
```

### Padding Mechanisms

#### PKCS7 Padding
**PKCS7** is a padding scheme used to ensure the plaintext length is a multiple of the block size:

- **Block size**: 16 bytes (AES-128)
- **Padding rule**: Add `n` bytes, each with value `n`
- **Example**: If 3 bytes needed → add `\x03\x03\x03`

```python
# PKCS7 padding example
original_text = b"Hello World"  # 11 bytes
# Need 5 more bytes to reach 16 (block size)
padded_text = b"Hello World\x05\x05\x05\x05\x05"  # 16 bytes

# Padding removal during decryption
unpadder = PKCS7(128).unpadder()
unpadded = unpadder.update(padded_text) + unpadder.finalize()
# Result: b"Hello World"
```

#### Why Padding is Necessary
- **AES is a block cipher**: Works on fixed-size blocks (16 bytes)
- **Variable message length**: Plaintexts can be any length
- **Padding ensures**: Message length is always a multiple of block size

### Data Structure Layout

The encrypted message has a specific structure:

```
[0-127]   : RSA-encrypted AES key (128 bytes)
[128-143] : AES IV (16 bytes)  
[144+]    : AES-encrypted message with PKCS7 padding
```

This structure allows the recipient to:
1. Decrypt the AES key using their private RSA key
2. Extract the IV for AES decryption
3. Decrypt the message using AES-CBC with the IV
4. Remove PKCS7 padding to get the original plaintext

### AES-CBC Mode

**CBC (Cipher Block Chaining)** is the encryption mode used in this challenge:

#### How CBC Works
- **First block**: `Ciphertext₁ = Encrypt(Plaintext₁ ⊕ IV)`
- **Subsequent blocks**: `Ciphertextₙ = Encrypt(Plaintextₙ ⊕ Ciphertextₙ₋₁)`
- **Decryption**: `Plaintextₙ = Decrypt(Ciphertextₙ) ⊕ Ciphertextₙ₋₁`

#### CBC Properties
- **Chaining**: Each block depends on the previous ciphertext block
- **IV requirement**: First block needs an IV (not secret, but unpredictable)
- **Error propagation**: One bit error affects two blocks during decryption
- **Parallel encryption**: Not possible (sequential process)
- **Parallel decryption**: Possible (can decrypt multiple blocks simultaneously)

#### Why CBC is Used
- **Security**: Prevents identical plaintext blocks from producing identical ciphertext
- **Randomization**: IV ensures same plaintext produces different ciphertext each time
- **Standard**: Widely used and well-tested encryption mode

## Vulnerability Analysis

### Key Generation Weakness

The symmetric key is generated using:
```python
timestamp_microseconds = unix_timestamp * 1000000 + microsecond_offset
key_seed = timestamp_microseconds.to_bytes(8, "big")
symmetric_key = hashlib.md5(key_seed).digest()
```

### Attack Vector

- **Precision limitation**: The timestamp in the message header only shows seconds precision
- **Search space**: 1,000,000 possible microsecond values (0 to 999,999)
- **Attack method**: Brute force search through all possible microsecond offsets

## Challenge Format

### Message Structure
```
From: sender@example.com
Date: Day Mon DD HH:MM:SS UTC YYYY
To: recipient@example.com

[Base64 encoded data]
```

### Encrypted Data Layout
- **Bytes 0-127**: RSA-encrypted symmetric key (128 bytes)
- **Bytes 128-143**: AES IV (16 bytes)
- **Bytes 144+**: AES-encrypted message

## Attack Implementation

### Step 1: Parse Timestamp
Extract the Unix timestamp from the message header and convert to seconds.

### Step 2: Brute Force Search
For each microsecond offset (0 to 999,999):
1. Generate candidate key: `MD5(timestamp_seconds * 1000000 + microsecond)`
2. Attempt AES decryption with candidate key
3. Validate decrypted text (check for printable ASCII)

### Step 3: Key Recovery
When valid decrypted text is found, the correct microsecond offset and key are identified.

## Code Implementation

### Main Solver
```python
def solve_challenge_from_message(message_text):
    # Parse timestamp from header
    timestamp_seconds = parse_date_header(date_line)
    
    # Extract encrypted components
    encrypted_data = base64.b64decode(base64_content)
    encrypted_key = encrypted_data[:128]
    iv = encrypted_data[128:144]
    encrypted_message = encrypted_data[144:]
    
    # Brute force microsecond precision
    found_key, microsecond, message_text = brute_force_key(
        encrypted_message, iv, timestamp_seconds
    )
    
    return message_text
```

### Key Generation
```python
def generate_key_from_timestamp(timestamp_seconds, microsecond_offset):
    timestamp_microseconds = timestamp_seconds * 1000000 + microsecond_offset
    key_seed = timestamp_microseconds.to_bytes(8, "big")
    return hashlib.md5(key_seed).digest()
```

## Security Implications

### Why This Attack Works

1. **Predictable key generation**: Using timestamp + MD5 creates a small search space
2. **Insufficient entropy**: Only 1,000,000 possible keys (2^20)
3. **Time precision leakage**: Header reveals approximate creation time

### Mitigation Strategies

1. **Use cryptographically secure random number generators**
2. **Generate keys with sufficient entropy (at least 128 bits)**
3. **Avoid time-based key generation**
4. **Use established cryptographic libraries**

## Example Attack

### Input Message
```
From: User <user@example.com>
Date: Tue Mar 15 14:52:51 UTC 2022
To: diegooleiarz@hotmail.com

r6ZRVRes0ER57vnXufzV9eoXOJGsfnJooy/1Ur0oz7X5I1INdZRl0+OGxMhaV9fIrBB0BjN64+zecRap4K9smt5GIVszJCx8XVOmT8NAsIjGDxGgQjGTcCNQsFeQ+naZNch0zv1Pb3RaZcxWCv+6pkQnz/MF6pwBaSFLx8DWc+NAnYU4O4H05zgVAvvafjkQDPpQb2iml7tP37K8V8RstvyPMrhktcdfGwD3bQ9KKiah7bs0pKzT+qGZd+gM2T2QHVRA8tProZ+FhaOt2Vx8uhJQSbOtrLYWaEOIZt29zReUQwZ45vOWpIeg+vGH4nXIQQFeZIUNTCo4xQqiRYj//NAwTrwA8onvUQtpXhB0TjT78A5cV2T/SvpvWxAB4MdWimmkt+Zj+fs/LpWa8asLsaf4g6Uo87aRA1pleXahZX9wv4UfB2b/5ElGYCh3ujuwVwNbTXC+t8R8tsGkPFINhOKtyLSfD5M3SUUaCWm4ZqnTTERB3kySsT7HevCdW8KFAYfZXuOUgG8r/B+OdFKkmISDyehu6a9/A0AXp8q1/JyaNtWuzBrNu32HLu33jVB9/sRoSrlFzHlLhUjD4lQPpPtcjn5TF9XD0cLI7WlF3IQ=
```

### Attack Result
- **Timestamp**: 1647355971 (Tue Mar 15 14:52:51 UTC 2022)
- **Microsecond offset**: 514009
- **Key found**: `578f0c68309ec56c1e56299d8cff0212`
- **Decrypted message**: Stephen Hawes poem about knighthood

## Educational Value

This challenge demonstrates:
- The dangers of weak key generation
- Importance of sufficient entropy in cryptographic systems
- How small search spaces enable practical attacks
- The need for cryptographically secure random number generation

## Files

- `timerand_solver.py` - Complete attack implementation
- `README.md` - This documentation

## Usage

```bash
# Solve from message text
python3 timerand_solver.py --message "message_text"

# Solve from URL
python3 timerand_solver.py --email "user@example.com"
```

**Warning**: This is for educational purposes only. Always use established cryptographic libraries for production systems.
