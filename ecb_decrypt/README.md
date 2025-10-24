# ECB Byte-by-Byte Decryption Attack

## Overview

This challenge demonstrates a fundamental vulnerability in AES encryption using ECB (Electronic Codebook) mode. The attack exploits the deterministic nature of ECB mode to recover a secret message by analyzing encrypted responses to controlled inputs. This is a classic example of an **oracle attack** where the attacker uses the encryption service as a "black box" to learn information about the secret.

## Challenge Description

The server implements the following process:
1. Receives a user-chosen message (base64 encoded)
2. Concatenates it with a secret message: `user_message || secret_message`
3. Encrypts the result with AES-ECB and PKCS7 padding
4. Returns the encrypted result (base64 encoded)

**Server Process:**
```
encode_base64(AES-ECB(decode_base64(user_message) || secret_message))
```

The challenge is to recover the secret message without knowing the encryption key.

## Vulnerability Analysis

### ECB Mode Weakness

ECB mode has a critical flaw: **identical plaintext blocks produce identical ciphertext blocks**. This deterministic behavior allows attackers to:

1. **Predict Encryption Output**: Same input always produces same output
2. **Block-by-Block Analysis**: Analyze individual blocks independently
3. **Oracle Attacks**: Use the encryption service to learn about unknown data

### Attack Strategy: Byte-by-Byte Recovery

The attack works by exploiting block alignment and ECB determinism:

1. **Length Discovery**: Determine the secret message length by analyzing ciphertext length changes
2. **Block Alignment**: Position unknown bytes at block boundaries
3. **Brute Force**: Test all possible byte values (0-255) for each unknown position
4. **Block Matching**: Use ECB determinism to identify correct bytes

## Technical Implementation

### Attack Process

#### Step 1: Determine Secret Length
```python
# Send messages of increasing length
for length in range(0, 33):
    test_message = "A" * length
    encrypted_response = encrypt_message(email, test_message)
    
    # Analyze ciphertext length to determine secret length
    ciphertext_length = len(base64.b64decode(encrypted_response))
```

#### Step 2: Byte-by-Byte Recovery
```python
for byte_position in range(secret_length):
    # Create alignment: 15 known bytes + 1 unknown byte
    known_bytes = "A" * 15
    target_block_index = byte_position // 16
    
    # Get reference block with unknown byte
    reference_message = known_bytes + "B" * padding
    reference_encrypted = encrypt_message(email, reference_message)
    reference_block = get_block(reference_encrypted, target_block_index)
    
    # Test all possible byte values
    for byte_value in range(256):
        test_message = known_bytes + chr(byte_value)
        test_encrypted = encrypt_message(email, test_message)
        test_block = get_block(test_encrypted, target_block_index)
        
        if test_block == reference_block:
            secret_byte = chr(byte_value)
            break
```

### Key Components

- **`ECBDecryptAttack`**: Main attack class implementing byte-by-byte decryption
- **`encrypt_message()`**: Sends messages to the server for encryption
- **`determine_secret_length()`**: Discovers the secret message length
- **`decrypt_byte_by_byte()`**: Recovers the secret message byte by byte
- **`submit_answer()`**: Submits the recovered secret to the server

## Detailed Attack Explanation

### Block Alignment Strategy

The attack relies on precise block alignment:

1. **Target Block**: The block containing the unknown byte
2. **Known Bytes**: 15 bytes we control (padding)
3. **Unknown Byte**: The secret byte we want to recover
4. **Block Boundary**: Position the unknown byte at the end of a block

### Why This Works

1. **ECB Determinism**: Same plaintext block → same ciphertext block
2. **Block Independence**: Each block is encrypted independently
3. **Controlled Input**: We can control 15 out of 16 bytes in a block
4. **Exhaustive Search**: Only 256 possible values for the unknown byte

### Mathematical Foundation

For a block containing bytes `[b0, b1, ..., b14, b15]`:
- We control `b0` through `b14` (15 bytes)
- We want to find `b15` (1 unknown byte)
- ECB determinism: `AES([b0,b1,...,b14,b15]) = C` is unique for each `b15`

By testing all 256 possible values for `b15`, we find the one that produces the target ciphertext block.

## Attack Complexity

- **Time Complexity**: O(n × 256) where n is the secret length
- **Space Complexity**: O(1) - constant space
- **Network Requests**: n × 256 requests to the server
- **Success Rate**: 100% (deterministic attack)

## Files

- **`ecb_decrypt_attack.py`**: Complete attack implementation
- **`test_ecb_decrypt.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python ecb_decrypt_attack.py

# Run tests
python test_ecb_decrypt.py
```

## Example Attack Flow

```python
# 1. Determine secret length
secret_length = attack.determine_secret_length(email)
# Output: "Mensaje secreto tiene aproximadamente 25 bytes"

# 2. Decrypt byte by byte
for i in range(secret_length):
    # Test all 256 possible byte values
    for byte_val in range(256):
        if test_block == target_block:
            secret_byte = chr(byte_val)
            break
    decrypted_secret += secret_byte

# 3. Submit answer
result = attack.submit_answer(email, decrypted_secret)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **ECB Mode Vulnerabilities**: Why ECB is fundamentally insecure
2. **Oracle Attacks**: Using encryption services as information sources
3. **Block Cipher Analysis**: Understanding block-level encryption behavior
4. **Cryptographic Malleability**: How deterministic encryption enables attacks
5. **Padding Attacks**: Importance of proper padding in block ciphers
6. **Side-Channel Information**: How ciphertext length reveals plaintext length

## Security Implications

### Why ECB Mode is Dangerous

1. **Pattern Leakage**: Identical blocks create visible patterns
2. **Deterministic Encryption**: Same input always produces same output
3. **Block Independence**: Blocks can be analyzed and manipulated separately
4. **Oracle Vulnerabilities**: Enables various oracle-based attacks

### Defenses Against This Attack

1. **Use Secure Modes**: CBC, GCM, or ChaCha20-Poly1305
2. **Random IVs**: Ensure different outputs for same inputs
3. **Authentication**: Use authenticated encryption modes
4. **Rate Limiting**: Limit oracle access to prevent exhaustive attacks
5. **Input Validation**: Validate and sanitize all inputs

## Advanced Attack Variations

### Multi-Block Secrets

For secrets longer than 16 bytes, the attack extends naturally:
- Each block is recovered independently
- Block alignment is maintained across multiple blocks
- Attack complexity scales linearly with secret length

### Optimizations

1. **Parallel Requests**: Send multiple requests simultaneously
2. **Caching**: Cache encryption results to avoid duplicate requests
3. **Early Termination**: Stop when correct byte is found
4. **Statistical Analysis**: Use frequency analysis for common characters

## References

- [ECB Mode Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
- [Oracle Attacks](https://en.wikipedia.org/wiki/Oracle_attack)
- [Padding Oracle Attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Cryptographic Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use established cryptographic libraries and secure modes of operation in production systems. ECB mode should never be used for encrypting multiple blocks of data.
