# ECB Forgery Attack

## Overview

This challenge demonstrates the vulnerability of AES encryption in ECB (Electronic Codebook) mode due to its malleability. The attack exploits the fact that ECB mode encrypts each block independently, allowing attackers to swap, duplicate, or rearrange blocks to forge messages.

## Challenge Description

The server allows users to register with an email address and returns a profile in the format:
```
user=<email>&id=<id>&role=user
```

The challenge is to forge an encrypted message that, when decrypted, contains `role=admin` instead of `role=user`.

## Vulnerability Analysis

### ECB Mode Weakness

ECB mode has a fundamental flaw: **identical plaintext blocks produce identical ciphertext blocks**. This makes it vulnerable to:

1. **Pattern Recognition**: Repeated patterns in plaintext are visible in ciphertext
2. **Block Manipulation**: Blocks can be swapped, duplicated, or rearranged
3. **Message Forgery**: New messages can be constructed by combining blocks from different encrypted messages

### Attack Strategy

1. **Find Admin Block**: Create an email that generates a block containing `role=admin`
2. **Get Target Profile**: Obtain the encrypted profile of the target user
3. **Block Substitution**: Replace the last block of the target profile with the admin block
4. **Submit Forged Message**: Send the modified encrypted message to the server

## Implementation

### Key Components

- **`ECBForgeAttack`**: Main attack class implementing the forgery
- **`get_profile()`**: Retrieves user profiles from the server
- **`find_admin_block_email()`**: Discovers emails that generate admin blocks
- **`forge_message()`**: Constructs the forged encrypted message
- **`submit_answer()`**: Submits the forged message to the server

### Attack Process

```python
# 1. Find email that generates admin block
admin_email, admin_block_index = attack.find_admin_block_email(challenge_email)

# 2. Get target profile (encrypted)
target_encrypted = attack.get_profile(challenge_email, target_email, encrypted=True)

# 3. Get admin profile (encrypted)
admin_encrypted = attack.get_profile(challenge_email, admin_email, encrypted=True)

# 4. Split into blocks
target_blocks = split_into_blocks(base64.b64decode(target_encrypted))
admin_blocks = split_into_blocks(base64.b64decode(admin_encrypted))

# 5. Forge message by replacing last block
forged_blocks = target_blocks[:-1] + [admin_blocks[admin_block_index]]

# 6. Reconstruct and submit
forged_message = base64.b64encode(b''.join(forged_blocks))
result = attack.submit_answer(challenge_email, forged_message)
```

## Technical Details

### Block Size and Alignment

- **AES Block Size**: 128 bits (16 bytes)
- **Padding**: PKCS7 padding is applied
- **Alignment**: Email length must be carefully chosen to align `role=admin` at block boundaries

### Email Length Calculation

To create a block containing `role=admin`, we need to calculate the email length that positions this string at the start of a block:

```
user=<email>&id=<id>&role=admin
```

The email length determines where `role=admin` appears in the block structure.

### PKCS7 Padding

The server uses PKCS7 padding:
- Adds 1-16 bytes to make the message length a multiple of 16
- Each padding byte contains the padding length
- Must be valid when the message is decrypted

## Files

- **`ecb_forge_attack.py`**: Complete attack implementation
- **`test_ecb_forge.py`**: Test cases and validation
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python ecb_forge_attack.py

# Run tests
python test_ecb_forge.py
```

## Educational Value

This challenge demonstrates:

1. **Why ECB mode is insecure**: Block independence allows manipulation
2. **Block cipher vulnerabilities**: How identical blocks create security issues
3. **Padding attacks**: Importance of proper padding validation
4. **Cryptographic malleability**: How encryption can be modified without decryption
5. **Practical cryptanalysis**: Real-world application of theoretical vulnerabilities

## Security Implications

- **Never use ECB mode** for encrypting multiple blocks of data
- **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305)
- **Implement proper padding validation**
- **Use random IVs** for CBC mode
- **Consider message authentication** for all encrypted communications

## References

- [ECB Mode Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
- [Padding Oracle Attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Cryptographic Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Warning

This is an educational demonstration. Always use established cryptographic libraries and secure modes of operation in production systems.
