# CBC Bit Flipping Attack

## Overview

This challenge demonstrates a fundamental vulnerability in AES encryption using CBC (Cipher Block Chaining) mode. The attack exploits the malleability of CBC mode to modify ciphertext blocks and affect the decryption of subsequent blocks in a predictable way. This is a classic example of a **bit flipping attack** where the attacker manipulates ciphertext to achieve desired changes in the decrypted plaintext.

## Challenge Description

The server implements the following process:
1. Receives a user email and additional data (base64 encoded)
2. Creates a profile: `user=<email>;data=<data>;role=user`
3. Encrypts the profile with AES-CBC and PKCS7 padding
4. Prepends a 16-byte IV to the ciphertext
5. Returns the result (IV + ciphertext) base64 encoded

**Server Process:**
```
IV || AES-CBC(profile, key, IV) -> base64_encode(IV || ciphertext)
```

The challenge is to modify the encrypted message so that when decrypted, it contains `role=admin` instead of `role=user`.

## Vulnerability Analysis

### CBC Mode Weakness

CBC mode has a critical vulnerability: **modifying a ciphertext block affects the decryption of the next block in a predictable way**. This malleability allows attackers to:

1. **Bit Flipping**: Change specific bits in ciphertext to affect subsequent blocks
2. **Block Manipulation**: Modify ciphertext blocks to achieve desired plaintext changes
3. **Predictable Changes**: Know exactly how modifications will affect decryption

### CBC Decryption Process

In CBC mode, decryption works as follows:
```
P[i] = D(C[i]) XOR C[i-1]
```

Where:
- `P[i]` is the plaintext block
- `C[i]` is the ciphertext block
- `D()` is the decryption function
- `C[i-1]` is the previous ciphertext block (or IV for the first block)

### Bit Flipping Attack Principle

If we modify `C[i-1]` by XORing it with a value `delta`:
```
C'[i-1] = C[i-1] XOR delta
```

Then the decryption of block `i` becomes:
```
P'[i] = D(C[i]) XOR C'[i-1]
P'[i] = D(C[i]) XOR (C[i-1] XOR delta)
P'[i] = (D(C[i]) XOR C[i-1]) XOR delta
P'[i] = P[i] XOR delta
```

This means we can control exactly how the next block changes by modifying the current block.

## Technical Implementation

### Attack Strategy

1. **Profile Analysis**: Understand the profile structure and block layout
2. **Block Alignment**: Control the data field to align blocks properly
3. **Bit Flip Calculation**: Calculate the XOR mask needed for desired changes
4. **Ciphertext Modification**: Apply the bit flip to the appropriate block
5. **Validation**: Ensure the modified ciphertext produces valid results

### Attack Process

#### Step 1: Analyze Profile Structure
```python
profile = "user=test@example.com;data=TestData;role=user"
# Split into blocks and analyze layout
blocks = split_into_blocks(profile.encode('utf-8'))
```

#### Step 2: Find Target Block
```python
# Find which block contains 'role=user'
role_block_index = find_role_block(profile)
```

#### Step 3: Calculate Bit Flip
```python
# We want to change 'role=user' to 'role=admin'
# Calculate XOR mask for the change
original = b'role=user'
target = b'role=admin'
mask = bytes(a ^ b for a, b in zip(original, target))
```

#### Step 4: Apply Bit Flip
```python
# Modify the previous block to affect the role block
modified_blocks = ciphertext_blocks.copy()
modified_blocks[role_block_index - 1] = bytes(
    a ^ b for a, b in zip(modified_blocks[role_block_index - 1], mask)
)
```

### Key Components

- **`CBCBitFlipAttack`**: Main attack class implementing bit flipping
- **`register_user()`**: Creates user profiles with controlled data
- **`analyze_profile_structure()`**: Analyzes profile layout and block structure
- **`find_role_block()`**: Locates the block containing 'role=user'
- **`calculate_bit_flip()`**: Calculates the XOR mask for desired changes
- **`submit_answer()`**: Submits the modified ciphertext to the server

## Detailed Attack Explanation

### Block Alignment Strategy

The attack relies on precise block alignment:

1. **Target Block**: The block containing 'role=user'
2. **Previous Block**: The block we modify to affect the target
3. **Data Control**: Use the data field to control block alignment
4. **Bit Positioning**: Ensure changes occur at the right positions

### Why This Works

1. **CBC Malleability**: Modifying `C[i-1]` affects `P[i]` predictably
2. **XOR Properties**: `(A XOR B) XOR B = A` allows precise control
3. **Block Independence**: Each block can be modified independently
4. **Controlled Input**: We can control the data field to align blocks

### Mathematical Foundation

For CBC decryption: `P[i] = D(C[i]) XOR C[i-1]`

If we modify `C[i-1]` to `C'[i-1] = C[i-1] XOR delta`:
- `P'[i] = D(C[i]) XOR C'[i-1]`
- `P'[i] = D(C[i]) XOR (C[i-1] XOR delta)`
- `P'[i] = (D(C[i]) XOR C[i-1]) XOR delta`
- `P'[i] = P[i] XOR delta`

This gives us precise control over how the next block changes.

## Attack Complexity

- **Time Complexity**: O(1) - constant time for bit flip calculation
- **Space Complexity**: O(n) where n is the ciphertext length
- **Network Requests**: 2 requests (register + submit)
- **Success Rate**: High (deterministic attack)

## Files

- **`cbc_bitflip_attack.py`**: Complete attack implementation
- **`test_cbc_bitflip.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python cbc_bitflip_attack.py

# Run tests
python test_cbc_bitflip.py
```

## Example Attack Flow

```python
# 1. Register user with controlled data
encrypted_response = attack.register_user(challenge_email, user_email, "TestData")

# 2. Analyze profile structure
analysis = attack.analyze_profile_structure(profile)

# 3. Find role block
role_block_index = attack.find_role_block(profile)

# 4. Calculate bit flip
mask = calculate_bit_flip(original_block, target_block)

# 5. Apply modification
modified_blocks[role_block_index - 1] = apply_bit_flip(modified_blocks[role_block_index - 1], mask)

# 6. Submit modified ciphertext
result = attack.submit_answer(challenge_email, modified_ciphertext)
```

## Educational Value

This challenge demonstrates:

1. **CBC Mode Vulnerabilities**: Why CBC is malleable and vulnerable to bit flipping
2. **Block Cipher Malleability**: How ciphertext modifications affect plaintext
3. **XOR Properties**: Mathematical foundation of bit flipping attacks
4. **Block Alignment**: Importance of understanding block boundaries
5. **Padding Attacks**: How padding affects attack success
6. **Cryptographic Malleability**: Why deterministic encryption is dangerous

## Security Implications

### Why CBC Mode is Vulnerable

1. **Malleability**: Ciphertext can be modified to affect plaintext
2. **Predictable Changes**: Modifications have predictable effects
3. **Block Dependencies**: Each block depends on the previous one
4. **No Authentication**: CBC doesn't provide message authentication

### Defenses Against Bit Flipping Attacks

1. **Use Authenticated Encryption**: AES-GCM, ChaCha20-Poly1305
2. **Message Authentication**: Add HMAC or use authenticated modes
3. **Input Validation**: Validate decrypted data before processing
4. **Constant-Time Comparison**: Prevent timing attacks
5. **Secure Padding**: Use secure padding schemes

## Advanced Attack Variations

### Multi-Block Modifications

For changes spanning multiple blocks:
- Each block can be modified independently
- Changes propagate through the CBC chain
- Complex modifications require careful planning

### Padding Oracle Attacks

Combined with padding oracle vulnerabilities:
- Bit flipping + padding oracle = complete decryption
- More powerful than standalone bit flipping
- Requires additional oracle access

## Common Pitfalls

1. **Block Alignment**: Misaligned blocks cause unpredictable results
2. **Padding Issues**: Invalid padding causes decryption failures
3. **Length Changes**: Changing 'user' to 'admin' changes length
4. **Character Encoding**: UTF-8 encoding can complicate byte-level changes

## References

- [CBC Mode Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
- [Bit Flipping Attacks](https://en.wikipedia.org/wiki/Bit-flipping_attack)
- [Padding Oracle Attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Cryptographic Malleability](https://en.wikipedia.org/wiki/Malleability_(cryptography))

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use authenticated encryption modes in production systems. CBC mode should be used with proper authentication (HMAC) or replaced with authenticated encryption modes like AES-GCM.
