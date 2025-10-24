# Padding Oracle Attack

## Overview

This challenge demonstrates a fundamental vulnerability in AES encryption using CBC (Cipher Block Chaining) mode when the server reveals information about padding validity. The attack exploits the fact that CBC decryption reveals whether padding is valid or not, allowing an attacker to recover the plaintext byte by byte without knowing the encryption key.

## Challenge Description

The server implements the following process:
1. Provides an encrypted message using AES-CBC with PKCS7 padding
2. The IV is sent as the first block of the ciphertext
3. Offers a decryption oracle that reveals padding validity:
   - **200 OK**: Valid padding and successful decryption
   - **400 Bad Request**: Invalid base64 encoding
   - **400 Bad Request**: "Bad padding bytes" - invalid padding or wrong block size

**Server Oracle:**
```
POST /decrypt
- Valid padding → 200 OK
- Invalid padding → 400 "Bad padding bytes"
- Invalid base64 → 400 "not been encoded in base64"
```

The challenge is to decrypt the secret message using only the padding oracle.

## Vulnerability Analysis

### CBC Mode Weakness

CBC mode has a critical vulnerability when padding validation is revealed:

1. **Padding Information Leakage**: Server responses reveal padding validity
2. **Block-by-Block Recovery**: Each block can be decrypted independently
3. **Byte-by-Byte Recovery**: Each byte can be recovered through padding manipulation
4. **No Key Required**: Attack works without knowing the encryption key

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

### Padding Oracle Attack Principle

The attack works by manipulating the previous block (`C[i-1]`) to control the padding in the current block (`P[i]`):

1. **Valid Padding Detection**: Server reveals if padding is valid
2. **Byte Recovery**: Use padding validity to recover individual bytes
3. **Block Recovery**: Recover entire blocks byte by byte
4. **Message Recovery**: Recover the complete message

## Technical Implementation

### Attack Strategy

1. **Ciphertext Analysis**: Understand the structure (IV + encrypted blocks)
2. **Block-by-Block Decryption**: Decrypt each block independently
3. **Byte-by-Byte Recovery**: Use padding oracle to recover each byte
4. **Padding Manipulation**: Control padding to reveal plaintext bytes

### Attack Process

#### Step 1: Analyze Ciphertext Structure
```python
ciphertext = get_challenge_ciphertext(email)
blocks = split_into_blocks(ciphertext)
iv = blocks[0]  # First block is IV
ciphertext_blocks = blocks[1:]  # Rest are encrypted data
```

#### Step 2: Decrypt Block Using Padding Oracle
```python
def decrypt_block(target_block, previous_block):
    decrypted_block = bytearray(16)
    
    # Decrypt byte by byte, starting from the last byte
    for byte_pos in range(15, -1, -1):
        padding_length = 16 - byte_pos
        
        # Modify previous block to create valid padding
        modified_previous = bytearray(previous_block)
        
        # Set padding bytes
        for i in range(byte_pos + 1, 16):
            modified_previous[i] = decrypted_block[i] ^ padding_length
        
        # Try all possible values for current byte
        for byte_value in range(256):
            modified_previous[byte_pos] = byte_value ^ padding_length
            
            if test_decryption(modified_previous + target_block) == "OK":
                decrypted_block[byte_pos] = byte_value
                break
    
    return bytes(decrypted_block)
```

#### Step 3: Decrypt Complete Message
```python
def decrypt_message(ciphertext):
    blocks = split_into_blocks(ciphertext)
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]
    
    decrypted_blocks = []
    
    for i, block in enumerate(ciphertext_blocks):
        if i == 0:
            previous_block = iv
        else:
            previous_block = ciphertext_blocks[i-1]
        
        decrypted_block = decrypt_block(block, previous_block)
        decrypted_blocks.append(decrypted_block)
    
    # Combine and remove padding
    decrypted_data = b''.join(decrypted_blocks)
    return unpad(decrypted_data, 16).decode('utf-8')
```

### Key Components

- **`PaddingOracleAttack`**: Main attack class implementing the padding oracle attack
- **`get_challenge_ciphertext()`**: Retrieves the encrypted challenge message
- **`test_decryption()`**: Tests decryption with the server (padding oracle)
- **`decrypt_block()`**: Decrypts a single block using padding oracle
- **`decrypt_message()`**: Decrypts the complete message
- **`submit_answer()`**: Submits the decrypted message to the server

## Detailed Attack Explanation

### Byte-by-Byte Recovery Process

For each byte position in a block:

1. **Set Up Valid Padding**: Modify the previous block to create valid padding
2. **Try All Byte Values**: Test all 256 possible values for the current byte
3. **Detect Valid Padding**: Use oracle response to identify correct byte
4. **Move to Next Byte**: Repeat for the next byte position

### Mathematical Foundation

The attack exploits the relationship:
```
P[i] = D(C[i]) XOR C[i-1]
```

By modifying `C[i-1]`, we can control `P[i]` to create valid padding:
```
P'[i] = D(C[i]) XOR C'[i-1]
```

When `P'[i]` has valid padding, we know the relationship between `C'[i-1]` and the original plaintext.

### Padding Manipulation

The attack creates specific padding patterns:
- **1-byte padding**: Last byte = 0x01
- **2-byte padding**: Last two bytes = 0x02
- **3-byte padding**: Last three bytes = 0x03
- And so on...

## Attack Complexity

- **Time Complexity**: O(n × 256) where n is the total number of bytes
- **Space Complexity**: O(1) - constant space
- **Network Requests**: n × 256 requests to the server (worst case)
- **Success Rate**: 100% (deterministic attack)

## Files

- **`padding_oracle_attack.py`**: Complete attack implementation
- **`test_padding_oracle.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python padding_oracle_attack.py

# Run tests
python test_padding_oracle.py
```

## Example Attack Flow

```python
# 1. Get challenge ciphertext
ciphertext = attack.get_challenge_ciphertext(email)

# 2. Analyze structure
analysis = attack.analyze_ciphertext(ciphertext)
# Output: "Ciphertext length: 64 bytes, Number of blocks: 4"

# 3. Decrypt block by block
for i, block in enumerate(ciphertext_blocks):
    decrypted_block = attack.decrypt_block(email, block, previous_block)
    print(f"Block {i+1} decrypted: {decrypted_block.hex()}")

# 4. Submit decrypted message
result = attack.submit_answer(email, decrypted_message)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **Padding Oracle Vulnerabilities**: Why revealing padding validity is dangerous
2. **CBC Mode Weaknesses**: How CBC mode can be exploited
3. **Information Leakage**: How small information leaks can lead to complete compromise
4. **Cryptographic Side Channels**: How server responses create side channels
5. **Block Cipher Analysis**: Understanding block-level decryption processes
6. **Practical Cryptanalysis**: Real-world application of theoretical attacks

## Security Implications

### Why Padding Oracles are Dangerous

1. **Complete Message Recovery**: Can decrypt entire messages without the key
2. **No Key Required**: Works without knowing the encryption key
3. **Deterministic Attack**: Always succeeds given enough oracle access
4. **Side Channel Information**: Server responses leak critical information

### Defenses Against Padding Oracle Attacks

1. **Use Authenticated Encryption**: AES-GCM, ChaCha20-Poly1305
2. **Constant-Time Padding Validation**: Always perform full decryption
3. **Message Authentication**: Add HMAC or use authenticated modes
4. **Rate Limiting**: Limit oracle access to prevent exhaustive attacks
5. **Error Handling**: Return consistent error messages regardless of failure type

## Advanced Attack Variations

### Multi-Block Messages

For messages with multiple blocks:
- Each block is decrypted independently
- Previous block is used as "IV" for current block
- Attack scales linearly with message length

### Optimizations

1. **Parallel Requests**: Send multiple requests simultaneously
2. **Caching**: Cache oracle responses to avoid duplicate requests
3. **Early Termination**: Stop when correct byte is found
4. **Statistical Analysis**: Use frequency analysis for common characters

## Common Pitfalls

1. **Block Alignment**: Must understand block boundaries correctly
2. **Padding Validation**: Must handle PKCS7 padding correctly
3. **Byte Order**: Must decrypt bytes in correct order (last to first)
4. **Error Handling**: Must handle network errors and timeouts

## References

- [Padding Oracle Attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [CBC Mode Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)
- [PKCS7 Padding](https://en.wikipedia.org/wiki/PKCS_7)
- [Cryptographic Side Channels](https://en.wikipedia.org/wiki/Side-channel_attack)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use authenticated encryption modes in production systems. Never reveal padding validity information in server responses, as this creates a critical security vulnerability.
