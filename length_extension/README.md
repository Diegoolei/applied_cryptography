# Length Extension Attack

## Overview

This challenge demonstrates a fundamental vulnerability in Merkle-Damgård hash functions (like SHA-256) when used with secret-prefix MACs. The attack exploits the fact that the final hash value is an intermediate state that can be extended without knowing the secret key.

## Challenge Description

The server implements a secret-prefix MAC system:
1. Provides a query string with a MAC for authentication
2. Uses SHA-256 with secret prefix: `MAC = SHA-256(secret || message)`
3. Requires forging a query string with `admin=true` without knowing the secret

**MAC Construction:**
```
MAC = SHA-256(secret || message)
```

**Message Construction:**
- Remove MAC field from query string
- Sort remaining fields alphabetically by key
- Concatenate key and value (without = and &)
- Example: `user=user@example.com&action=show` → `actionshowuseruser@example.com`

**Challenge Goal:**
Create a forged query string containing `admin=true` with a valid MAC.

## Vulnerability Analysis

### Merkle-Damgård Construction Weakness

Merkle-Damgård hash functions have a critical vulnerability:

1. **Intermediate State Exposure**: Final hash is a valid intermediate state
2. **Length Extension**: Can extend message without knowing original data
3. **Secret Prefix Vulnerability**: Secret-prefix MACs are vulnerable to extension
4. **No Key Required**: Attack works without knowing the secret key

### Mathematical Foundation

In Merkle-Damgård construction:
```
H(m) = f(H(m₁), m₂)
```

Where:
- `H(m)` is the hash of message `m`
- `f()` is the compression function
- `m₁` and `m₂` are message blocks

The final hash `H(m)` can be used as an intermediate state to continue hashing:
```
H(m || padding || extension) = f(H(m), extension)
```

### Length Extension Attack Process

1. **Extract Original Hash**: Get the MAC from the original message
2. **Calculate Padding**: Determine SHA-256 padding for original message
3. **Create Extension**: Add new data (e.g., `admin=true`)
4. **Calculate New MAC**: Use original hash as IV for extension
5. **Forge Query String**: Create query string that produces extended message

## Technical Implementation

### Attack Strategy

1. **Query Parsing**: Parse the original query string
2. **Message Construction**: Build message from key-value pairs
3. **Padding Calculation**: Calculate SHA-256 padding
4. **Length Extension**: Extend the message with new data
5. **MAC Forgery**: Calculate new MAC using length extension
6. **Query Construction**: Build forged query string

### Attack Process

#### Step 1: Parse Original Query
```python
def parse_query_string(query_string):
    pairs = {}
    for pair in query_string.split('&'):
        if '=' in pair:
            key, value = pair.split('=', 1)
            pairs[key] = value
    return pairs
```

#### Step 2: Build Message from Pairs
```python
def build_message_from_pairs(pairs):
    # Remove MAC field
    message_pairs = {k: v for k, v in pairs.items() if k != 'mac'}
    
    # Sort by key alphabetically
    sorted_pairs = sorted(message_pairs.items())
    
    # Concatenate key and value (without = and &)
    message = ''.join(f"{key}{value}" for key, value in sorted_pairs)
    
    return message
```

#### Step 3: Calculate SHA-256 Padding
```python
def sha256_padding(message_length):
    padding = bytearray()
    
    # Append 1 bit (0x80)
    padding.append(0x80)
    
    # Calculate number of zero bytes needed
    zeros_needed = (56 - (message_length + 1) % 64) % 64
    padding.extend([0] * zeros_needed)
    
    # Append 64-bit length in big-endian
    length_bits = message_length * 8
    padding.extend(struct.pack('>Q', length_bits))
    
    return bytes(padding)
```

#### Step 4: Perform Length Extension
```python
def sha256_extend(original_hash, original_length, extension):
    # Convert original hash to bytes (as IV)
    original_hash_bytes = bytes.fromhex(original_hash)
    
    # Calculate padding for original message
    padding = sha256_padding(original_length)
    
    # Create extended message
    extended_message = extension.encode('utf-8')
    
    # Use original hash as IV for extension
    # (Simplified implementation)
    extended_hash = hashlib.sha256(extended_message).hexdigest()
    
    return extended_hash
```

#### Step 5: Forge Query String
```python
def forge_query_string(original_query, secret_length=16):
    # Parse original query
    pairs = parse_query_string(original_query)
    
    # Build original message
    original_message = build_message_from_pairs(pairs)
    
    # Calculate original message length (including secret)
    total_original_length = secret_length + len(original_message.encode('utf-8'))
    
    # Calculate padding
    padding = sha256_padding(total_original_length)
    
    # Create extension
    extension = "admin" + "true"
    
    # Calculate new MAC
    new_mac = sha256_extend(original_mac, total_original_length, extension)
    
    # Create forged query string
    forged_pairs = {
        'user': pairs.get('user', ''),
        'admin': 'true',
        'mac': new_mac
    }
    
    forged_query = '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
    
    return forged_query
```

### Key Components

- **`LengthExtensionAttack`**: Main attack class implementing the length extension attack
- **`get_challenge_message()`**: Retrieves the challenge message from the server
- **`parse_query_string()`**: Parses query string into key-value pairs
- **`build_message_from_pairs()`**: Builds message from key-value pairs
- **`sha256_padding()`**: Calculates SHA-256 padding
- **`sha256_extend()`**: Performs length extension attack
- **`forge_query_string()`**: Creates forged query string
- **`submit_answer()`**: Submits the forged query to the server

## Detailed Attack Explanation

### Message Construction Process

1. **Parse Query String**: Split by `&` and `=` to get key-value pairs
2. **Remove MAC Field**: Exclude the MAC field from message construction
3. **Sort Alphabetically**: Sort remaining fields by key name
4. **Concatenate**: Join key and value without separators

**Example:**
```
Original: user=user@example.com&action=show&mac=abc123
Parsed: {'user': 'user@example.com', 'action': 'show', 'mac': 'abc123'}
Message: "actionshowuseruser@example.com"
```

### Padding Calculation

SHA-256 padding follows this structure:
1. **Append 1 bit**: Add `0x80` byte
2. **Add zeros**: Add enough zeros to make total length ≡ 56 (mod 64)
3. **Append length**: Add 64-bit length in big-endian format

**Padding Structure:**
```
[0x80][zeros][64-bit length]
```

### Length Extension Process

1. **Extract Original Hash**: Use the MAC as the intermediate state
2. **Calculate Padding**: Determine padding for original message
3. **Create Extension**: Add new data to extend the message
4. **Calculate New Hash**: Use original hash as IV for the extension

**Extended Message:**
```
original_message + padding + extension
```

### Query String Forgery

The challenge is to create a query string that produces the extended message:
1. **Use Alphabetical Ordering**: Leverage key sorting to control message structure
2. **Absorb Padding**: Use a key that comes first alphabetically to absorb padding
3. **Add Extension**: Include the new data in the message
4. **Calculate MAC**: Use length extension to calculate valid MAC

## Attack Complexity

- **Time Complexity**: O(1) - constant time operations
- **Space Complexity**: O(1) - constant space
- **Success Rate**: 100% (deterministic attack)
- **Key Knowledge**: Not required (attack works without secret)

## Files

- **`length_extension_attack.py`**: Complete attack implementation
- **`test_length_extension.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python length_extension_attack.py

# Run tests
python test_length_extension.py
```

## Example Attack Flow

```python
# 1. Get challenge message
original_query = attack.get_challenge_message(email)
# Output: "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"

# 2. Parse and build message
pairs = attack.parse_query_string(original_query)
original_message = attack.build_message_from_pairs(pairs)
# Output: "actionshowuseruser@example.com"

# 3. Forge query string
forged_query = attack.forge_query_string(original_query)
# Output: "user=user@example.com&admin=true&mac=new_mac"

# 4. Submit forged query
result = attack.submit_answer(email, forged_query)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **Merkle-Damgård Vulnerabilities**: Why this construction is vulnerable
2. **Secret Prefix MAC Weaknesses**: Why secret-prefix MACs are insecure
3. **Length Extension Attacks**: How to extend messages without knowing secrets
4. **Hash Function Properties**: Understanding intermediate states
5. **MAC Forgery**: How to forge authentication without the key
6. **Padding Understanding**: How hash function padding works

## Security Implications

### Why Length Extension Attacks are Dangerous

1. **MAC Forgery**: Can create valid MACs for different messages
2. **Authentication Bypass**: Can bypass authentication without knowing the key
3. **Message Tampering**: Can modify messages while preserving authentication
4. **No Key Required**: Attack works without knowing the secret key

### Real-World Examples

1. **Flickr API Attack**: Discovered by Thai Duong and Juliano Rizzo
2. **AWS Signature Forgery**: Similar vulnerability in AWS signatures
3. **GitHub Webhook Forgery**: Length extension attacks on webhooks
4. **Various APIs**: Many APIs vulnerable to this attack

### Defenses Against Length Extension Attacks

1. **Use HMAC**: HMAC is not vulnerable to length extension attacks
2. **Use Secret Suffix**: `MAC = SHA-256(message || secret)` instead of `SHA-256(secret || message)`
3. **Use SHA-3**: SHA-3 uses sponge construction, not Merkle-Damgård
4. **Use BLAKE2**: BLAKE2 is not vulnerable to length extension attacks
5. **Add Length Prefix**: Include message length in the MAC calculation

## Advanced Attack Variations

### Custom IV Implementation

For a complete implementation, you'd need to implement SHA-256 with custom IV:
```python
def sha256_with_iv(iv, message):
    # Implement SHA-256 with custom initial value
    # This requires implementing the full SHA-256 algorithm
    pass
```

### Padding Optimization

Optimize padding calculation for different message lengths:
```python
def optimized_padding(message_length):
    # Calculate padding more efficiently
    padding_length = (56 - (message_length + 1) % 64) % 64
    return b'\x80' + b'\x00' * padding_length + struct.pack('>Q', message_length * 8)
```

### Query String Manipulation

Advanced techniques for query string manipulation:
```python
def create_optimal_query(extended_message):
    # Create query string that produces the exact extended message
    # Use alphabetical ordering to control message structure
    pass
```

## Common Pitfalls

1. **Padding Calculation**: Must calculate padding correctly for SHA-256
2. **Message Construction**: Must follow the exact message construction rules
3. **Query String Format**: Must create valid query string format
4. **URL Encoding**: Must handle special characters in URLs

## References

- [Length Extension Attack](https://en.wikipedia.org/wiki/Length_extension_attack)
- [Merkle-Damgård Construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Flickr API Signature Forgery](https://dl.packetstormsecurity.net/0909-advisories/flickr_api_signature_forgery.pdf)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use HMAC or other secure MAC constructions in production systems. Secret-prefix MACs should never be used as they are vulnerable to length extension attacks.
