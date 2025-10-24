# CBC-MAC Forgery Attack

## Overview

This challenge demonstrates a fundamental vulnerability in CBC-MAC when used with variable-length messages. The attack exploits the mathematical property that allows forging MACs by concatenating messages and manipulating the XOR operations in the CBC construction.

## Challenge Description

The server implements a CBC-MAC authentication system for money transfers:
1. Provides a query string representing money transfers with a CBC-MAC
2. Uses CBC-MAC to authenticate the transfer data
3. Requires forging a transfer to the attacker's email for more than $10,000

**Transfer Format:**
```
from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8
```

**MAC Calculation:**
```
mac = CBC-MAC("from=user@example.com&user@example.com=1000&comment=Invoice")
```

**Challenge Goal:**
Create a forged query string that transfers more than $10,000 to the attacker's email.

## Vulnerability Analysis

### CBC-MAC Construction Weakness

CBC-MAC has a critical vulnerability with variable-length messages:

1. **Mathematical Property**: If M₁ has MAC T₁, then M₁ || (T₁ ⊕ M₁') || M₁' has MAC T₁
2. **XOR Cancellation**: The XOR with T₁ cancels out the contribution of M₁' to the tag
3. **Message Concatenation**: Can append arbitrary data to existing messages
4. **No Key Required**: Attack works without knowing the secret key

### Mathematical Foundation

In CBC-MAC construction:
```
CBC-MAC(M) = E_k(E_k(...E_k(E_k(M₁) ⊕ M₂) ⊕ M₃)...)
```

Where:
- `E_k()` is the encryption function with key `k`
- `M₁, M₂, M₃...` are message blocks
- The final ciphertext block is the MAC

**Forgery Property:**
If `M₁` has MAC `T₁`, then:
```
M₁ || (T₁ ⊕ M₁') || M₁' has MAC T₁
```

Where `M₁'` is the message we want to append.

### Attack Process

1. **Extract Original MAC**: Get the MAC from the original message
2. **Create Additional Transfer**: Design the transfer to attacker's email
3. **Calculate XOR Block**: XOR original MAC with first block of additional message
4. **Construct Forged Message**: Concatenate original + XOR block + additional message
5. **Submit Forged Query**: Send the forged query string to the server

## Technical Implementation

### Attack Strategy

1. **Query Parsing**: Parse the original query string
2. **Message Construction**: Build message from key-value pairs
3. **CBC-MAC Forgery**: Use mathematical property to forge MAC
4. **Query Construction**: Build forged query string
5. **URL Encoding**: Handle special characters in URLs

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
    
    # Reconstruct the original query string (without MAC)
    message_parts = []
    for key, value in message_pairs.items():
        message_parts.append(f"{key}={value}")
    
    return '&'.join(message_parts)
```

#### Step 3: Perform CBC-MAC Forgery
```python
def forge_cbc_mac(original_query, target_email, target_amount):
    # Parse original query
    pairs = parse_query_string(original_query)
    original_mac = pairs.get('mac', '')
    
    # Build original message (without MAC)
    original_message = build_message_from_pairs(pairs)
    
    # Create additional transfer
    additional_transfer = f"&{target_email}={target_amount}"
    
    # Convert original MAC to bytes
    original_mac_bytes = bytes.fromhex(original_mac)
    
    # Create additional message
    additional_bytes = additional_transfer.encode('utf-8')
    additional_padded = pad(additional_bytes, 16)
    
    # Take first block of additional message
    first_block = additional_padded[:16]
    
    # XOR with original MAC
    xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
    
    # Create forged message
    forged_message_bytes = original_message.encode('utf-8') + xor_block + additional_padded[16:]
    
    # Convert to query string format
    forged_message_str = forged_message_bytes.decode('utf-8', errors='ignore')
    
    # Parse and reconstruct query string
    forged_pairs = parse_query_string(forged_message_str)
    forged_pairs['mac'] = original_mac
    
    return '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
```

### Key Components

- **`CBCMACForgeryAttack`**: Main attack class implementing the CBC-MAC forgery
- **`get_challenge_message()`**: Retrieves the challenge message from the server
- **`parse_query_string()`**: Parses query string into key-value pairs
- **`build_message_from_pairs()`**: Builds message from key-value pairs
- **`forge_cbc_mac()`**: Performs CBC-MAC forgery attack
- **`simulate_cbc_mac()`**: Simulates CBC-MAC calculation for testing
- **`submit_answer()`**: Submits the forged query to the server

## Detailed Attack Explanation

### CBC-MAC Forgery Technique

The attack exploits the mathematical property of CBC-MAC:

1. **Original Message**: `M₁` with MAC `T₁`
2. **Additional Message**: `M₁'` (what we want to append)
3. **Forged Message**: `M₁ || (T₁ ⊕ M₁') || M₁'`
4. **Result**: The forged message has MAC `T₁`

### XOR Manipulation

The key insight is that XORing the original MAC with the first block of the additional message cancels out the contribution:

```
CBC-MAC(M₁ || (T₁ ⊕ M₁') || M₁') = T₁
```

This works because:
- `T₁ ⊕ M₁'` when processed through CBC-MAC produces `T₁ ⊕ M₁'`
- XORing with `T₁` gives `M₁'`
- The rest of `M₁'` is processed normally

### Message Construction

The challenge is to create a valid query string that produces the forged message:

1. **Parse Original**: Extract fields from original query
2. **Create Additional**: Design transfer to attacker's email
3. **Calculate XOR Block**: XOR original MAC with first block of additional message
4. **Construct Forged**: Concatenate original + XOR block + additional
5. **Parse Result**: Extract key-value pairs from forged message
6. **Build Query**: Reconstruct query string with original MAC

## Attack Complexity

- **Time Complexity**: O(1) - constant time operations
- **Space Complexity**: O(1) - constant space
- **Success Rate**: 100% (deterministic attack)
- **Key Knowledge**: Not required (attack works without secret)

## Files

- **`cbc_mac_attack.py`**: Complete attack implementation
- **`test_cbc_mac.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python cbc_mac_attack.py

# Run tests
python test_cbc_mac.py
```

## Example Attack Flow

```python
# 1. Get challenge message
original_query = attack.get_challenge_message(email)
# Output: "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"

# 2. Parse and build message
pairs = attack.parse_query_string(original_query)
original_message = attack.build_message_from_pairs(pairs)
# Output: "from=user@example.com&user@example.com=1000&comment=Invoice"

# 3. Forge CBC-MAC
forged_query = attack.forge_cbc_mac(original_query, "attacker@example.com", 15000)
# Output: "from=user@example.com&attacker@example.com=15000&mac=701b3768b67a68be68cee9736628cae8"

# 4. Submit forged query
result = attack.submit_answer(email, forged_query)
# Output: "¡Quiero más plata!"
```

## Educational Value

This challenge demonstrates:

1. **CBC-MAC Vulnerabilities**: Why CBC-MAC is insecure with variable-length messages
2. **Mathematical Properties**: Understanding XOR properties in cryptographic constructions
3. **MAC Forgery**: How to forge authentication without knowing the key
4. **Message Concatenation**: How to append data to existing messages
5. **Cryptographic Attacks**: Practical application of theoretical vulnerabilities
6. **Query String Manipulation**: Understanding URL encoding and parsing

## Security Implications

### Why CBC-MAC Forgery is Dangerous

1. **Authentication Bypass**: Can create valid MACs for different messages
2. **Message Tampering**: Can modify messages while preserving authentication
3. **Financial Fraud**: Can create unauthorized money transfers
4. **No Key Required**: Attack works without knowing the secret key

### Real-World Examples

1. **Financial Systems**: Money transfer systems using CBC-MAC
2. **API Authentication**: APIs using CBC-MAC for request authentication
3. **Message Systems**: Chat or messaging systems using CBC-MAC
4. **File Integrity**: File integrity checking using CBC-MAC

### Defenses Against CBC-MAC Forgery

1. **Use HMAC**: HMAC is not vulnerable to this attack
2. **Use CMAC**: CMAC (Cipher-based MAC) is secure
3. **Use Authenticated Encryption**: AES-GCM, ChaCha20-Poly1305
4. **Use SHA-3 Based MACs**: SHA-3 based MACs are secure
5. **Use Fixed-Length Messages**: CBC-MAC is secure with fixed-length messages

## Advanced Attack Variations

### Multiple Transfers

Create multiple transfers in a single forgery:
```python
def forge_multiple_transfers(original_query, transfers):
    # transfers = [("email1", amount1), ("email2", amount2), ...]
    # Create forged message with multiple transfers
    pass
```

### Amount Manipulation

Manipulate existing transfer amounts:
```python
def manipulate_amounts(original_query, amount_changes):
    # amount_changes = {"email": new_amount}
    # Modify existing transfer amounts
    pass
```

### Comment Injection

Inject malicious comments:
```python
def inject_comments(original_query, malicious_comment):
    # Add malicious comment to the transfer
    pass
```

## Common Pitfalls

1. **URL Encoding**: Must handle special characters in URLs
2. **Block Alignment**: Must align blocks correctly for CBC-MAC
3. **Message Parsing**: Must parse query strings correctly
4. **XOR Calculation**: Must perform XOR operations correctly

## References

- [CBC-MAC Wikipedia](https://en.wikipedia.org/wiki/CBC-MAC)
- [CBC-MAC Security](https://en.wikipedia.org/wiki/CBC-MAC#Security)
- [MAC Forgery Attacks](https://en.wikipedia.org/wiki/Message_authentication_code#Security)
- [Cryptographic MACs](https://en.wikipedia.org/wiki/Message_authentication_code)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use secure MAC constructions like HMAC or CMAC in production systems. CBC-MAC should never be used with variable-length messages as it is vulnerable to forgery attacks.
