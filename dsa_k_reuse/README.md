# DSA k-Reuse Attack

## Overview

This challenge demonstrates a critical vulnerability in DSA (Digital Signature Algorithm) when the same random value k is reused for multiple signatures. The attack exploits this weakness to recover the private key without knowing any of the individual k values.

## Challenge Description

The server implements DSA signature generation with a flawed random number generator:
1. Provides DSA signatures for user-chosen messages
2. Uses SHA-256 as the hash function
3. Has a defective random number generator that often reuses k values
4. Requires recovering the private key x

**DSA Signature Process:**
```
1. Choose random k
2. Calculate r = (g^k mod p) mod q
3. Calculate s = k^(-1) * (h + x*r) mod q
4. Signature is (r, s)
```

**Challenge Goal:**
Recover the private key x by exploiting k reuse in multiple signatures.

## Vulnerability Analysis

### k-Reuse Vulnerability

DSA is completely compromised when the same k value is reused:

1. **Same k Value**: Multiple signatures use the same random k
2. **Same r Value**: Identical r values indicate k reuse
3. **Different s Values**: Different messages produce different s values
4. **Mathematical Exploitation**: Can solve for k and then x

### Mathematical Foundation

**DSA Signature Equations:**
For two messages m₁ and m₂ signed with the same k:
```
r₁ = r₂ = (g^k mod p) mod q
s₁ = k^(-1) * (h₁ + x*r) mod q
s₂ = k^(-1) * (h₂ + x*r) mod q
```

**k Recovery:**
From the two equations:
```
s₁ = k^(-1) * (h₁ + x*r) mod q
s₂ = k^(-1) * (h₂ + x*r) mod q
```

Subtracting:
```
s₁ - s₂ = k^(-1) * (h₁ - h₂) mod q
k = (h₁ - h₂) * (s₁ - s₂)^(-1) mod q
```

**Private Key Recovery:**
Once k is known:
```
s = k^(-1) * (h + x*r) mod q
x = (s*k - h) * r^(-1) mod q
```

### Attack Process

1. **Collect Signatures**: Get multiple signatures from the server
2. **Find k Reuse**: Look for identical r values
3. **Recover k**: Use mathematical formula to calculate k
4. **Recover Private Key**: Use k to calculate private key x
5. **Submit Answer**: Send recovered private key to server

## Technical Implementation

### Attack Strategy

1. **Data Collection**: Collect multiple signatures from server
2. **k Reuse Detection**: Find signatures with identical r values
3. **Mathematical Recovery**: Use DSA equations to recover k and x
4. **Verification**: Verify recovered values
5. **Submission**: Submit private key to server

### Attack Process

#### Step 1: Collect Signatures
```python
def collect_signatures(self, email: str, messages: List[str], count: int = 10):
    signatures = []
    
    for i in range(count):
        message = messages[i] if i < len(messages) else f"message_{i}"
        signature = self.sign_message(email, message)
        signatures.append(signature)
    
    return signatures
```

#### Step 2: Find k Reuse
```python
def find_k_reuse(self, signatures: List[Dict[str, int]]):
    r_values = {}
    reuse_indices = []
    
    for i, sig in enumerate(signatures):
        r = sig['r']
        if r in r_values:
            reuse_indices.extend([r_values[r], i])
        else:
            r_values[r] = i
    
    return list(set(reuse_indices))
```

#### Step 3: Recover k
```python
def recover_k(self, message1: bytes, message2: bytes, s1: int, s2: int, q: int):
    # Calculate hashes
    h1 = self.sha256_hash(message1)
    h2 = self.sha256_hash(message2)
    
    # Calculate k using the formula:
    # k = (h1 - h2) * (s1 - s2)^(-1) mod q
    numerator = (h1 - h2) % q
    denominator = (s1 - s2) % q
    
    # Calculate modular inverse of denominator
    denominator_inv = self.modular_inverse(denominator, q)
    
    # Calculate k
    k = (numerator * denominator_inv) % q
    
    return k
```

#### Step 4: Recover Private Key
```python
def recover_private_key(self, message: bytes, r: int, s: int, k: int, q: int):
    # Calculate hash
    h = self.sha256_hash(message)
    
    # Calculate private key using the formula:
    # x = (s * k - h) * r^(-1) mod q
    numerator = (s * k - h) % q
    r_inv = self.modular_inverse(r, q)
    
    # Calculate private key
    x = (numerator * r_inv) % q
    
    return x
```

#### Step 5: Modular Inverse
```python
def modular_inverse(self, a: int, m: int):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for {a} mod {m}")
    
    return x % m
```

### Key Components

- **`DSAKReuseAttack`**: Main attack class implementing the k-reuse attack
- **`get_public_key()`**: Retrieves DSA public key from the server
- **`sign_message()`**: Signs a message using DSA
- **`find_k_reuse()`**: Finds signatures that reuse the same k value
- **`recover_k()`**: Recovers k from two signatures with same k
- **`recover_private_key()`**: Recovers private key x using k
- **`modular_inverse()`**: Calculates modular inverse using extended Euclidean algorithm
- **`submit_answer()`**: Submits the recovered private key to the server

## Detailed Attack Explanation

### DSA Signature Process

DSA signature generation involves:
1. **Random k**: Choose a random value k (should be unique for each signature)
2. **Calculate r**: r = (g^k mod p) mod q
3. **Calculate s**: s = k^(-1) * (h + x*r) mod q
4. **Signature**: The pair (r, s)

### k-Reuse Detection

When the same k is used for multiple signatures:
- **Same r**: r values will be identical
- **Different s**: s values will be different due to different message hashes
- **Pattern**: Look for identical r values in signature collection

### Mathematical Recovery

**k Recovery Formula:**
```
k = (h₁ - h₂) * (s₁ - s₂)^(-1) mod q
```

**Private Key Recovery Formula:**
```
x = (s*k - h) * r^(-1) mod q
```

### Attack Complexity

- **Time Complexity**: O(n) where n is the number of signatures
- **Space Complexity**: O(n) for storing signatures
- **Success Rate**: 100% when k reuse is found
- **Key Knowledge**: Not required (attack works without knowing k values)

## Files

- **`dsa_k_reuse_attack.py`**: Complete attack implementation
- **`test_dsa_k_reuse.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python dsa_k_reuse_attack.py

# Run tests
python test_dsa_k_reuse.py
```

## Example Attack Flow

```python
# 1. Get public key
public_key = attack.get_public_key(email)
# Output: {"P": ..., "Q": ..., "G": ..., "Y": ...}

# 2. Collect signatures
signatures = attack.collect_signatures(email, messages, 20)
# Output: List of signatures with r and s values

# 3. Find k reuse
reuse_indices = attack.find_k_reuse(signatures)
# Output: [0, 5] (indices where r values are identical)

# 4. Recover k
k = attack.recover_k(msg1, msg2, s1, s2, q)
# Output: 123456789 (recovered k value)

# 5. Recover private key
private_key = attack.recover_private_key(msg1, r1, s1, k, q)
# Output: 987654321 (recovered private key x)

# 6. Submit answer
result = attack.submit_answer(email, private_key)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **DSA Vulnerabilities**: Why k reuse is catastrophic for DSA
2. **Random Number Generation**: Importance of cryptographically secure randomness
3. **Mathematical Cryptanalysis**: Using number theory to break signatures
4. **Signature Analysis**: How to detect and exploit signature weaknesses
5. **Private Key Recovery**: How to recover private keys from public information
6. **Digital Signature Security**: Understanding DSA implementation requirements

## Security Implications

### Why k-Reuse is Dangerous

1. **Complete Compromise**: Private key can be recovered
2. **Signature Forgery**: Can forge signatures for any message
3. **Identity Theft**: Can impersonate the signer
4. **No Detection**: Attack is undetectable without signature analysis

### Real-World Examples

1. **Sony PlayStation 3**: Used same k for all signatures
2. **Bitcoin Wallets**: Some implementations had k reuse vulnerabilities
3. **Smart Cards**: Hardware random number generator failures
4. **Embedded Systems**: Insufficient entropy in random number generation

### Defenses Against k-Reuse Attacks

1. **Cryptographically Secure Random**: Use proper random number generators
2. **k Uniqueness**: Ensure each k is unique and unpredictable
3. **Entropy Sources**: Use multiple entropy sources for randomness
4. **Hardware Security**: Use hardware random number generators
5. **Signature Analysis**: Monitor signatures for k reuse patterns

## Advanced Attack Variations

### Multiple k Reuse

Handle cases with multiple k reuse patterns:
```python
def find_all_k_reuse(self, signatures):
    # Find all patterns of k reuse
    # Handle multiple groups of reused k values
    pass
```

### Statistical Analysis

Use statistical methods to detect k reuse:
```python
def statistical_k_detection(self, signatures):
    # Use statistical analysis to detect k reuse
    # Even when r values are not identical
    pass
```

### Fault Injection

Exploit fault injection to cause k reuse:
```python
def fault_injection_attack(self, target_system):
    # Inject faults to cause k reuse
    # Exploit hardware vulnerabilities
    pass
```

## Common Pitfalls

1. **Insufficient Signatures**: May need many signatures to find k reuse
2. **Modular Arithmetic**: Must handle modular arithmetic correctly
3. **Hash Calculation**: Must use the same hash function as the server
4. **Base64 Encoding**: Must handle message encoding correctly

## References

- [DSA Wikipedia](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
- [DSA Security](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Security)
- [k-Reuse Attack](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#k-reuse_attack)
- [Sony PlayStation 3 Attack](https://www.zdnet.com/article/sony-playstation-3-hacked-due-to-epic-cryptographic-fail/)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use cryptographically secure random number generators for DSA k values in production systems. k reuse completely compromises DSA security and should never occur in properly implemented systems.
