# RSA Broadcast Attack

## Overview

This challenge demonstrates a fundamental vulnerability in RSA when the same message is encrypted with multiple public keys using small exponent (e=3). The attack exploits the Chinese Remainder Theorem to recover the plaintext without knowing any private keys.

## Challenge Description

The server implements RSA encryption with small exponent:
1. Provides multiple ciphertexts of the same message encrypted with different public keys
2. Uses RSA with exponent e=3 (small exponent)
3. Uses textbook RSA (no padding)
4. Requires recovering the original plaintext

**RSA Encryption:**
```
c = m^e mod n
```

**Challenge Goal:**
Recover the plaintext message from multiple ciphertexts encrypted with different public keys.

## Vulnerability Analysis

### Small Exponent Vulnerability

RSA with small exponent (e=3) is vulnerable to broadcast attacks:

1. **Same Message**: Multiple encryptions of the same message
2. **Small Exponent**: Exponent e=3 makes the attack feasible
3. **No Padding**: Textbook RSA without padding
4. **Chinese Remainder Theorem**: Mathematical tool for the attack

### Mathematical Foundation

**Chinese Remainder Theorem:**
If we have a system of congruences:
```
x ≡ a₁ (mod n₁)
x ≡ a₂ (mod n₂)
x ≡ a₃ (mod n₃)
```

Where n₁, n₂, n₃ are pairwise coprime, then there exists a unique solution x modulo n₁n₂n₃.

**Application to RSA:**
If the same message m is encrypted with three different public keys (n₁,3), (n₂,3), (n₃,3):
```
c₁ ≡ m³ (mod n₁)
c₂ ≡ m³ (mod n₂)
c₃ ≡ m³ (mod n₃)
```

We can use CRT to find m³, then take the cube root to get m.

### Attack Process

1. **Collect Ciphertexts**: Get multiple ciphertexts of the same message
2. **Extract Moduli**: Extract the RSA moduli from public keys
3. **Apply CRT**: Use Chinese Remainder Theorem to find m³
4. **Calculate Cube Root**: Take cube root to recover m
5. **Convert to Text**: Convert integer back to plaintext

## Technical Implementation

### Attack Strategy

1. **Data Collection**: Collect multiple ciphertexts from server
2. **Parsing**: Parse JSON responses to extract ciphertexts and moduli
3. **Chinese Remainder Theorem**: Solve system of congruences
4. **Cube Root**: Calculate integer cube root
5. **Text Recovery**: Convert recovered integer to plaintext

### Attack Process

#### Step 1: Collect Ciphertexts
```python
def collect_ciphertexts(self, email: str, count: int = 3):
    ciphertexts = []
    moduli = []
    
    for i in range(count):
        data = self.get_challenge_data(email)
        ciphertext_bytes, n, e = self.parse_challenge_data(data)
        
        ciphertexts.append(ciphertext_bytes)
        moduli.append(n)
    
    return ciphertexts, moduli
```

#### Step 2: Parse Challenge Data
```python
def parse_challenge_data(self, data: dict):
    # Decode base64 ciphertext
    ciphertext_b64 = data['ciphertext']
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    
    # Extract public key components
    public_key = data['publicKey']
    n = public_key['n']
    e = public_key['e']
    
    return ciphertext_bytes, n, e
```

#### Step 3: Chinese Remainder Theorem
```python
def chinese_remainder_theorem(self, remainders: List[int], moduli: List[int]):
    # Calculate product of all moduli
    N = 1
    for modulus in moduli:
        N *= modulus
    
    # Calculate solution using CRT formula
    result = 0
    for i in range(len(remainders)):
        # Calculate Ni = N / ni
        Ni = N // moduli[i]
        
        # Calculate Mi = Ni^(-1) mod ni
        Mi = self.modular_inverse(Ni, moduli[i])
        
        # Add to result
        result += remainders[i] * Ni * Mi
    
    return result % N
```

#### Step 4: Modular Inverse
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

#### Step 5: Cube Root Calculation
```python
def cube_root(self, n: int):
    # Use Newton's method for cube root
    x = n
    for _ in range(100):  # Precision iterations
        x = (2 * x + n // (x * x)) // 3
    
    return x
```

#### Step 6: Perform Broadcast Attack
```python
def perform_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Convert ciphertexts to integers
    ciphertext_ints = []
    for ciphertext in ciphertexts:
        ciphertext_int = bytes_to_long(ciphertext)
        ciphertext_ints.append(ciphertext_int)
    
    # Apply Chinese Remainder Theorem
    m_cubed = self.chinese_remainder_theorem(ciphertext_ints, moduli)
    
    # Calculate cube root to get m
    m = self.cube_root(m_cubed)
    
    # Convert back to bytes and then to string
    plaintext_bytes = long_to_bytes(m)
    plaintext = plaintext_bytes.decode('utf-8')
    
    return plaintext
```

### Key Components

- **`RSABroadcastAttack`**: Main attack class implementing the broadcast attack
- **`get_challenge_data()`**: Retrieves challenge data from the server
- **`parse_challenge_data()`**: Parses JSON response to extract ciphertext and public key
- **`chinese_remainder_theorem()`**: Implements CRT to solve system of congruences
- **`modular_inverse()`**: Calculates modular inverse using extended Euclidean algorithm
- **`cube_root()`**: Calculates integer cube root using Newton's method
- **`perform_broadcast_attack()`**: Orchestrates the complete attack
- **`submit_answer()`**: Submits the recovered plaintext to the server

## Detailed Attack Explanation

### Chinese Remainder Theorem

The Chinese Remainder Theorem states that if we have a system of congruences:
```
x ≡ a₁ (mod n₁)
x ≡ a₂ (mod n₂)
x ≡ a₃ (mod n₃)
```

Where n₁, n₂, n₃ are pairwise coprime, then there exists a unique solution x modulo n₁n₂n₃.

**Solution Formula:**
```
x = Σ(aᵢ × Nᵢ × Mᵢ) mod N
```

Where:
- N = n₁ × n₂ × n₃
- Nᵢ = N / nᵢ
- Mᵢ = Nᵢ^(-1) mod nᵢ

### RSA Broadcast Attack

When the same message m is encrypted with three different public keys (n₁,3), (n₂,3), (n₃,3):
```
c₁ ≡ m³ (mod n₁)
c₂ ≡ m³ (mod n₂)
c₃ ≡ m³ (mod n₃)
```

We can use CRT to find m³, then take the cube root to get m.

**Why This Works:**
1. **Small Exponent**: e=3 makes m³ manageable
2. **No Padding**: Textbook RSA without padding
3. **Same Message**: Multiple encryptions of the same message
4. **Pairwise Coprime**: RSA moduli are typically pairwise coprime

### Cube Root Calculation

Since we need to find m from m³, we need to calculate the cube root:
```
m = ∛(m³)
```

For large integers, we use Newton's method:
```
x_{n+1} = (2x_n + m³/x_n²) / 3
```

## Attack Complexity

- **Time Complexity**: O(k³) where k is the number of ciphertexts
- **Space Complexity**: O(k) for storing ciphertexts and moduli
- **Success Rate**: 100% (deterministic attack)
- **Key Knowledge**: Not required (attack works without private keys)

## Files

- **`rsa_broadcast_attack.py`**: Complete attack implementation
- **`test_rsa_broadcast.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python rsa_broadcast_attack.py

# Run tests
python test_rsa_broadcast.py
```

## Example Attack Flow

```python
# 1. Collect ciphertexts
ciphertexts, moduli = attack.collect_ciphertexts(email, 3)
# Output: 3 ciphertexts and 3 moduli

# 2. Perform broadcast attack
plaintext = attack.perform_broadcast_attack(ciphertexts, moduli)
# Output: "Professional wrestling: ballet for the common man."

# 3. Submit answer
result = attack.submit_answer(email, plaintext)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **RSA Vulnerabilities**: Why small exponents are dangerous
2. **Chinese Remainder Theorem**: Mathematical tool for solving congruences
3. **Broadcast Attacks**: How to exploit multiple encryptions
4. **Textbook RSA Weaknesses**: Why padding is essential
5. **Mathematical Cryptanalysis**: Using number theory to break cryptography
6. **Integer Arithmetic**: Working with large integers in Python

## Security Implications

### Why Broadcast Attacks are Dangerous

1. **No Private Key Required**: Attack works without knowing any private keys
2. **Deterministic**: Always succeeds with sufficient ciphertexts
3. **Efficient**: Polynomial time complexity
4. **Practical**: Can be implemented easily

### Real-World Examples

1. **Small Exponent RSA**: Systems using e=3 for efficiency
2. **Textbook RSA**: Systems without proper padding
3. **Broadcast Systems**: Systems that encrypt the same message multiple times
4. **Legacy Systems**: Old systems that haven't been updated

### Defenses Against Broadcast Attacks

1. **Use Larger Exponents**: Use e=65537 instead of e=3
2. **Use Proper Padding**: Use OAEP or PKCS#1 v1.5 padding
3. **Use Random Padding**: Add random data to each encryption
4. **Use Different Messages**: Never encrypt the same message multiple times
5. **Use Hybrid Encryption**: Use RSA only for key exchange

## Advanced Attack Variations

### Multiple Ciphertexts

The attack can be extended to use more than 3 ciphertexts:
```python
def extended_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Use more ciphertexts for better accuracy
    # Especially useful for non-perfect cube roots
    pass
```

### Different Exponents

The attack can be adapted for different small exponents:
```python
def generalized_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int], exponent: int):
    # Generalize for any small exponent
    # Use nth root instead of cube root
    pass
```

### Error Handling

Robust error handling for real-world scenarios:
```python
def robust_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]):
    # Handle non-perfect roots
    # Handle decoding errors
    # Handle invalid ciphertexts
    pass
```

## Common Pitfalls

1. **Non-Perfect Cube Roots**: May need to handle non-perfect cubes
2. **Decoding Errors**: May need to handle invalid UTF-8 sequences
3. **Modulus Validation**: Ensure moduli are pairwise coprime
4. **Precision Issues**: May need higher precision for cube root calculation

## References

- [RSA Broadcast Attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack#H%C3%A5stad%27s_broadcast_attack)
- [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
- [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Small Exponent Attack](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Small_private_exponent)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use proper padding (OAEP or PKCS#1 v1.5) and larger exponents (e=65537) in production RSA systems. Textbook RSA should never be used as it is vulnerable to multiple attacks including broadcast attacks.
