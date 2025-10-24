# RSA Small Key Attack

## Overview

This challenge demonstrates a critical vulnerability in RSA when using small key sizes (256 bits). The attack exploits the fact that small moduli can be factorized efficiently, allowing complete recovery of the private key and decryption of any ciphertext.

## Challenge Description

The server implements RSA encryption with a small key size:
1. Provides RSA ciphertext encrypted with 256-bit modulus
2. Uses PKCS#1 v1.5 padding
3. Uses standard public exponent (e=65537)
4. Requires recovering the original plaintext

**RSA Encryption:**
```
c = m^e mod n
```

**Challenge Goal:**
Decrypt the ciphertext by factorizing the small modulus and recovering the private key.

## Vulnerability Analysis

### Small Key Size Vulnerability

RSA with small key sizes is vulnerable to factorization attacks:

1. **Small Modulus**: 256-bit modulus can be factorized efficiently
2. **Factorization**: Once n is factorized, private key can be calculated
3. **Complete Compromise**: Private key allows decryption of any ciphertext
4. **PKCS#1 v1.5**: Padding can be removed after decryption

### Mathematical Foundation

**RSA Key Generation:**
```
1. Choose two primes p, q
2. Calculate n = p * q
3. Calculate φ(n) = (p-1) * (q-1)
4. Choose e such that gcd(e, φ(n)) = 1
5. Calculate d such that e * d ≡ 1 (mod φ(n))
```

**Factorization Attack:**
```
1. Factorize n to find p, q
2. Calculate φ(n) = (p-1) * (q-1)
3. Calculate d = e^(-1) mod φ(n)
4. Decrypt: m = c^d mod n
```

### Attack Process

1. **Extract Modulus**: Get n from public key
2. **Factorize n**: Use factorization algorithms to find p, q
3. **Calculate Private Key**: Compute d from p, q, e
4. **Decrypt Ciphertext**: Use private key to decrypt
5. **Remove Padding**: Remove PKCS#1 v1.5 padding
6. **Submit Answer**: Send decrypted plaintext to server

## Technical Implementation

### Attack Strategy

1. **Data Collection**: Get ciphertext and public key from server
2. **Factorization**: Use multiple algorithms to factorize n
3. **Key Recovery**: Calculate private key from factors
4. **Decryption**: Decrypt ciphertext using private key
5. **Padding Removal**: Remove PKCS#1 v1.5 padding
6. **Submission**: Submit plaintext to server

### Attack Process

#### Step 1: Parse Challenge Data
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

#### Step 2: Factorize Modulus
```python
def factorize(self, n: int):
    # Try different factorization methods
    
    # 1. Trial division for small factors
    factor = self.trial_division(n)
    if factor:
        return factor, n // factor
    
    # 2. Pollard's rho algorithm
    factor = self.pollard_rho(n)
    if factor:
        return factor, n // factor
    
    # 3. Fermat's factorization
    factors = self.fermat_factorization(n)
    if factors:
        return factors
    
    # 4. Brute force for very small numbers
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return i, n // i
    
    raise ValueError(f"Could not factorize n = {n}")
```

#### Step 3: Trial Division
```python
def trial_division(self, n: int, limit: int = 1000000):
    # Test small primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
    
    for p in small_primes:
        if n % p == 0:
            return p
    
    # Test odd numbers up to limit
    for i in range(3, min(int(math.sqrt(n)) + 1, limit), 2):
        if n % i == 0:
            return i
    
    return None
```

#### Step 4: Pollard's Rho Algorithm
```python
def pollard_rho(self, n: int):
    if n % 2 == 0:
        return 2
    
    def f(x):
        return (x * x + 1) % n
    
    x = 2
    y = 2
    d = 1
    
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
    
    if d == n:
        return None
    return d
```

#### Step 5: Fermat's Factorization
```python
def fermat_factorization(self, n: int):
    a = int(math.ceil(math.sqrt(n)))
    b2 = a * a - n
    
    while b2 < 0 or int(math.sqrt(b2)) ** 2 != b2:
        a += 1
        b2 = a * a - n
        
        if a > n:
            return None
    
    b = int(math.sqrt(b2))
    p = a - b
    q = a + b
    
    if p * q == n and p > 1 and q > 1:
        return p, q
    
    return None
```

#### Step 6: Calculate Private Key
```python
def calculate_private_key(self, p: int, q: int, e: int):
    # Calculate Euler's totient function
    phi = (p - 1) * (q - 1)
    
    # Calculate private key d using extended Euclidean algorithm
    d = self.modular_inverse(e, phi)
    
    return d
```

#### Step 7: Decrypt and Remove Padding
```python
def decrypt_rsa(self, ciphertext: bytes, n: int, d: int):
    # Convert ciphertext to integer
    c = bytes_to_long(ciphertext)
    
    # Decrypt: m = c^d mod n
    m = pow(c, d, n)
    
    # Convert back to bytes
    plaintext_bytes = long_to_bytes(m)
    
    return plaintext_bytes

def remove_pkcs1_padding(self, padded_data: bytes):
    if len(padded_data) < 3:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    
    if padded_data[0] != 0x00:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    
    if padded_data[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    
    # Find separator byte (0x00)
    separator_index = None
    for i in range(2, len(padded_data)):
        if padded_data[i] == 0x00:
            separator_index = i
            break
    
    if separator_index is None:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    
    # Extract actual data
    actual_data = padded_data[separator_index + 1:]
    
    return actual_data
```

### Key Components

- **`RSASmallKeyAttack`**: Main attack class implementing the small key attack
- **`get_challenge_data()`**: Retrieves challenge data from the server
- **`parse_challenge_data()`**: Parses JSON response to extract ciphertext and public key
- **`factorize()`**: Orchestrates multiple factorization methods
- **`trial_division()`**: Implements trial division factorization
- **`pollard_rho()`**: Implements Pollard's rho algorithm
- **`fermat_factorization()`**: Implements Fermat's factorization method
- **`calculate_private_key()`**: Calculates private key from prime factors
- **`decrypt_rsa()`**: Decrypts ciphertext using private key
- **`remove_pkcs1_padding()`**: Removes PKCS#1 v1.5 padding
- **`submit_answer()`**: Submits the decrypted plaintext to the server

## Detailed Attack Explanation

### Factorization Methods

**Trial Division:**
- Test small primes and odd numbers up to √n
- Efficient for small factors
- Time complexity: O(√n)

**Pollard's Rho Algorithm:**
- Uses Floyd's cycle detection algorithm
- Finds factors by detecting cycles in a sequence
- Time complexity: O(√p) where p is the smallest factor

**Fermat's Factorization:**
- Exploits the difference of squares
- Effective when factors are close to √n
- Time complexity: O(√n)

### PKCS#1 v1.5 Padding

**Padding Structure:**
```
00 || 02 || PS || 00 || D
```

Where:
- `00`: First byte (always 0x00)
- `02`: Second byte (always 0x02)
- `PS`: Padding string (random non-zero bytes)
- `00`: Separator byte
- `D`: Actual data

**Removal Process:**
1. Verify first two bytes (0x00, 0x02)
2. Find separator byte (0x00)
3. Extract data after separator

### Attack Complexity

- **Time Complexity**: O(√n) for factorization
- **Space Complexity**: O(1) for most methods
- **Success Rate**: 100% for small moduli
- **Key Knowledge**: Not required (attack works with public key only)

## Files

- **`rsa_small_attack.py`**: Complete attack implementation
- **`test_rsa_small.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python rsa_small_attack.py

# Run tests
python test_rsa_small.py
```

## Example Attack Flow

```python
# 1. Get challenge data
data = attack.get_challenge_data(email)
# Output: {"ciphertext": "...", "publicKey": {"n": ..., "e": 65537}}

# 2. Parse data
ciphertext_bytes, n, e = attack.parse_challenge_data(data)
# Output: ciphertext bytes, modulus n, exponent e

# 3. Factorize modulus
p, q = attack.factorize(n)
# Output: prime factors p and q

# 4. Calculate private key
d = attack.calculate_private_key(p, q, e)
# Output: private key d

# 5. Decrypt ciphertext
padded_plaintext = attack.decrypt_rsa(ciphertext_bytes, n, d)
# Output: padded plaintext bytes

# 6. Remove padding
plaintext = attack.remove_pkcs1_padding(padded_plaintext)
# Output: "Hello, World!"

# 7. Submit answer
result = attack.submit_answer(email, plaintext)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **RSA Vulnerabilities**: Why small key sizes are dangerous
2. **Factorization Algorithms**: Multiple methods for integer factorization
3. **PKCS#1 v1.5 Padding**: Understanding and removing padding
4. **Private Key Recovery**: How to recover private keys from public information
5. **Mathematical Cryptanalysis**: Using number theory to break cryptography
6. **Key Size Importance**: Why larger key sizes are necessary

## Security Implications

### Why Small Keys are Dangerous

1. **Factorization Feasibility**: Small moduli can be factorized efficiently
2. **Complete Compromise**: Private key can be recovered
3. **Decryption Capability**: Can decrypt any ciphertext
4. **Signature Forgery**: Can forge signatures if used for signing

### Real-World Examples

1. **Early RSA Implementations**: Used small key sizes for performance
2. **Embedded Systems**: Limited computational power led to small keys
3. **Legacy Systems**: Old systems that haven't been updated
4. **Educational Examples**: Demonstrations using small keys

### Defenses Against Small Key Attacks

1. **Use Large Key Sizes**: Use at least 2048-bit keys (3072-bit recommended)
2. **Regular Key Updates**: Rotate keys regularly
3. **Key Size Validation**: Validate minimum key sizes
4. **Security Standards**: Follow industry standards for key sizes
5. **Performance vs Security**: Balance performance with security requirements

## Advanced Attack Variations

### Parallel Factorization

Use multiple processes for faster factorization:
```python
def parallel_factorization(self, n: int):
    # Use multiple processes to factorize
    # Distribute work across CPU cores
    pass
```

### Advanced Factorization Methods

Implement more sophisticated algorithms:
```python
def advanced_factorization(self, n: int):
    # Implement ECM, QS, or NFS
    # For larger numbers
    pass
```

### Automated Tool Integration

Integrate with existing factorization tools:
```python
def external_factorization(self, n: int):
    # Use tools like msieve, GMP-ECM, or CADO-NFS
    # For production-quality factorization
    pass
```

## Common Pitfalls

1. **Insufficient Factorization Methods**: May need multiple algorithms
2. **Padding Validation**: Must handle PKCS#1 v1.5 padding correctly
3. **Integer Overflow**: Must handle large integers correctly
4. **Error Handling**: Must handle factorization failures gracefully

## References

- [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Integer Factorization](https://en.wikipedia.org/wiki/Integer_factorization)
- [Pollard's Rho Algorithm](https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm)
- [Fermat's Factorization Method](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
- [PKCS#1 v1.5](https://tools.ietf.org/html/rfc2313)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use large key sizes (at least 2048 bits) for RSA in production systems. Small key sizes make RSA completely insecure and should never be used in real-world applications.
