# Applied Cryptography

This repository contains the results of the challenges of the cybersecurity diploma, specifically those corresponding to the applied cryptography module.

## Projects

### 1. Java Random Number Generator Prediction
**Location**: `JavaRandomNumberGenerator/`

Demonstrates the vulnerability in Java's `Random` class by predicting future outputs from just two consecutive values.

- **Algorithm**: Linear Congruential Generator (LCG) with 48-bit state
- **Vulnerability**: Only 16 bits of internal state are hidden (2^16 = 65,536 possibilities)
- **Attack**: Brute force search to recover the complete internal state
- **Impact**: Complete prediction of all future random numbers

**Key Files**:
- `java_predict_simple.py` - Simplified prediction algorithm
- `java_random_algorithm.md` - Detailed technical documentation

### 2. ADOdb Crypt Analysis
**Location**: `MD5crypt/`

Analyzes and breaks the ADOdb Crypt encryption algorithm using known plaintext attacks.

- **Algorithm**: Two-layer encryption with MD5 and XOR operations
- **Vulnerability**: Predictable internal keys (32,001 possible values) and known structure
- **Attack**: Known plaintext attack to recover encryption keys
- **Impact**: Complete decryption of encrypted messages

**Key Files**:
- `ADOdb_crypt.py` - Original encryption implementation
- `ADOdb_crypt_decode.py` - Decryption and attack implementation
- `md5crypt_algorithm.md` - Detailed technical documentation

### 3. Timerand Challenge - Time-Based Key Generation Attack
**Location**: `TimerandChallenge/`

Demonstrates the vulnerability in time-based key generation systems using MD5 and microsecond precision.

- **Algorithm**: Hybrid encryption (AES-128-CBC + RSA-1024) with time-based key generation
- **Vulnerability**: Predictable key generation from Unix timestamp with limited microsecond precision
- **Attack**: Brute force search through 1,000,000 possible microsecond offsets
- **Impact**: Complete decryption of time-encrypted messages

**Key Files**:
- `timerand_solver.py` - Complete attack implementation with brute force search
- `README.md` - Detailed technical documentation

### 4. ECB Forgery Attack
**Location**: `ecb_false/`

Demonstrates the vulnerability of AES encryption in ECB (Electronic Codebook) mode due to its malleability.

- **Algorithm**: AES-128-ECB with PKCS7 padding
- **Vulnerability**: Block independence allows manipulation and message forgery
- **Attack**: Block substitution to forge messages with admin privileges
- **Impact**: Complete message forgery and privilege escalation

**Key Files**:
- `ecb_forge_attack.py` - Complete ECB forgery attack implementation
- `test_ecb_forge.py` - Test cases and validation
- `README.md` - Detailed technical documentation

### 5. ECB Byte-by-Byte Decryption Attack
**Location**: `ecb_decrypt/`

Demonstrates a fundamental vulnerability in AES-ECB mode using oracle attacks to recover secret messages.

- **Algorithm**: AES-128-ECB with PKCS7 padding and oracle access
- **Vulnerability**: Deterministic encryption enables byte-by-byte recovery
- **Attack**: Oracle-based exhaustive search to decrypt secret messages
- **Impact**: Complete secret message recovery without knowing the encryption key

**Key Files**:
- `ecb_decrypt_attack.py` - Complete ECB decryption attack implementation
- `test_ecb_decrypt.py` - Comprehensive test suite with oracle simulation
- `README.md` - Detailed technical documentation

### 6. CBC Bit Flipping Attack
**Location**: `cbc_bitflip/`

Demonstrates the malleability vulnerability in AES-CBC mode using bit flipping attacks to modify encrypted messages.

- **Algorithm**: AES-128-CBC with PKCS7 padding and IV
- **Vulnerability**: Ciphertext malleability allows predictable plaintext modification
- **Attack**: Bit flipping to change 'role=user' to 'role=admin' in encrypted profiles
- **Impact**: Privilege escalation through encrypted message manipulation

**Key Files**:
- `cbc_bitflip_attack.py` - Complete CBC bit flipping attack implementation
- `test_cbc_bitflip.py` - Comprehensive test suite with oracle simulation
- `README.md` - Detailed technical documentation

### 7. Stream Cipher Keystream Recovery Attack
**Location**: `stream_cipher/`

Demonstrates a fundamental vulnerability in stream ciphers that reuse the same keystream for multiple messages.

- **Algorithm**: Stream cipher with reused keystream
- **Vulnerability**: Keystream reuse enables message recovery through statistical analysis
- **Attack**: XOR-based keystream recovery from repeated character messages
- **Impact**: Complete message decryption without knowing the encryption key

**Key Files**:
- `stream_cipher_attack.py` - Complete keystream recovery attack implementation
- `test_stream_cipher.py` - Comprehensive test suite with oracle simulation
- `README.md` - Detailed technical documentation

### 8. Stream Cipher Bit Flipping Attack
**Location**: `stream_bitflip/`

Demonstrates the malleability vulnerability in stream ciphers using bit flipping attacks to modify encrypted messages.

- **Algorithm**: Stream cipher with nonce and profile encryption
- **Vulnerability**: Direct bit manipulation allows predictable plaintext modification
- **Attack**: Bit flipping to change 'role=user' to 'role=admin' in encrypted profiles
- **Impact**: Privilege escalation through encrypted message manipulation

**Key Files**:
- `stream_bitflip_attack.py` - Complete stream cipher bit flipping attack implementation
- `test_stream_bitflip.py` - Comprehensive test suite with oracle simulation
- `README.md` - Detailed technical documentation

### 9. Padding Oracle Attack
**Location**: `padding_oracle/`

Demonstrates a fundamental vulnerability in AES-CBC mode when the server reveals information about padding validity.

- **Algorithm**: AES-128-CBC with PKCS7 padding and padding oracle
- **Vulnerability**: Padding validation information leakage enables byte-by-byte decryption
- **Attack**: Padding oracle to decrypt messages without knowing the encryption key
- **Impact**: Complete message decryption through padding manipulation

**Key Files**:
- `padding_oracle_attack.py` - Complete padding oracle attack implementation
- `test_padding_oracle.py` - Comprehensive test suite with oracle simulation
- `README.md` - Detailed technical documentation

### 10. Second Preimage Attack
**Location**: `second_preimage/`

Demonstrates a fundamental vulnerability in truncated hash functions by finding a second preimage.

- **Algorithm**: SHA-256-24 (truncated SHA-256 to 24 bits)
- **Vulnerability**: Reduced output space makes brute force attacks feasible
- **Attack**: Brute force search to find different messages with same hash
- **Impact**: Hash collision and message forgery capabilities

**Key Files**:
- `second_preimage_attack.py` - Complete second preimage attack implementation
- `test_second_preimage.py` - Comprehensive test suite with collision simulation
- `README.md` - Detailed technical documentation

### 11. Hash Collision Attack
**Location**: `hash_collision/`

Demonstrates the vulnerability of truncated hash functions by finding two different messages that produce the same hash.

- **Algorithm**: SHA-256-48 (truncated SHA-256 to 48 bits)
- **Vulnerability**: Birthday paradox makes collisions likely with reduced hash space
- **Attack**: Brute force and birthday attack to find hash collisions
- **Impact**: Hash collision and message forgery capabilities

**Key Files**:
- `hash_collision_attack.py` - Complete hash collision attack implementation
- `test_hash_collision.py` - Comprehensive test suite with collision simulation
- `README.md` - Detailed technical documentation

### 12. Length Extension Attack
**Location**: `length_extension/`

Demonstrates a fundamental vulnerability in Merkle-Damgård hash functions when used with secret-prefix MACs.

- **Algorithm**: SHA-256 with secret-prefix MAC construction
- **Vulnerability**: Merkle-Damgård construction allows message extension without knowing the secret
- **Attack**: Length extension to forge MACs and bypass authentication
- **Impact**: MAC forgery and authentication bypass without knowing the secret key

**Key Files**:
- `length_extension_attack.py` - Complete length extension attack implementation
- `test_length_extension.py` - Comprehensive test suite with MAC forgery simulation
- `README.md` - Detailed technical documentation

### 13. CBC-MAC Forgery Attack
**Location**: `cbc_mac/`

Demonstrates a fundamental vulnerability in CBC-MAC when used with variable-length messages.

- **Algorithm**: CBC-MAC with variable-length message authentication
- **Vulnerability**: Mathematical property allows MAC forgery through message concatenation
- **Attack**: XOR manipulation to forge MACs and create unauthorized transfers
- **Impact**: MAC forgery and financial fraud without knowing the secret key

**Key Files**:
- `cbc_mac_attack.py` - Complete CBC-MAC forgery attack implementation
- `test_cbc_mac.py` - Comprehensive test suite with MAC forgery simulation
- `README.md` - Detailed technical documentation

### 14. RSA Broadcast Attack
**Location**: `rsa_broadcast/`

Demonstrates a fundamental vulnerability in RSA when the same message is encrypted with multiple public keys using small exponent.

- **Algorithm**: RSA with small exponent (e=3) and textbook encryption
- **Vulnerability**: Chinese Remainder Theorem allows plaintext recovery from multiple ciphertexts
- **Attack**: Mathematical cryptanalysis using CRT and cube root calculation
- **Impact**: Plaintext recovery without knowing any private keys

**Key Files**:
- `rsa_broadcast_attack.py` - Complete RSA broadcast attack implementation
- `test_rsa_broadcast.py` - Comprehensive test suite with CRT simulation
- `README.md` - Detailed technical documentation

### 15. DSA k-Reuse Attack
**Location**: `dsa_k_reuse/`

Demonstrates a critical vulnerability in DSA when the same random value k is reused for multiple signatures.

- **Algorithm**: DSA with SHA-256 hash function and flawed random number generation
- **Vulnerability**: k-reuse allows complete private key recovery through mathematical analysis
- **Attack**: Signature analysis and mathematical recovery of private key
- **Impact**: Complete compromise of DSA private key and signature forgery capability

**Key Files**:
- `dsa_k_reuse_attack.py` - Complete DSA k-reuse attack implementation
- `test_dsa_k_reuse.py` - Comprehensive test suite with signature analysis
- `README.md` - Detailed technical documentation

### 16. RSA Small Key Attack
**Location**: `rsa_small/`

Demonstrates a critical vulnerability in RSA when using small key sizes (256 bits).

- **Algorithm**: RSA with 256-bit modulus and PKCS#1 v1.5 padding
- **Vulnerability**: Small modulus can be factorized efficiently using multiple algorithms
- **Attack**: Factorization attack using trial division, Pollard's rho, and Fermat's method
- **Impact**: Complete private key recovery and decryption of any ciphertext

**Key Files**:
- `rsa_small_attack.py` - Complete RSA small key attack implementation
- `test_rsa_small.py` - Comprehensive test suite with factorization algorithms
- `README.md` - Detailed technical documentation

## Educational Purpose

These implementations demonstrate:
- Why weak random number generators are dangerous
- How to analyze and break weak encryption algorithms
- The importance of using cryptographically secure primitives
- Practical application of cryptanalysis techniques
- Vulnerabilities in time-based key generation systems
- The dangers of insufficient entropy in cryptographic keys
- ECB mode vulnerabilities and message forgery attacks
- Block cipher malleability and its security implications
- Oracle attacks and deterministic encryption vulnerabilities
- Byte-by-byte decryption techniques and their practical applications
- CBC mode malleability and bit flipping attack vectors
- Ciphertext manipulation and privilege escalation techniques
- Stream cipher vulnerabilities and keystream reuse attacks
- Stream cipher malleability and bit manipulation techniques
- Padding oracle vulnerabilities and information leakage attacks
- Truncated hash function vulnerabilities and collision attacks
- Second preimage attacks and hash function weaknesses
- Birthday paradox and collision probability in hash functions
- Brute force attacks and computational feasibility
- Parallel processing and attack optimization techniques
- Merkle-Damgård construction vulnerabilities and length extension attacks
- Secret-prefix MAC weaknesses and authentication bypass techniques
- Hash function intermediate state exploitation
- CBC-MAC vulnerabilities and MAC forgery techniques
- Mathematical properties of cryptographic constructions
- Financial system vulnerabilities and fraud prevention
- RSA vulnerabilities and small exponent attacks
- Chinese Remainder Theorem applications in cryptanalysis
- Public key cryptography weaknesses and mathematical attacks
- DSA vulnerabilities and k-reuse attacks
- Digital signature security and random number generation
- Signature analysis and private key recovery techniques
- RSA key size vulnerabilities and factorization attacks
- Integer factorization algorithms and computational complexity
- PKCS#1 v1.5 padding and its security implications

**Warning**: These are educational examples. Always use established cryptographic libraries for production systems.
