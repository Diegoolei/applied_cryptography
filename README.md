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

## Educational Purpose

These implementations demonstrate:
- Why weak random number generators are dangerous
- How to analyze and break weak encryption algorithms
- The importance of using cryptographically secure primitives
- Practical application of cryptanalysis techniques

**Warning**: These are educational examples. Always use established cryptographic libraries for production systems.
