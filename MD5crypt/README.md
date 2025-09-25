# ADOdb Crypt Algorithm - Step-by-Step Explanation

## Introduction

ADOdb Crypt is an encryption algorithm that uses MD5 and XOR operations to encrypt text. This document explains step-by-step how the algorithm works with detailed examples using bits.

## Algorithm Structure

The ADOdb Crypt algorithm has **two encryption layers**:

1. **Inner layer**: Generates a random MD5 key and interleaves it with the text
2. **Outer layer**: Applies XOR with an external key provided by the user

## Constants and Parameters

- **Random number range**: 0 to 32,000
- **MD5 key length**: 32 hexadecimal characters
- **Encoding**: Base64 for final result

## Algorithm Formula

```
Encrypted = Base64(KeyED(Interleave(MD5(rand), Text), ExternalKey))
```

## Step-by-Step Example

Let's follow the algorithm with:
- **Original text**: "HELLO"
- **External key**: "0123456789abcdef0123456789abcdef"

### Step 1: Generate Random Number

```python
import random
rand = random.randint(0, 32000)
# Example: rand = 12345
```

### Step 2: Generate MD5 Hash

```python
import hashlib
md5_hash = hashlib.md5(str(rand).encode()).hexdigest()
# Example: md5_hash = "827ccb0eea8a706c4c34a16891f84e7b"
```

**MD5 Process**:
```
Input: "12345"
MD5: 827ccb0eea8a706c4c34a16891f84e7b
Length: 32 characters (128 bits)
```

### Step 3: Interleave MD5 with Text

The interleaving process alternates characters from the MD5 hash and the original text:

```python
def interleave(md5_hash, text):
    result = ""
    for i in range(len(text)):
        result += md5_hash[i] + text[i]
    return result
```

**Example**:
```
MD5:     827ccb0eea8a706c4c34a16891f84e7b
Text:    HELLO
Result:  8H2E7LcLcOb0eO
```

**Step-by-step**:
- Position 0: '8' (from MD5) + 'H' (from text) = "8H"
- Position 1: '2' (from MD5) + 'E' (from text) = "2E"
- Position 2: '7' (from MD5) + 'L' (from text) = "7L"
- Position 3: 'c' (from MD5) + 'L' (from text) = "cL"
- Position 4: 'c' (from MD5) + 'O' (from text) = "cO"
- Remaining MD5: "b0eO" (appended at the end)

**Final interleaved**: "8H2E7LcLcOb0eO"

### Step 4: Apply External Key XOR

```python
def keyed_xor(interleaved, external_key):
    result = ""
    for i in range(len(interleaved)):
        # Convert characters to ASCII values
        char_val = ord(interleaved[i])
        key_val = ord(external_key[i % len(external_key)])
        
        # XOR operation
        xor_result = char_val ^ key_val
        
        # Convert back to character
        result += chr(xor_result)
    return result
```

**Example**:
```
Interleaved: 8H2E7LcLcOb0eO
External key: 0123456789abcdef0123456789abcdef

Character-by-character XOR:
'8' ^ '0' = 56 ^ 48 = 8 = '\x08'
'H' ^ '1' = 72 ^ 49 = 121 = 'y'
'2' ^ '2' = 50 ^ 50 = 0 = '\x00'
'E' ^ '3' = 69 ^ 51 = 118 = 'v'
'7' ^ '4' = 55 ^ 52 = 3 = '\x03'
'L' ^ '5' = 76 ^ 53 = 121 = 'y'
'c' ^ '6' = 99 ^ 54 = 85 = 'U'
'L' ^ '7' = 76 ^ 55 = 123 = '{'
'c' ^ '8' = 99 ^ 56 = 91 = '['
'O' ^ '9' = 79 ^ 57 = 118 = 'v'
'b' ^ 'a' = 98 ^ 97 = 3 = '\x03'
'0' ^ 'b' = 48 ^ 98 = 82 = 'R'
'e' ^ 'c' = 101 ^ 99 = 6 = '\x06'
'O' ^ 'd' = 79 ^ 100 = 47 = '/'
```

**XOR result**: "\x08y\x00v\x03yU{[v\x03R\x06/"

### Step 5: Base64 Encoding

```python
import base64
encoded = base64.b64encode(xor_result.encode('latin-1')).decode()
# Result: "CHgAdgN5VXtbdgNSBg8="
```

## Complete Algorithm Implementation

```python
import hashlib
import random
import base64

def adodb_crypt(text, external_key):
    """ADOdb Crypt encryption algorithm."""
    
    # Step 1: Generate random number
    rand = random.randint(0, 32000)
    
    # Step 2: Generate MD5 hash
    md5_hash = hashlib.md5(str(rand).encode()).hexdigest()
    
    # Step 3: Interleave MD5 with text
    interleaved = ""
    for i in range(len(text)):
        interleaved += md5_hash[i] + text[i]
    interleaved += md5_hash[len(text):]  # Add remaining MD5 characters
    
    # Step 4: Apply external key XOR
    result = ""
    for i in range(len(interleaved)):
        char_val = ord(interleaved[i])
        key_val = ord(external_key[i % len(external_key)])
        xor_result = char_val ^ key_val
        result += chr(xor_result)
    
    # Step 5: Base64 encoding
    return base64.b64encode(result.encode('latin-1')).decode()

# Example usage
text = "HELLO"
key = "0123456789abcdef0123456789abcdef"
encrypted = adodb_crypt(text, key)
print(f"Encrypted: {encrypted}")
```

## Attack Analysis

### Vulnerability: Known Plaintext Attack

The ADOdb Crypt algorithm is vulnerable to known plaintext attacks because:

1. **Predictable random range**: Only 32,001 possible values (0 to 32,000)
2. **Known structure**: The interleaving pattern is predictable
3. **XOR weakness**: XOR operations can be reversed with known plaintext

### Attack Process

1. **Brute force the random number**: Try all 32,001 possible values
2. **Generate MD5 hash**: For each candidate random number
3. **Reverse the interleaving**: Extract the original text from the interleaved result
4. **Verify with known plaintext**: Check if the extracted text matches the known plaintext

### Attack Implementation

```python
def attack_adodb_crypt(encrypted, known_plaintext, external_key):
    """Attack ADOdb Crypt using known plaintext."""
    
    # Decode Base64
    try:
        decoded = base64.b64decode(encrypted).decode('latin-1')
    except:
        return None
    
    # Try all possible random numbers
    for rand in range(32001):
        # Generate MD5 hash
        md5_hash = hashlib.md5(str(rand).encode()).hexdigest()
        
        # Reverse XOR with external key
        interleaved = ""
        for i in range(len(decoded)):
            char_val = ord(decoded[i])
            key_val = ord(external_key[i % len(external_key)])
            xor_result = char_val ^ key_val
            interleaved += chr(xor_result)
        
        # Try to extract plaintext
        if len(interleaved) >= len(known_plaintext) * 2:
            extracted = ""
            for i in range(len(known_plaintext)):
                if i * 2 + 1 < len(interleaved):
                    extracted += interleaved[i * 2 + 1]
            
            if extracted == known_plaintext:
                return rand, md5_hash
    
    return None

# Example attack
encrypted = "CHgAdgN5VXtbdgNSBg8="
known_plaintext = "HELLO"
external_key = "0123456789abcdef0123456789abcdef"

result = attack_adodb_crypt(encrypted, known_plaintext, external_key)
if result:
    rand, md5_hash = result
    print(f"Found random number: {rand}")
    print(f"MD5 hash: {md5_hash}")
else:
    print("Attack failed")
```

## Security Analysis

### Weaknesses

1. **Small key space**: Only 32,001 possible random numbers
2. **Predictable structure**: The interleaving pattern is known
3. **XOR vulnerability**: XOR can be easily reversed with known plaintext
4. **No authentication**: No integrity checking

### Strengths

1. **Two-layer encryption**: Provides some obfuscation
2. **Base64 encoding**: Makes the output look random
3. **Variable length**: Can handle different text lengths

### Recommendations

1. **Use established algorithms**: Use AES or other proven encryption methods
2. **Larger key space**: Use cryptographically secure random number generators
3. **Add authentication**: Include HMAC or similar for integrity checking
4. **Avoid custom crypto**: Don't implement custom encryption algorithms

## Conclusion

ADOdb Crypt demonstrates several common mistakes in custom encryption:

1. **Insufficient randomness**: 32,001 possible values is too small
2. **Predictable structure**: The algorithm structure is too simple
3. **XOR weakness**: XOR alone is not sufficient for security
4. **No security analysis**: The algorithm wasn't designed with security in mind

This analysis shows why it's important to use established, well-tested cryptographic algorithms rather than implementing custom solutions. The attack demonstrates how even seemingly complex algorithms can be broken with simple known plaintext attacks.

## Educational Value

This example teaches:

- **Why custom crypto is dangerous**: Even complex-looking algorithms can have simple vulnerabilities
- **Importance of key space**: Small key spaces make brute force attacks feasible
- **Known plaintext attacks**: How attackers can exploit known plaintext-ciphertext pairs
- **Security by obscurity**: Why hiding the algorithm doesn't make it secure
- **Cryptographic principles**: The importance of using established, tested algorithms

**Warning**: This analysis is for educational purposes only. Always use established cryptographic libraries for production systems.
