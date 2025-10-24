# Second Preimage Attack

## Overview

This challenge demonstrates a fundamental vulnerability in truncated hash functions by finding a second preimage - a different message that produces the same hash as the original message. The attack exploits the fact that truncated SHA-256 (SHA-256-24) has significantly reduced security due to its shorter output length.

## Challenge Description

The server implements the following process:
1. Provides a target hash (SHA-256-24) of the user's email address
2. Requires finding a different message that produces the same hash
3. The challenge uses SHA-256-24, which takes the first 24 bits (3 bytes, 6 hex characters) of SHA-256

**Hash Function:**
```
SHA-256-24(message) = SHA-256(message)[:6]
```

**Example:**
```
SHA-256("user@example.com") = b4c9a289323b21a01c3e940f150eb...
SHA-256-24("user@example.com") = b4c9a2
```

The challenge is to find a second preimage that produces the same hash as the original email.

## Vulnerability Analysis

### Truncated Hash Weakness

Truncated hash functions have significantly reduced security:

1. **Reduced Output Space**: 24-bit output means only 2^24 = 16,777,216 possible hashes
2. **Birthday Paradox**: Collisions become likely with ~2^12 = 4,096 messages
3. **Brute Force Feasible**: 2^24 operations are computationally feasible
4. **Second Preimage Attack**: Finding a second preimage requires ~2^24 operations

### Mathematical Foundation

For a hash function with n-bit output:
- **Collision Resistance**: ~2^(n/2) operations (birthday paradox)
- **Second Preimage Resistance**: ~2^n operations (brute force)
- **Preimage Resistance**: ~2^n operations (brute force)

For SHA-256-24 (24-bit output):
- **Collision Resistance**: ~2^12 = 4,096 operations
- **Second Preimage Resistance**: ~2^24 = 16,777,216 operations

## Technical Implementation

### Attack Strategy

1. **Hash Calculation**: Implement SHA-256-24 function
2. **Brute Force Search**: Try different suffixes to find collision
3. **Optimization**: Use multiple strategies and threading
4. **Verification**: Ensure found message produces target hash

### Attack Process

#### Step 1: Get Target Hash
```python
def get_target_hash(email):
    url = f"{base_url}/cripto/second-preimage/{email}/challenge"
    response = requests.get(url)
    return response.text.strip()
```

#### Step 2: Calculate SHA-256-24
```python
def calculate_hash(message):
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    truncated_hash = full_hash[:6]  # First 6 hex characters = 24 bits
    return truncated_hash
```

#### Step 3: Brute Force Search
```python
def brute_force_search(target_hash, original_message, max_length=10):
    charset = string.printable.strip()
    
    for length in range(1, max_length + 1):
        for suffix in itertools.product(charset, repeat=length):
            candidate = original_message + ''.join(suffix)
            candidate_hash = calculate_hash(candidate)
            
            if candidate_hash == target_hash and candidate != original_message:
                return candidate
    
    return None
```

#### Step 4: Optimized Search Strategies
```python
def optimized_search(target_hash, original_message):
    # Strategy 1: Common suffixes
    common_suffixes = ["1", "2", "3", "a", "b", "c", "!", "@", "#"]
    
    # Strategy 2: Incremental numbers
    for i in range(1, 10000):
        candidate = original_message + str(i)
        if calculate_hash(candidate) == target_hash:
            return candidate
    
    # Strategy 3: Random-looking suffixes
    # ... (additional strategies)
```

### Key Components

- **`SecondPreimageAttack`**: Main attack class implementing the second preimage attack
- **`get_target_hash()`**: Retrieves the target hash from the server
- **`calculate_hash()`**: Calculates SHA-256-24 hash of a message
- **`brute_force_search()`**: Performs brute force search for second preimage
- **`optimized_search()`**: Uses multiple strategies to find collisions
- **`submit_answer()`**: Submits the second preimage to the server

## Detailed Attack Explanation

### Brute Force Process

1. **Character Set**: Use printable ASCII characters (94 characters)
2. **Suffix Generation**: Generate all possible suffixes of increasing length
3. **Hash Calculation**: Calculate SHA-256-24 for each candidate
4. **Collision Detection**: Check if hash matches target
5. **Verification**: Ensure candidate is different from original

### Optimization Strategies

#### Strategy 1: Common Suffixes
Try common patterns first:
- Single characters: "1", "2", "a", "b", "!"
- Double characters: "01", "aa", "!!"
- Triple characters: "001", "aaa", "!!!"

#### Strategy 2: Incremental Numbers
Try numeric suffixes:
- "1", "2", "3", ..., "1000", "1001", ...

#### Strategy 3: Random-Looking Suffixes
Try random character combinations:
- "abc", "def", "xyz", "!@#", "$%^", ...

#### Strategy 4: Parallel Processing
Use multiple threads to speed up search:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = []
    for length in range(1, max_length + 1):
        future = executor.submit(search_length, target_hash, original_message, length)
        futures.append(future)
```

## Attack Complexity

- **Time Complexity**: O(2^24) in worst case, much better with optimizations
- **Space Complexity**: O(1) - constant space
- **Expected Operations**: ~2^24 / 2 = 8,388,608 operations on average
- **Success Rate**: 100% (deterministic attack)

## Files

- **`second_preimage_attack.py`**: Complete attack implementation
- **`test_second_preimage.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python second_preimage_attack.py

# Run tests
python test_second_preimage.py
```

## Example Attack Flow

```python
# 1. Get target hash
target_hash = attack.get_target_hash(email)
# Output: "b4c9a2"

# 2. Verify original message
original_hash = attack.calculate_hash(email)
# Output: "b4c9a2"

# 3. Search for second preimage
second_preimage = attack.optimized_search(target_hash, email)
# Output: "user@example.com123"

# 4. Verify collision
verification_hash = attack.calculate_hash(second_preimage)
# Output: "b4c9a2"

# 5. Submit answer
result = attack.submit_answer(email, second_preimage)
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **Truncated Hash Vulnerabilities**: Why shorter hashes are weaker
2. **Second Preimage Attacks**: How to find different messages with same hash
3. **Birthday Paradox**: Mathematical foundation of collision attacks
4. **Brute Force Feasibility**: When computational attacks become practical
5. **Hash Function Security**: Importance of full-length hash outputs
6. **Optimization Strategies**: How to improve attack efficiency

## Security Implications

### Why Truncated Hashes are Dangerous

1. **Reduced Security**: 24-bit hash provides only 2^24 = 16M possible outputs
2. **Practical Attacks**: Brute force becomes feasible with modern hardware
3. **Collision Vulnerability**: Birthday paradox makes collisions likely
4. **Second Preimage Vulnerability**: Different messages can produce same hash

### Real-World Examples

1. **Git Commit Hashes**: Short commit hashes can be vulnerable
2. **Session Tokens**: Short tokens can be brute-forced
3. **Password Hashes**: Truncated password hashes are weak
4. **Checksums**: Short checksums provide limited integrity protection

### Defenses Against Second Preimage Attacks

1. **Use Full-Length Hashes**: SHA-256 (256-bit) instead of truncated versions
2. **Use Stronger Hashes**: SHA-3, BLAKE2 for new applications
3. **Salt Messages**: Add random salt to prevent precomputed attacks
4. **Rate Limiting**: Limit hash computation attempts
5. **Keyed Hashes**: Use HMAC with secret keys

## Advanced Attack Variations

### Parallel Processing

Use multiple CPU cores to speed up the search:
```python
with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
    # Distribute work across cores
```

### Memory Optimization

Store only necessary information to reduce memory usage:
```python
# Instead of storing all candidates, just check hashes
for candidate in generate_candidates():
    if calculate_hash(candidate) == target_hash:
        return candidate
```

### Statistical Analysis

Use frequency analysis to prioritize likely candidates:
```python
# Try common patterns first
common_patterns = ["123", "abc", "!@#", "000", "111"]
for pattern in common_patterns:
    candidate = original_message + pattern
    if calculate_hash(candidate) == target_hash:
        return candidate
```

## Common Pitfalls

1. **Character Set**: Must use appropriate character set for the application
2. **Length Limits**: Must respect maximum message length constraints
3. **Encoding Issues**: Must handle UTF-8 encoding correctly
4. **Performance**: Must optimize for the target platform

## References

- [Second Preimage Attack](https://en.wikipedia.org/wiki/Preimage_attack)
- [Birthday Paradox](https://en.wikipedia.org/wiki/Birthday_problem)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Hash Function Security](https://en.wikipedia.org/wiki/Cryptographic_hash_function)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use full-length hash functions in production systems. Truncated hash functions should only be used when the security implications are fully understood and the reduced security is acceptable for the specific use case.
