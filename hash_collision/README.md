# Hash Collision Attack

## Overview

This challenge demonstrates a fundamental vulnerability in truncated hash functions by finding hash collisions - two different messages that produce the same hash value. The attack exploits the birthday paradox and the reduced security of truncated SHA-256 (SHA-256-48) to find collisions efficiently.

## Challenge Description

The server implements the following process:
1. Requires finding two different messages that produce the same SHA-256-48 hash
2. Both messages must contain the user's email address
3. The challenge uses SHA-256-48, which takes the first 48 bits (6 bytes, 12 hex characters) of SHA-256

**Hash Function:**
```
SHA-256-48(message) = SHA-256(message)[:12]
```

**Example:**
```
SHA-256("user@example.com") = b4c9a289323b21a01c3e940f150eb...
SHA-256-48("user@example.com") = b4c9a289323b
```

The challenge is to find two different messages that both contain the email and produce the same hash.

## Vulnerability Analysis

### Truncated Hash Weakness

Truncated hash functions have significantly reduced security:

1. **Reduced Output Space**: 48-bit output means only 2^48 = 281,474,976,710,656 possible hashes
2. **Birthday Paradox**: Collisions become likely with ~2^24 = 16,777,216 messages
3. **Brute Force Feasible**: 2^24 operations are computationally feasible on modern hardware
4. **Collision Attack**: Finding collisions requires ~2^24 operations (birthday attack)

### Mathematical Foundation

For a hash function with n-bit output:
- **Collision Resistance**: ~2^(n/2) operations (birthday paradox)
- **Second Preimage Resistance**: ~2^n operations (brute force)
- **Preimage Resistance**: ~2^n operations (brute force)

For SHA-256-48 (48-bit output):
- **Collision Resistance**: ~2^24 = 16,777,216 operations
- **Second Preimage Resistance**: ~2^48 = 281,474,976,710,656 operations
- **Preimage Resistance**: ~2^48 = 281,474,976,710,656 operations

### Birthday Paradox

The birthday paradox states that in a group of 23 people, there's a 50% chance that two people share the same birthday. For hash functions:

- **Probability of collision**: P(collision) ≈ 1 - e^(-k²/(2×2^n))
- **Expected collisions**: After ~√(π/2 × 2^n) messages
- **For 48-bit hashes**: Expected collision after ~2^24 messages

## Technical Implementation

### Attack Strategy

1. **Hash Calculation**: Implement SHA-256-48 function
2. **Collision Detection**: Use hash map to detect collisions
3. **Multiple Strategies**: Optimized search, birthday attack, brute force
4. **Parallel Processing**: Use multiple threads for performance
5. **Verification**: Ensure both messages contain email and produce same hash

### Attack Process

#### Step 1: Calculate SHA-256-48
```python
def calculate_hash(message):
    hash_obj = hashlib.sha256(message.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    truncated_hash = full_hash[:12]  # First 12 hex characters = 48 bits
    return truncated_hash
```

#### Step 2: Optimized Collision Search
```python
def find_collision_optimized(email):
    hash_map = defaultdict(list)
    
    # Strategy 1: Common suffixes
    common_suffixes = ["1", "2", "3", "a", "b", "c", "!", "@", "#"]
    
    # Strategy 2: Incremental numbers
    for i in range(1, 10000):
        candidate = email + str(i)
        candidate_hash = calculate_hash(candidate)
        hash_map[candidate_hash].append(candidate)
        
        if len(hash_map[candidate_hash]) >= 2:
            return hash_map[candidate_hash][:2]
```

#### Step 3: Birthday Attack
```python
def find_collision_birthday_attack(email, max_attempts=1000000):
    hash_map = defaultdict(list)
    
    for attempt in range(max_attempts):
        # Generate random suffix
        suffix = ''.join(random.choice(charset) for _ in range(random.randint(1, 8)))
        candidate = email + suffix
        candidate_hash = calculate_hash(candidate)
        hash_map[candidate_hash].append(candidate)
        
        if len(hash_map[candidate_hash]) >= 2:
            return hash_map[candidate_hash][:2]
```

#### Step 4: Brute Force Search
```python
def find_collision_brute_force(email, max_length=8):
    hash_map = defaultdict(list)
    
    for length in range(1, max_length + 1):
        for suffix in itertools.product(charset, repeat=length):
            candidate = email + ''.join(suffix)
            candidate_hash = calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                return hash_map[candidate_hash][:2]
```

### Key Components

- **`HashCollisionAttack`**: Main attack class implementing collision finding
- **`calculate_hash()`**: Calculates SHA-256-48 hash of a message
- **`find_collision_optimized()`**: Uses multiple strategies to find collisions
- **`find_collision_birthday_attack()`**: Random generation birthday attack
- **`find_collision_brute_force()`**: Systematic brute force search
- **`submit_collision()`**: Submits the collision pair to the server

## Detailed Attack Explanation

### Collision Detection Process

1. **Hash Map Storage**: Store messages by their hash values
2. **Collision Detection**: When hash map contains 2+ messages for same hash
3. **Message Validation**: Ensure both messages contain the email
4. **Hash Verification**: Verify both messages produce the same hash

### Optimization Strategies

#### Strategy 1: Common Suffixes
Try common patterns first:
- Single characters: "1", "2", "a", "b", "!"
- Double characters: "01", "aa", "!!"
- Triple characters: "001", "aaa", "!!!"

#### Strategy 2: Incremental Numbers
Try numeric suffixes:
- "1", "2", "3", ..., "1000", "1001", ...

#### Strategy 3: Random Generation
Use random character combinations:
- Random length suffixes with random characters
- Birthday attack approach

#### Strategy 4: Parallel Processing
Use multiple threads to speed up search:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = []
    for length in range(1, max_length + 1):
        future = executor.submit(search_length, email, charset, length)
        futures.append(future)
```

## Attack Complexity

- **Time Complexity**: O(2^24) for collision finding (birthday attack)
- **Space Complexity**: O(2^24) for hash map storage
- **Expected Operations**: ~2^24 = 16,777,216 operations
- **Success Rate**: High probability with sufficient attempts

## Files

- **`hash_collision_attack.py`**: Complete attack implementation
- **`test_hash_collision.py`**: Comprehensive test suite
- **`README.md`**: This documentation

## Usage

```bash
# Run the attack
python hash_collision_attack.py

# Run tests
python test_hash_collision.py
```

## Example Attack Flow

```python
# 1. Initialize attack
attack = HashCollisionAttack()
email = "user@example.com"

# 2. Try optimized search first
collision = attack.find_collision_optimized(email)
# Output: ("user@example.com123", "user@example.com456")

# 3. Verify collision
hash1 = attack.calculate_hash(collision[0])
hash2 = attack.calculate_hash(collision[1])
# Output: "b4c9a289323b" == "b4c9a289323b"

# 4. Submit collision
result = attack.submit_collision(email, collision[0], collision[1])
# Output: "¡Ganaste!"
```

## Educational Value

This challenge demonstrates:

1. **Hash Collision Attacks**: How to find different messages with same hash
2. **Birthday Paradox**: Mathematical foundation of collision attacks
3. **Truncated Hash Vulnerabilities**: Why shorter hashes are weaker
4. **Collision Probability**: Understanding collision likelihood
5. **Attack Optimization**: Multiple strategies for finding collisions
6. **Parallel Processing**: Using multiple threads for performance

## Security Implications

### Why Hash Collisions are Dangerous

1. **Message Forgery**: Can create fake messages with same hash
2. **Digital Signatures**: Can forge signatures for different messages
3. **Password Attacks**: Can find different passwords with same hash
4. **Integrity Violations**: Can modify messages while preserving hash

### Real-World Examples

1. **MD5 Collisions**: MD5 is vulnerable to collision attacks
2. **SHA-1 Collisions**: SHA-1 has been broken for collisions
3. **Certificate Attacks**: Collision attacks on certificate hashes
4. **Blockchain Attacks**: Collision attacks on transaction hashes

### Defenses Against Hash Collision Attacks

1. **Use Strong Hashes**: SHA-256, SHA-3, BLAKE2 for new applications
2. **Avoid Truncated Hashes**: Use full-length hash outputs
3. **Use Salted Hashes**: Add random salt to prevent precomputed attacks
4. **Use Keyed Hashes**: Use HMAC with secret keys
5. **Regular Updates**: Update to stronger hash functions when vulnerabilities are found

## Advanced Attack Variations

### Parallel Processing

Use multiple CPU cores to speed up the search:
```python
with ThreadPoolExecutor(max_workers=cpu_count()) as executor:
    # Distribute work across cores
```

### Memory Optimization

Use efficient data structures to reduce memory usage:
```python
# Use defaultdict for efficient hash map operations
hash_map = defaultdict(list)
```

### Statistical Analysis

Use frequency analysis to prioritize likely candidates:
```python
# Try common patterns first
common_patterns = ["123", "abc", "!@#", "000", "111"]
for pattern in common_patterns:
    candidate = email + pattern
    # Check for collision
```

## Common Pitfalls

1. **Character Set**: Must use appropriate character set for the application
2. **Length Limits**: Must respect maximum message length constraints
3. **Memory Usage**: Hash maps can consume significant memory
4. **Performance**: Must optimize for the target platform

## References

- [Hash Collision Attack](https://en.wikipedia.org/wiki/Hash_collision)
- [Birthday Paradox](https://en.wikipedia.org/wiki/Birthday_problem)
- [SHA-256 Wikipedia](https://en.wikipedia.org/wiki/SHA-2)
- [Hash Function Security](https://en.wikipedia.org/wiki/Cryptographic_hash_function)

## Warning

This is an educational demonstration of cryptographic vulnerabilities. Always use full-length hash functions in production systems. Truncated hash functions should only be used when the security implications are fully understood and the reduced security is acceptable for the specific use case.
