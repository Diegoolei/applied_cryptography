#!/usr/bin/env python3
"""
Hash Collision Attack

This module implements a hash collision attack against truncated SHA-256 hash functions.
It demonstrates the vulnerability of truncated hash functions by finding two different
messages that produce the same hash value.
"""

import requests
import hashlib
import itertools
import string
import time
from typing import Optional, Tuple
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict


class HashCollisionAttack:
    """Implements hash collision attack against truncated SHA-256."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the hash collision attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.hash_length = 48  # 48 bits = 6 bytes = 12 hex characters
        
    def calculate_hash(self, message: str) -> str:
        """
        Calculate SHA-256-48 hash of a message.
        
        Args:
            message: Message to hash
            
        Returns:
            Hash as 12-character hex string
        """
        hash_obj = hashlib.sha256(message.encode('utf-8'))
        full_hash = hash_obj.hexdigest()
        truncated_hash = full_hash[:12]  # First 12 hex characters = 48 bits
        
        return truncated_hash
    
    def submit_collision(self, email: str, message1: str, message2: str) -> str:
        """
        Submit the collision pair to the server.
        
        Args:
            email: Email of the user operating the challenge
            message1: First message in collision pair
            message2: Second message in collision pair
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/collision/{email}/answer"
        
        # Use files parameter to send binary data
        files = {
            'message1': message1.encode('utf-8'),
            'message2': message2.encode('utf-8')
        }
        
        response = requests.post(url, files=files)
        return response.text.strip()
    
    def find_collision_brute_force(self, email: str, max_length: int = 8, 
                                  num_threads: int = 4) -> Optional[Tuple[str, str]]:
        """
        Find hash collision using brute force search.
        
        Args:
            email: Email that must be included in both messages
            max_length: Maximum length of suffix to try
            num_threads: Number of threads to use
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print(f"Searching for hash collision with email: {email}")
        print(f"Hash length: {self.hash_length} bits ({self.hash_length//4} hex characters)")
        print(f"Max suffix length: {max_length}")
        print(f"Using {num_threads} threads")
        
        # Character set for brute force (printable ASCII)
        charset = string.printable.strip()  # All printable characters except whitespace
        
        print(f"Character set: {charset}")
        print(f"Total combinations to try: ~{len(charset)**max_length:,}")
        
        # Use threading to speed up the search
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            
            # Submit tasks for different suffix lengths
            for length in range(1, max_length + 1):
                future = executor.submit(
                    self._search_collision_length, 
                    email, 
                    charset, 
                    length
                )
                futures.append(future)
            
            # Check results as they complete
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    # Cancel remaining tasks
                    for f in futures:
                        f.cancel()
                    return result
        
        return None
    
    def _search_collision_length(self, email: str, charset: str, 
                               length: int) -> Optional[Tuple[str, str]]:
        """
        Search for collision with specific suffix length.
        
        Args:
            email: Email that must be included in both messages
            charset: Character set to use
            length: Length of suffix to try
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print(f"Searching with suffix length {length}...")
        
        start_time = time.time()
        count = 0
        hash_map = defaultdict(list)
        
        # Generate all possible combinations of given length
        for suffix in itertools.product(charset, repeat=length):
            count += 1
            
            # Create candidate message
            candidate = email + ''.join(suffix)
            
            # Calculate hash
            candidate_hash = self.calculate_hash(candidate)
            
            # Store in hash map
            hash_map[candidate_hash].append(candidate)
            
            # Check for collision
            if len(hash_map[candidate_hash]) >= 2:
                messages = hash_map[candidate_hash][:2]
                elapsed = time.time() - start_time
                print(f"Found collision after {count:,} attempts in {elapsed:.2f} seconds")
                print(f"Hash: {candidate_hash}")
                print(f"Message 1: {messages[0]}")
                print(f"Message 2: {messages[1]}")
                return (messages[0], messages[1])
            
            # Progress reporting
            if count % 100000 == 0:
                elapsed = time.time() - start_time
                rate = count / elapsed if elapsed > 0 else 0
                print(f"Length {length}: {count:,} attempts, {rate:,.0f} hashes/sec")
        
        elapsed = time.time() - start_time
        print(f"Length {length}: {count:,} attempts completed in {elapsed:.2f} seconds")
        return None
    
    def find_collision_optimized(self, email: str) -> Optional[Tuple[str, str]]:
        """
        Find collision using optimized strategies.
        
        Args:
            email: Email that must be included in both messages
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print("Starting optimized collision search...")
        
        # Strategy 1: Try common suffixes first
        common_suffixes = [
            "1", "2", "3", "a", "b", "c", "!", "@", "#", "$",
            "01", "02", "03", "aa", "bb", "cc", "!!", "@@", "##", "$$",
            "001", "002", "003", "aaa", "bbb", "ccc", "!!!", "@@@", "###", "$$$",
            "0001", "0002", "0003", "aaaa", "bbbb", "cccc", "!!!!", "@@@@", "####", "$$$$"
        ]
        
        print("Strategy 1: Trying common suffixes...")
        hash_map = defaultdict(list)
        
        for suffix in common_suffixes:
            candidate = email + suffix
            candidate_hash = self.calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                messages = hash_map[candidate_hash][:2]
                print(f"Found collision with common suffixes: {messages}")
                return tuple(messages)
        
        # Strategy 2: Try incremental suffixes
        print("Strategy 2: Trying incremental suffixes...")
        for i in range(1, 10000):  # Try first 10,000 numbers
            candidate = email + str(i)
            candidate_hash = self.calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                messages = hash_map[candidate_hash][:2]
                print(f"Found collision with incremental suffixes: {messages}")
                return tuple(messages)
            
            if i % 1000 == 0:
                print(f"Tried {i} incremental suffixes...")
        
        # Strategy 3: Try random-looking suffixes
        print("Strategy 3: Trying random-looking suffixes...")
        random_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        
        for length in range(1, 6):
            count = 0
            for suffix in itertools.product(random_chars, repeat=length):
                candidate = email + ''.join(suffix)
                candidate_hash = self.calculate_hash(candidate)
                hash_map[candidate_hash].append(candidate)
                
                if len(hash_map[candidate_hash]) >= 2:
                    messages = hash_map[candidate_hash][:2]
                    print(f"Found collision with random suffixes: {messages}")
                    return tuple(messages)
                
                count += 1
                if count > 10000:  # Limit attempts per length
                    break
        
        return None
    
    def find_collision_birthday_attack(self, email: str, max_attempts: int = 1000000) -> Optional[Tuple[str, str]]:
        """
        Find collision using birthday attack (random generation).
        
        Args:
            email: Email that must be included in both messages
            max_attempts: Maximum number of attempts
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print(f"Starting birthday attack with max {max_attempts:,} attempts...")
        
        import random
        charset = string.printable.strip()
        hash_map = defaultdict(list)
        
        for attempt in range(max_attempts):
            # Generate random suffix
            suffix_length = random.randint(1, 8)
            suffix = ''.join(random.choice(charset) for _ in range(suffix_length))
            
            candidate = email + suffix
            candidate_hash = self.calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                messages = hash_map[candidate_hash][:2]
                print(f"Found collision after {attempt:,} attempts")
                print(f"Hash: {candidate_hash}")
                print(f"Message 1: {messages[0]}")
                print(f"Message 2: {messages[1]}")
                return tuple(messages)
            
            if attempt % 100000 == 0:
                print(f"Birthday attack: {attempt:,} attempts completed")
        
        print(f"Birthday attack completed {max_attempts:,} attempts without finding collision")
        return None
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete hash collision attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        try:
            print(f"Starting hash collision attack against {email}")
            
            # Step 1: Try optimized search first
            print("\nStep 1: Trying optimized collision search...")
            start_time = time.time()
            
            collision = self.find_collision_optimized(email)
            
            if collision is None:
                print("\nOptimized search failed, trying birthday attack...")
                collision = self.find_collision_birthday_attack(email, max_attempts=500000)
            
            if collision is None:
                print("\nBirthday attack failed, trying brute force...")
                collision = self.find_collision_brute_force(email, max_length=6, num_threads=4)
            
            elapsed = time.time() - start_time
            
            if collision is None:
                return f"Error: Could not find collision after {elapsed:.2f} seconds"
            
            message1, message2 = collision
            
            print(f"\nCollision found: {message1} and {message2}")
            print(f"Hash: {self.calculate_hash(message1)}")
            print(f"Verification: {self.calculate_hash(message1)} == {self.calculate_hash(message2)}")
            print(f"Time taken: {elapsed:.2f} seconds")
            
            # Step 2: Submit collision
            print("\nStep 2: Submitting collision...")
            result = self.submit_collision(email, message1, message2)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class CollisionFinder:
    """Utility class for finding hash collisions."""
    
    @staticmethod
    def find_collision_generic(target_hash: str, charset: str = string.printable.strip(), 
                              max_length: int = 8) -> Optional[Tuple[str, str]]:
        """
        Find a collision for a given hash using generic approach.
        
        Args:
            target_hash: Hash to find collision for
            charset: Character set to use
            max_length: Maximum length of strings to try
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print(f"Looking for collision with hash: {target_hash}")
        
        hash_map = defaultdict(list)
        
        for length in range(1, max_length + 1):
            for message in itertools.product(charset, repeat=length):
                msg_str = ''.join(message)
                msg_hash = hashlib.sha256(msg_str.encode('utf-8')).hexdigest()[:12]
                
                hash_map[msg_hash].append(msg_str)
                
                if len(hash_map[msg_hash]) >= 2:
                    messages = hash_map[msg_hash][:2]
                    return tuple(messages)
        
        return None


def main():
    """Main function to demonstrate the hash collision attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = HashCollisionAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
