#!/usr/bin/env python3
"""
Second Preimage Attack

This module implements a second preimage attack against truncated SHA-256 hash functions.
It demonstrates the vulnerability of truncated hash functions by finding collisions
through brute force search.
"""

import requests
import hashlib
import itertools
import string
import time
from typing import Optional, Tuple
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class SecondPreimageAttack:
    """Implements second preimage attack against truncated SHA-256."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the second preimage attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.hash_length = 24  # 24 bits = 3 bytes = 6 hex characters
        
    def get_target_hash(self, email: str) -> str:
        """
        Get the target hash from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Target hash (6 hex characters)
        """
        url = f"{self.base_url}/cripto/second-preimage/{email}/challenge"
        
        response = requests.get(url)
        target_hash = response.text.strip()
        
        return target_hash
    
    def calculate_hash(self, message: str) -> str:
        """
        Calculate SHA-256-24 hash of a message.
        
        Args:
            message: Message to hash
            
        Returns:
            Hash as 6-character hex string
        """
        hash_obj = hashlib.sha256(message.encode('utf-8'))
        full_hash = hash_obj.hexdigest()
        truncated_hash = full_hash[:6]  # First 6 hex characters = 24 bits
        
        return truncated_hash
    
    def submit_answer(self, email: str, second_preimage: str) -> str:
        """
        Submit the second preimage to the server.
        
        Args:
            email: Email of the user operating the challenge
            second_preimage: Message that produces the same hash
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/second-preimage/{email}/answer"
        data = {'message': second_preimage}
        
        response = requests.post(url, data=data)
        return response.text.strip()
    
    def brute_force_search(self, target_hash: str, original_message: str, 
                          max_length: int = 10, num_threads: int = 4) -> Optional[str]:
        """
        Perform brute force search for a second preimage.
        
        Args:
            target_hash: Target hash to match
            original_message: Original message (to avoid finding the same message)
            max_length: Maximum length of suffix to try
            num_threads: Number of threads to use
            
        Returns:
            Second preimage if found, None otherwise
        """
        print(f"Searching for second preimage with hash: {target_hash}")
        print(f"Original message: {original_message}")
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
                    self._search_length, 
                    target_hash, 
                    original_message, 
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
    
    def _search_length(self, target_hash: str, original_message: str, 
                      charset: str, length: int) -> Optional[str]:
        """
        Search for second preimage with specific suffix length.
        
        Args:
            target_hash: Target hash to match
            original_message: Original message
            charset: Character set to use
            length: Length of suffix to try
            
        Returns:
            Second preimage if found, None otherwise
        """
        print(f"Searching with suffix length {length}...")
        
        start_time = time.time()
        count = 0
        
        # Generate all possible combinations of given length
        for suffix in itertools.product(charset, repeat=length):
            count += 1
            
            # Create candidate message
            candidate = original_message + ''.join(suffix)
            
            # Calculate hash
            candidate_hash = self.calculate_hash(candidate)
            
            # Check if it matches
            if candidate_hash == target_hash and candidate != original_message:
                elapsed = time.time() - start_time
                print(f"Found second preimage after {count:,} attempts in {elapsed:.2f} seconds")
                print(f"Second preimage: {candidate}")
                print(f"Hash: {candidate_hash}")
                return candidate
            
            # Progress reporting
            if count % 100000 == 0:
                elapsed = time.time() - start_time
                rate = count / elapsed if elapsed > 0 else 0
                print(f"Length {length}: {count:,} attempts, {rate:,.0f} hashes/sec")
        
        elapsed = time.time() - start_time
        print(f"Length {length}: {count:,} attempts completed in {elapsed:.2f} seconds")
        return None
    
    def optimized_search(self, target_hash: str, original_message: str) -> Optional[str]:
        """
        Optimized search using different strategies.
        
        Args:
            target_hash: Target hash to match
            original_message: Original message
            
        Returns:
            Second preimage if found, None otherwise
        """
        print("Starting optimized search for second preimage...")
        
        # Strategy 1: Try common suffixes first
        common_suffixes = [
            "1", "2", "3", "a", "b", "c", "!", "@", "#", "$",
            "01", "02", "03", "aa", "bb", "cc", "!!", "@@", "##", "$$",
            "001", "002", "003", "aaa", "bbb", "ccc", "!!!", "@@@", "###", "$$$",
            "0001", "0002", "0003", "aaaa", "bbbb", "cccc", "!!!!", "@@@@", "####", "$$$$"
        ]
        
        print("Strategy 1: Trying common suffixes...")
        for suffix in common_suffixes:
            candidate = original_message + suffix
            candidate_hash = self.calculate_hash(candidate)
            
            if candidate_hash == target_hash and candidate != original_message:
                print(f"Found second preimage with common suffix: {candidate}")
                return candidate
        
        # Strategy 2: Try incremental suffixes
        print("Strategy 2: Trying incremental suffixes...")
        for i in range(1, 10000):  # Try first 10,000 numbers
            candidate = original_message + str(i)
            candidate_hash = self.calculate_hash(candidate)
            
            if candidate_hash == target_hash and candidate != original_message:
                print(f"Found second preimage with incremental suffix: {candidate}")
                return candidate
            
            if i % 1000 == 0:
                print(f"Tried {i} incremental suffixes...")
        
        # Strategy 3: Try random-looking suffixes
        print("Strategy 3: Trying random-looking suffixes...")
        random_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        
        for length in range(1, 6):
            for suffix in itertools.product(random_chars, repeat=length):
                candidate = original_message + ''.join(suffix)
                candidate_hash = self.calculate_hash(candidate)
                
                if candidate_hash == target_hash and candidate != original_message:
                    print(f"Found second preimage with random suffix: {candidate}")
                    return candidate
                
                # Limit attempts per length
                if len(suffix) == length and sum(1 for _ in itertools.product(random_chars, repeat=length)) > 10000:
                    break
        
        # Strategy 4: Full brute force with limited character set
        print("Strategy 4: Full brute force with limited character set...")
        limited_charset = "abcdefghijklmnopqrstuvwxyz0123456789"
        
        for length in range(1, 5):  # Try up to 4 characters
            for suffix in itertools.product(limited_charset, repeat=length):
                candidate = original_message + ''.join(suffix)
                candidate_hash = self.calculate_hash(candidate)
                
                if candidate_hash == target_hash and candidate != original_message:
                    print(f"Found second preimage with limited charset: {candidate}")
                    return candidate
        
        return None
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete second preimage attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        try:
            # Step 1: Get target hash
            print("Step 1: Getting target hash...")
            target_hash = self.get_target_hash(email)
            print(f"Target hash: {target_hash}")
            
            # Step 2: Verify original message produces target hash
            original_hash = self.calculate_hash(email)
            print(f"Original message hash: {original_hash}")
            
            if original_hash != target_hash:
                return f"Error: Original message hash ({original_hash}) doesn't match target ({target_hash})"
            
            # Step 3: Search for second preimage
            print("\nStep 2: Searching for second preimage...")
            start_time = time.time()
            
            # Try optimized search first
            second_preimage = self.optimized_search(target_hash, email)
            
            # If not found, try brute force
            if second_preimage is None:
                print("\nOptimized search failed, trying brute force...")
                second_preimage = self.brute_force_search(target_hash, email, max_length=4, num_threads=4)
            
            elapsed = time.time() - start_time
            
            if second_preimage is None:
                return f"Error: Could not find second preimage after {elapsed:.2f} seconds"
            
            print(f"\nSecond preimage found: {second_preimage}")
            print(f"Verification: {self.calculate_hash(second_preimage)} == {target_hash}")
            print(f"Time taken: {elapsed:.2f} seconds")
            
            # Step 4: Submit answer
            print("\nStep 3: Submitting answer...")
            result = self.submit_answer(email, second_preimage)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class HashCollisionFinder:
    """Utility class for finding hash collisions."""
    
    @staticmethod
    def find_collision(target_hash: str, charset: str = string.printable.strip(), 
                      max_length: int = 6) -> Optional[Tuple[str, str]]:
        """
        Find a collision for a given hash.
        
        Args:
            target_hash: Hash to find collision for
            charset: Character set to use
            max_length: Maximum length of strings to try
            
        Returns:
            Tuple of (message1, message2) if collision found, None otherwise
        """
        print(f"Looking for collision with hash: {target_hash}")
        
        seen_hashes = {}
        
        for length in range(1, max_length + 1):
            for message in itertools.product(charset, repeat=length):
                msg_str = ''.join(message)
                msg_hash = hashlib.sha256(msg_str.encode('utf-8')).hexdigest()[:6]
                
                if msg_hash == target_hash:
                    if target_hash in seen_hashes:
                        return (seen_hashes[target_hash], msg_str)
                    else:
                        seen_hashes[target_hash] = msg_str
        
        return None


def main():
    """Main function to demonstrate the second preimage attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = SecondPreimageAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
