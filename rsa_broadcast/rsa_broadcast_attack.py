#!/usr/bin/env python3
"""
RSA Broadcast Attack

This module implements an RSA broadcast attack that exploits the Chinese Remainder Theorem
to recover plaintext when the same message is encrypted with multiple RSA public keys
with small exponent (e=3).
"""

import requests
import base64
import json
import math
from typing import List, Tuple, Optional
from Crypto.Util.number import bytes_to_long, long_to_bytes


class RSABroadcastAttack:
    """Implements RSA broadcast attack using Chinese Remainder Theorem."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the RSA broadcast attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.exponent = 3  # RSA exponent
        
    def get_challenge_data(self, email: str) -> dict:
        """
        Get challenge data from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Dictionary containing ciphertext and public key
        """
        url = f"{self.base_url}/cripto/rsa-broadcast/{email}/challenge"
        
        response = requests.get(url)
        return response.json()
    
    def submit_answer(self, email: str, plaintext: str) -> str:
        """
        Submit the decrypted plaintext to the server.
        
        Args:
            email: Email of the user operating the challenge
            plaintext: Decrypted plaintext message
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/rsa-broadcast/{email}/answer"
        
        response = requests.post(url, files={'message': plaintext})
        return response.text.strip()
    
    def parse_challenge_data(self, data: dict) -> Tuple[bytes, int, int]:
        """
        Parse challenge data to extract ciphertext and public key.
        
        Args:
            data: Challenge data from server
            
        Returns:
            Tuple of (ciphertext_bytes, n, e)
        """
        # Decode base64 ciphertext
        ciphertext_b64 = data['ciphertext']
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        
        # Extract public key components
        public_key = data['publicKey']
        n = public_key['n']
        e = public_key['e']
        
        return ciphertext_bytes, n, e
    
    def chinese_remainder_theorem(self, remainders: List[int], moduli: List[int]) -> int:
        """
        Solve system of congruences using Chinese Remainder Theorem.
        
        Args:
            remainders: List of remainders
            moduli: List of moduli (must be pairwise coprime)
            
        Returns:
            Solution to the system of congruences
        """
        if len(remainders) != len(moduli):
            raise ValueError("Number of remainders must equal number of moduli")
        
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
    
    def modular_inverse(self, a: int, m: int) -> int:
        """
        Calculate modular inverse of a mod m using extended Euclidean algorithm.
        
        Args:
            a: Number to find inverse of
            m: Modulus
            
        Returns:
            Modular inverse of a mod m
        """
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
    
    def integer_nth_root(self, n: int, precision: int = 100) -> int:
        """
        Calculate integer nth root using Newton's method.
        
        Args:
            n: Number to find root of
            precision: Precision for Newton's method
            
        Returns:
            Integer nth root
        """
        if n < 0:
            raise ValueError("Cannot find root of negative number")
        
        if n == 0:
            return 0
        
        # Use Newton's method for cube root
        x = n
        for _ in range(precision):
            x = (2 * x + n // (x * x)) // 3
        
        return x
    
    def cube_root(self, n: int) -> int:
        """
        Calculate integer cube root.
        
        Args:
            n: Number to find cube root of
            
        Returns:
            Integer cube root
        """
        return self.integer_nth_root(n, 3)
    
    def perform_broadcast_attack(self, ciphertexts: List[bytes], moduli: List[int]) -> str:
        """
        Perform RSA broadcast attack to recover plaintext.
        
        Args:
            ciphertexts: List of ciphertexts (as bytes)
            moduli: List of RSA moduli
            
        Returns:
            Recovered plaintext
        """
        if len(ciphertexts) != len(moduli):
            raise ValueError("Number of ciphertexts must equal number of moduli")
        
        if len(ciphertexts) < 3:
            raise ValueError("Need at least 3 ciphertexts for broadcast attack")
        
        print(f"Performing broadcast attack with {len(ciphertexts)} ciphertexts")
        
        # Convert ciphertexts to integers
        ciphertext_ints = []
        for ciphertext in ciphertexts:
            ciphertext_int = bytes_to_long(ciphertext)
            ciphertext_ints.append(ciphertext_int)
        
        print(f"Ciphertext integers: {ciphertext_ints}")
        print(f"Moduli: {moduli}")
        
        # Apply Chinese Remainder Theorem
        print("\nApplying Chinese Remainder Theorem...")
        m_cubed = self.chinese_remainder_theorem(ciphertext_ints, moduli)
        
        print(f"m^3 (mod N): {m_cubed}")
        
        # Calculate cube root to get m
        print("\nCalculating cube root...")
        m = self.cube_root(m_cubed)
        
        print(f"Recovered m: {m}")
        
        # Convert back to bytes
        plaintext_bytes = long_to_bytes(m)
        
        print(f"Plaintext bytes: {plaintext_bytes}")
        
        # Convert to string
        try:
            plaintext = plaintext_bytes.decode('utf-8')
            print(f"Recovered plaintext: {plaintext}")
            return plaintext
        except UnicodeDecodeError:
            print("Failed to decode as UTF-8, trying ASCII...")
            try:
                plaintext = plaintext_bytes.decode('ascii')
                print(f"Recovered plaintext: {plaintext}")
                return plaintext
            except UnicodeDecodeError:
                print("Failed to decode as ASCII")
                return plaintext_bytes.hex()
    
    def collect_ciphertexts(self, email: str, count: int = 3) -> Tuple[List[bytes], List[int]]:
        """
        Collect multiple ciphertexts from the server.
        
        Args:
            email: Email of the user operating the challenge
            count: Number of ciphertexts to collect
            
        Returns:
            Tuple of (ciphertexts, moduli)
        """
        ciphertexts = []
        moduli = []
        
        print(f"Collecting {count} ciphertexts from server...")
        
        for i in range(count):
            print(f"\nCollecting ciphertext {i+1}/{count}...")
            
            # Get challenge data
            data = self.get_challenge_data(email)
            print(f"Received data: {json.dumps(data, indent=2)}")
            
            # Parse data
            ciphertext_bytes, n, e = self.parse_challenge_data(data)
            
            # Verify exponent
            if e != self.exponent:
                print(f"Warning: Expected exponent {self.exponent}, got {e}")
            
            # Store data
            ciphertexts.append(ciphertext_bytes)
            moduli.append(n)
            
            print(f"Ciphertext {i+1}: {len(ciphertext_bytes)} bytes")
            print(f"Modulus {i+1}: {n}")
            print(f"Exponent: {e}")
        
        return ciphertexts, moduli
    
    def execute_attack(self, email: str, ciphertext_count: int = 3) -> str:
        """
        Execute the complete RSA broadcast attack.
        
        Args:
            email: Email of the user operating the challenge
            ciphertext_count: Number of ciphertexts to collect
            
        Returns:
            Attack result
        """
        try:
            print(f"Starting RSA broadcast attack against {email}")
            print(f"Collecting {ciphertext_count} ciphertexts...")
            
            # Step 1: Collect ciphertexts
            print("\nStep 1: Collecting ciphertexts from server...")
            ciphertexts, moduli = self.collect_ciphertexts(email, ciphertext_count)
            
            # Step 2: Perform broadcast attack
            print("\nStep 2: Performing broadcast attack...")
            plaintext = self.perform_broadcast_attack(ciphertexts, moduli)
            
            # Step 3: Submit answer
            print("\nStep 3: Submitting answer...")
            result = self.submit_answer(email, plaintext)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class RSASimulator:
    """Simulates RSA encryption for testing purposes."""
    
    def __init__(self):
        """Initialize the RSA simulator."""
        pass
    
    def encrypt(self, plaintext: str, n: int, e: int) -> bytes:
        """
        Encrypt plaintext using RSA.
        
        Args:
            plaintext: Plaintext to encrypt
            n: RSA modulus
            e: RSA exponent
            
        Returns:
            Encrypted ciphertext as bytes
        """
        # Convert plaintext to integer
        m = bytes_to_long(plaintext.encode('utf-8'))
        
        # Encrypt: c = m^e mod n
        c = pow(m, e, n)
        
        # Convert back to bytes
        ciphertext_bytes = long_to_bytes(c)
        
        return ciphertext_bytes
    
    def decrypt(self, ciphertext: bytes, n: int, d: int) -> str:
        """
        Decrypt ciphertext using RSA.
        
        Args:
            ciphertext: Ciphertext to decrypt
            n: RSA modulus
            d: RSA private exponent
            
        Returns:
            Decrypted plaintext
        """
        # Convert ciphertext to integer
        c = bytes_to_long(ciphertext)
        
        # Decrypt: m = c^d mod n
        m = pow(c, d, n)
        
        # Convert back to string
        plaintext_bytes = long_to_bytes(m)
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext


def main():
    """Main function to demonstrate the RSA broadcast attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = RSABroadcastAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
