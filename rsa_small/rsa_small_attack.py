#!/usr/bin/env python3
"""
RSA Small Key Attack

This module implements an RSA small key attack that exploits the vulnerability
when RSA uses a small modulus (256 bits), making it feasible to factorize
and recover the private key.
"""

import requests
import base64
import json
import math
from typing import Tuple, Optional
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class RSASmallKeyAttack:
    """Implements RSA small key attack to factorize modulus and recover private key."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the RSA small key attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        
    def get_challenge_data(self, email: str) -> dict:
        """
        Get challenge data from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Dictionary containing ciphertext and public key
        """
        url = f"{self.base_url}/cripto/rsa-small/{email}/challenge"
        
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
        url = f"{self.base_url}/cripto/rsa-small/{email}/answer"
        
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
    
    def trial_division(self, n: int, limit: int = 1000000) -> Optional[int]:
        """
        Perform trial division to find a factor of n.
        
        Args:
            n: Number to factorize
            limit: Maximum number to test
            
        Returns:
            A factor of n if found, None otherwise
        """
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
    
    def pollard_rho(self, n: int) -> Optional[int]:
        """
        Pollard's rho algorithm for integer factorization.
        
        Args:
            n: Number to factorize
            
        Returns:
            A factor of n if found, None otherwise
        """
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
    
    def fermat_factorization(self, n: int) -> Optional[Tuple[int, int]]:
        """
        Fermat's factorization method.
        
        Args:
            n: Number to factorize
            
        Returns:
            Tuple of factors (p, q) if found, None otherwise
        """
        a = int(math.ceil(math.sqrt(n)))
        b2 = a * a - n
        
        while b2 < 0 or int(math.sqrt(b2)) ** 2 != b2:
            a += 1
            b2 = a * a - n
            
            # Prevent infinite loop
            if a > n:
                return None
        
        b = int(math.sqrt(b2))
        p = a - b
        q = a + b
        
        if p * q == n and p > 1 and q > 1:
            return p, q
        
        return None
    
    def factorize(self, n: int) -> Tuple[int, int]:
        """
        Factorize n into two prime factors.
        
        Args:
            n: Modulus to factorize
            
        Returns:
            Tuple of prime factors (p, q)
        """
        print(f"Factorizing n = {n}")
        print(f"n has {n.bit_length()} bits")
        
        # Try different factorization methods
        
        # 1. Trial division for small factors
        print("Trying trial division...")
        factor = self.trial_division(n)
        if factor:
            other_factor = n // factor
            print(f"Found factors via trial division: {factor}, {other_factor}")
            return factor, other_factor
        
        # 2. Pollard's rho algorithm
        print("Trying Pollard's rho algorithm...")
        factor = self.pollard_rho(n)
        if factor:
            other_factor = n // factor
            print(f"Found factors via Pollard's rho: {factor}, {other_factor}")
            return factor, other_factor
        
        # 3. Fermat's factorization
        print("Trying Fermat's factorization...")
        factors = self.fermat_factorization(n)
        if factors:
            p, q = factors
            print(f"Found factors via Fermat: {p}, {q}")
            return p, q
        
        # 4. Brute force for very small numbers
        print("Trying brute force...")
        for i in range(3, int(math.sqrt(n)) + 1, 2):
            if n % i == 0:
                other_factor = n // i
                print(f"Found factors via brute force: {i}, {other_factor}")
                return i, other_factor
        
        raise ValueError(f"Could not factorize n = {n}")
    
    def calculate_private_key(self, p: int, q: int, e: int) -> int:
        """
        Calculate private key d from prime factors p, q and public exponent e.
        
        Args:
            p: First prime factor
            q: Second prime factor
            e: Public exponent
            
        Returns:
            Private key d
        """
        # Calculate Euler's totient function
        phi = (p - 1) * (q - 1)
        
        # Calculate private key d using extended Euclidean algorithm
        d = self.modular_inverse(e, phi)
        
        return d
    
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
    
    def decrypt_rsa(self, ciphertext: bytes, n: int, d: int) -> bytes:
        """
        Decrypt RSA ciphertext using private key.
        
        Args:
            ciphertext: Encrypted data
            n: RSA modulus
            d: Private key
            
        Returns:
            Decrypted data
        """
        # Convert ciphertext to integer
        c = bytes_to_long(ciphertext)
        
        # Decrypt: m = c^d mod n
        m = pow(c, d, n)
        
        # Convert back to bytes
        plaintext_bytes = long_to_bytes(m)
        
        return plaintext_bytes
    
    def remove_pkcs1_padding(self, padded_data: bytes) -> bytes:
        """
        Remove PKCS#1 v1.5 padding from decrypted data.
        
        Args:
            padded_data: Data with PKCS#1 v1.5 padding
            
        Returns:
            Unpadded data
        """
        if len(padded_data) < 3:
            raise ValueError("Invalid PKCS#1 v1.5 padding")
        
        if padded_data[0] != 0x00:
            raise ValueError("Invalid PKCS#1 v1.5 padding: first byte not 0x00")
        
        if padded_data[1] != 0x02:
            raise ValueError("Invalid PKCS#1 v1.5 padding: second byte not 0x02")
        
        # Find the separator byte (0x00)
        separator_index = None
        for i in range(2, len(padded_data)):
            if padded_data[i] == 0x00:
                separator_index = i
                break
        
        if separator_index is None:
            raise ValueError("Invalid PKCS#1 v1.5 padding: no separator found")
        
        # Extract the actual data
        actual_data = padded_data[separator_index + 1:]
        
        return actual_data
    
    def perform_small_key_attack(self, ciphertext: bytes, n: int, e: int) -> str:
        """
        Perform RSA small key attack to decrypt ciphertext.
        
        Args:
            ciphertext: Encrypted data
            n: RSA modulus
            e: Public exponent
            
        Returns:
            Decrypted plaintext
        """
        print(f"Starting RSA small key attack")
        print(f"Modulus n: {n}")
        print(f"Exponent e: {e}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Step 1: Factorize n
        print("\nStep 1: Factorizing modulus...")
        p, q = self.factorize(n)
        
        print(f"Found prime factors: p = {p}, q = {q}")
        print(f"Verification: p * q = {p * q} (should equal {n})")
        
        # Step 2: Calculate private key
        print("\nStep 2: Calculating private key...")
        d = self.calculate_private_key(p, q, e)
        print(f"Private key d: {d}")
        
        # Step 3: Decrypt ciphertext
        print("\nStep 3: Decrypting ciphertext...")
        padded_plaintext = self.decrypt_rsa(ciphertext, n, d)
        print(f"Padded plaintext: {padded_plaintext.hex()}")
        
        # Step 4: Remove PKCS#1 v1.5 padding
        print("\nStep 4: Removing PKCS#1 v1.5 padding...")
        plaintext = self.remove_pkcs1_padding(padded_plaintext)
        print(f"Plaintext bytes: {plaintext}")
        
        # Step 5: Convert to string
        try:
            plaintext_str = plaintext.decode('utf-8')
            print(f"Decrypted plaintext: {plaintext_str}")
            return plaintext_str
        except UnicodeDecodeError:
            print("Failed to decode as UTF-8, trying ASCII...")
            try:
                plaintext_str = plaintext.decode('ascii')
                print(f"Decrypted plaintext: {plaintext_str}")
                return plaintext_str
            except UnicodeDecodeError:
                print("Failed to decode as ASCII")
                return plaintext.hex()
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete RSA small key attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        try:
            print(f"Starting RSA small key attack against {email}")
            
            # Step 1: Get challenge data
            print("\nStep 1: Getting challenge data...")
            data = self.get_challenge_data(email)
            print(f"Challenge data: {json.dumps(data, indent=2)}")
            
            # Step 2: Parse data
            ciphertext_bytes, n, e = self.parse_challenge_data(data)
            
            # Step 3: Perform attack
            print("\nStep 2: Performing small key attack...")
            plaintext = self.perform_small_key_attack(ciphertext_bytes, n, e)
            
            # Step 4: Submit answer
            print("\nStep 3: Submitting answer...")
            result = self.submit_answer(email, plaintext)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class RSASimulator:
    """Simulates RSA for testing purposes."""
    
    def __init__(self, p: int, q: int, e: int = 65537):
        """
        Initialize RSA simulator.
        
        Args:
            p: First prime factor
            q: Second prime factor
            e: Public exponent
        """
        self.p = p
        self.q = q
        self.n = p * q
        self.e = e
        self.phi = (p - 1) * (q - 1)
        self.d = self.modular_inverse(e, self.phi)
    
    def modular_inverse(self, a: int, m: int) -> int:
        """Calculate modular inverse."""
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
    
    def encrypt(self, plaintext: str) -> bytes:
        """
        Encrypt plaintext using RSA with PKCS#1 v1.5 padding.
        
        Args:
            plaintext: Plaintext to encrypt
            
        Returns:
            Encrypted data
        """
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Add PKCS#1 v1.5 padding
        padded_data = self.add_pkcs1_padding(plaintext_bytes)
        
        # Convert to integer
        m = bytes_to_long(padded_data)
        
        # Encrypt: c = m^e mod n
        c = pow(m, self.e, self.n)
        
        # Convert back to bytes
        ciphertext_bytes = long_to_bytes(c)
        
        return ciphertext_bytes
    
    def add_pkcs1_padding(self, data: bytes) -> bytes:
        """
        Add PKCS#1 v1.5 padding to data.
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        # Calculate required padding length
        data_len = len(data)
        key_len = (self.n.bit_length() + 7) // 8  # Convert bits to bytes
        
        if data_len > key_len - 11:
            raise ValueError("Data too long for PKCS#1 v1.5 padding")
        
        # Create padding
        padding_len = key_len - data_len - 3
        padding = b'\x00\x02' + b'\xff' * padding_len + b'\x00'
        
        return padding + data
    
    def decrypt(self, ciphertext: bytes) -> str:
        """
        Decrypt ciphertext using RSA.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted plaintext
        """
        # Convert ciphertext to integer
        c = bytes_to_long(ciphertext)
        
        # Decrypt: m = c^d mod n
        m = pow(c, self.d, self.n)
        
        # Convert back to bytes
        padded_data = long_to_bytes(m)
        
        # Remove PKCS#1 v1.5 padding
        plaintext_bytes = self.remove_pkcs1_padding(padded_data)
        
        # Convert to string
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
    
    def remove_pkcs1_padding(self, padded_data: bytes) -> bytes:
        """Remove PKCS#1 v1.5 padding."""
        if len(padded_data) < 3:
            raise ValueError("Invalid PKCS#1 v1.5 padding")
        
        if padded_data[0] != 0x00:
            raise ValueError("Invalid PKCS#1 v1.5 padding")
        
        if padded_data[1] != 0x02:
            raise ValueError("Invalid PKCS#1 v1.5 padding")
        
        # Find separator
        separator_index = None
        for i in range(2, len(padded_data)):
            if padded_data[i] == 0x00:
                separator_index = i
                break
        
        if separator_index is None:
            raise ValueError("Invalid PKCS#1 v1.5 padding")
        
        return padded_data[separator_index + 1:]


def main():
    """Main function to demonstrate the RSA small key attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = RSASmallKeyAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
