#!/usr/bin/env python3
"""
DSA k-Reuse Attack

This module implements a DSA k-reuse attack that exploits the vulnerability
when the same random value k is reused in DSA signatures, allowing recovery
of the private key.
"""

import requests
import base64
import json
import hashlib
from typing import List, Tuple, Optional, Dict
from Crypto.Util.number import bytes_to_long, long_to_bytes


class DSAKReuseAttack:
    """Implements DSA k-reuse attack to recover private key."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the DSA k-reuse attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        
    def get_public_key(self, email: str) -> Dict[str, int]:
        """
        Get DSA public key from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Dictionary containing public key parameters
        """
        url = f"{self.base_url}/cripto/dsa/{email}/public-key"
        
        response = requests.get(url)
        return response.json()
    
    def sign_message(self, email: str, message: str) -> Dict[str, int]:
        """
        Sign a message using DSA.
        
        Args:
            email: Email of the user operating the challenge
            message: Message to sign (base64 encoded)
            
        Returns:
            Dictionary containing signature (r, s)
        """
        url = f"{self.base_url}/cripto/dsa/{email}/sign"
        
        response = requests.post(url, files={'message': message})
        return response.json()
    
    def submit_answer(self, email: str, private_key: int) -> str:
        """
        Submit the recovered private key to the server.
        
        Args:
            email: Email of the user operating the challenge
            private_key: Recovered private key x
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/dsa/{email}/answer"
        
        response = requests.post(url, files={'private-key': str(private_key)})
        return response.text.strip()
    
    def sha256_hash(self, data: bytes) -> int:
        """
        Calculate SHA-256 hash of data and convert to integer.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash as integer
        """
        hash_bytes = hashlib.sha256(data).digest()
        return bytes_to_long(hash_bytes)
    
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
    
    def find_k_reuse(self, signatures: List[Dict[str, int]]) -> List[int]:
        """
        Find signatures that reuse the same k value.
        
        Args:
            signatures: List of signatures with r and s values
            
        Returns:
            List of indices where k is reused
        """
        r_values = {}
        reuse_indices = []
        
        for i, sig in enumerate(signatures):
            r = sig['r']
            if r in r_values:
                # Found a reuse
                reuse_indices.extend([r_values[r], i])
            else:
                r_values[r] = i
        
        return list(set(reuse_indices))
    
    def recover_k(self, message1: bytes, message2: bytes, s1: int, s2: int, q: int) -> int:
        """
        Recover k from two messages signed with the same k.
        
        Args:
            message1: First message
            message2: Second message
            s1: Signature s value for first message
            s2: Signature s value for second message
            q: DSA parameter q
            
        Returns:
            Recovered k value
        """
        # Calculate hashes
        h1 = self.sha256_hash(message1)
        h2 = self.sha256_hash(message2)
        
        # Calculate k using the formula:
        # k = (h1 - h2) * (s1 - s2)^(-1) mod q
        numerator = (h1 - h2) % q
        denominator = (s1 - s2) % q
        
        # Calculate modular inverse of denominator
        denominator_inv = self.modular_inverse(denominator, q)
        
        # Calculate k
        k = (numerator * denominator_inv) % q
        
        return k
    
    def recover_private_key(self, message: bytes, r: int, s: int, k: int, q: int) -> int:
        """
        Recover private key x from DSA signature.
        
        Args:
            message: Signed message
            r: Signature r value
            s: Signature s value
            k: Recovered k value
            q: DSA parameter q
            
        Returns:
            Recovered private key x
        """
        # Calculate hash
        h = self.sha256_hash(message)
        
        # Calculate private key using the formula:
        # x = (s * k - h) * r^(-1) mod q
        numerator = (s * k - h) % q
        r_inv = self.modular_inverse(r, q)
        
        # Calculate private key
        x = (numerator * r_inv) % q
        
        return x
    
    def collect_signatures(self, email: str, messages: List[str], count: int = 10) -> List[Dict[str, int]]:
        """
        Collect multiple signatures from the server.
        
        Args:
            email: Email of the user operating the challenge
            messages: List of messages to sign
            count: Number of signatures to collect
            
        Returns:
            List of signatures
        """
        signatures = []
        
        print(f"Collecting {count} signatures from server...")
        
        for i in range(count):
            # Use provided messages or generate simple ones
            if i < len(messages):
                message = messages[i]
            else:
                message = f"message_{i}".encode('utf-8')
                message = base64.b64encode(message).decode('utf-8')
            
            print(f"\nCollecting signature {i+1}/{count}...")
            print(f"Message: {message}")
            
            # Sign message
            signature = self.sign_message(email, message)
            signatures.append(signature)
            
            print(f"Signature: r={signature['r']}, s={signature['s']}")
        
        return signatures
    
    def perform_k_reuse_attack(self, email: str, messages: List[str] = None) -> int:
        """
        Perform complete k-reuse attack to recover private key.
        
        Args:
            email: Email of the user operating the challenge
            messages: List of messages to sign (optional)
            
        Returns:
            Recovered private key x
        """
        try:
            print(f"Starting DSA k-reuse attack against {email}")
            
            # Step 1: Get public key
            print("\nStep 1: Getting public key...")
            public_key = self.get_public_key(email)
            print(f"Public key: {json.dumps(public_key, indent=2)}")
            
            # Step 2: Collect signatures
            print("\nStep 2: Collecting signatures...")
            if messages is None:
                messages = [base64.b64encode(f"test_message_{i}".encode('utf-8')).decode('utf-8') for i in range(20)]
            
            signatures = self.collect_signatures(email, messages, len(messages))
            
            # Step 3: Find k reuse
            print("\nStep 3: Looking for k reuse...")
            reuse_indices = self.find_k_reuse(signatures)
            
            if len(reuse_indices) < 2:
                print("No k reuse found, trying more signatures...")
                # Try more signatures
                more_signatures = self.collect_signatures(email, messages, 50)
                signatures.extend(more_signatures)
                reuse_indices = self.find_k_reuse(signatures)
            
            if len(reuse_indices) < 2:
                raise ValueError("No k reuse found in signatures")
            
            print(f"Found k reuse at indices: {reuse_indices}")
            
            # Step 4: Recover k
            print("\nStep 4: Recovering k...")
            sig1 = signatures[reuse_indices[0]]
            sig2 = signatures[reuse_indices[1]]
            
            # Get corresponding messages
            msg1 = base64.b64decode(messages[reuse_indices[0]])
            msg2 = base64.b64decode(messages[reuse_indices[1]])
            
            print(f"Message 1: {msg1}")
            print(f"Message 2: {msg2}")
            print(f"Signature 1: r={sig1['r']}, s={sig1['s']}")
            print(f"Signature 2: r={sig2['r']}, s={sig2['s']}")
            
            k = self.recover_k(msg1, msg2, sig1['s'], sig2['s'], public_key['Q'])
            print(f"Recovered k: {k}")
            
            # Step 5: Recover private key
            print("\nStep 5: Recovering private key...")
            private_key = self.recover_private_key(msg1, sig1['r'], sig1['s'], k, public_key['Q'])
            print(f"Recovered private key x: {private_key}")
            
            return private_key
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            raise
    
    def execute_attack(self, email: str, messages: List[str] = None) -> str:
        """
        Execute the complete DSA k-reuse attack.
        
        Args:
            email: Email of the user operating the challenge
            messages: List of messages to sign (optional)
            
        Returns:
            Attack result
        """
        try:
            # Perform attack
            private_key = self.perform_k_reuse_attack(email, messages)
            
            # Submit answer
            print("\nStep 6: Submitting answer...")
            result = self.submit_answer(email, private_key)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class DSASimulator:
    """Simulates DSA for testing purposes."""
    
    def __init__(self, p: int, q: int, g: int, x: int):
        """
        Initialize DSA simulator.
        
        Args:
            p: DSA parameter p
            q: DSA parameter q
            g: DSA parameter g
            x: Private key
        """
        self.p = p
        self.q = q
        self.g = g
        self.x = x
        self.y = pow(g, x, p)  # Public key
    
    def sign(self, message: bytes, k: int) -> Tuple[int, int]:
        """
        Sign a message using DSA.
        
        Args:
            message: Message to sign
            k: Random value (should be unique)
            
        Returns:
            Tuple of (r, s)
        """
        # Calculate r = (g^k mod p) mod q
        r = pow(self.g, k, self.p) % self.q
        
        # Calculate hash
        h = bytes_to_long(hashlib.sha256(message).digest())
        
        # Calculate s = k^(-1) * (h + x*r) mod q
        k_inv = self.modular_inverse(k, self.q)
        s = (k_inv * (h + self.x * r)) % self.q
        
        return r, s
    
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


def main():
    """Main function to demonstrate the DSA k-reuse attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = DSAKReuseAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
