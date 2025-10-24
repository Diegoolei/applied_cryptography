#!/usr/bin/env python3
"""
CBC-MAC Forgery Attack

This module implements a CBC-MAC forgery attack that exploits the vulnerability
of CBC-MAC with variable-length messages by creating a forgery through
message concatenation and XOR manipulation.
"""

import requests
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from typing import List, Tuple, Optional
import re


class CBCMACForgeryAttack:
    """Implements CBC-MAC forgery attack."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the CBC-MAC forgery attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.block_size = 16  # AES block size
        
    def get_challenge_message(self, email: str) -> str:
        """
        Get the challenge message from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Challenge message (query string)
        """
        url = f"{self.base_url}/cripto/cbc-mac/{email}/challenge"
        
        response = requests.get(url)
        return response.text.strip()
    
    def submit_answer(self, email: str, forged_query: str) -> str:
        """
        Submit the forged query string to the server.
        
        Args:
            email: Email of the user operating the challenge
            forged_query: Forged query string
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/cbc-mac/{email}/answer?{forged_query}"
        
        response = requests.get(url)
        return response.text.strip()
    
    def parse_query_string(self, query_string: str) -> dict:
        """
        Parse a query string into key-value pairs.
        
        Args:
            query_string: Query string to parse
            
        Returns:
            Dictionary of key-value pairs
        """
        pairs = {}
        for pair in query_string.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                pairs[key] = value
        
        return pairs
    
    def build_message_from_pairs(self, pairs: dict) -> str:
        """
        Build message from key-value pairs (excluding MAC).
        
        Args:
            pairs: Dictionary of key-value pairs
            
        Returns:
            Message string for MAC calculation
        """
        # Remove MAC field
        message_pairs = {k: v for k, v in pairs.items() if k != 'mac'}
        
        # Reconstruct the original query string (without MAC)
        message_parts = []
        for key, value in message_pairs.items():
            message_parts.append(f"{key}={value}")
        
        return '&'.join(message_parts)
    
    def simulate_cbc_mac(self, message: str, key: bytes = b"test_key_16_bytes") -> str:
        """
        Simulate CBC-MAC calculation for testing purposes.
        
        Args:
            message: Message to authenticate
            key: Secret key
            
        Returns:
            MAC as hex string
        """
        # Pad the message
        padded_message = pad(message.encode('utf-8'), self.block_size)
        
        # Initialize with zero IV
        iv = b'\x00' * self.block_size
        
        # Encrypt using CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_message)
        
        # Return the last block as MAC
        mac = encrypted[-self.block_size:]
        
        return mac.hex()
    
    def forge_cbc_mac(self, original_query: str, target_email: str, target_amount: int = 15000) -> str:
        """
        Forge CBC-MAC to create a transfer to target email with target amount.
        
        Args:
            original_query: Original query string
            target_email: Email to transfer money to
            target_amount: Amount to transfer
            
        Returns:
            Forged query string
        """
        print(f"Original query: {original_query}")
        
        # Parse the original query
        pairs = self.parse_query_string(original_query)
        print(f"Parsed pairs: {pairs}")
        
        # Extract original MAC
        original_mac = pairs.get('mac', '')
        print(f"Original MAC: {original_mac}")
        
        # Build original message (without MAC)
        original_message = self.build_message_from_pairs(pairs)
        print(f"Original message: {original_message}")
        
        # Create the attack message
        # We'll use the CBC-MAC forgery technique:
        # If we have message M1 with MAC T1, we can create:
        # M2 = M1 || (T1 XOR M1') || M1'
        # Where M1' is the message we want to append
        
        # Create the additional transfer message
        additional_transfer = f"&{target_email}={target_amount}"
        print(f"Additional transfer: {additional_transfer}")
        
        # For CBC-MAC forgery, we need to:
        # 1. Take the original MAC as the IV for the next block
        # 2. XOR it with the first block of our additional message
        # 3. Append the rest of our additional message
        
        # Convert original MAC to bytes
        original_mac_bytes = bytes.fromhex(original_mac)
        
        # Create the forged message
        # The technique is to create: original_message || (original_mac XOR first_block_of_additional) || rest_of_additional
        
        # Split additional message into blocks
        additional_bytes = additional_transfer.encode('utf-8')
        
        # Pad additional message to block size
        additional_padded = pad(additional_bytes, self.block_size)
        
        # Take first block of additional message
        first_block = additional_padded[:self.block_size]
        
        # XOR with original MAC
        xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
        
        # Create forged message
        forged_message = original_message.encode('utf-8') + xor_block + additional_padded[self.block_size:]
        
        # Convert back to string (handling non-printable characters)
        forged_message_str = forged_message.decode('utf-8', errors='ignore')
        
        print(f"Forged message: {forged_message_str}")
        
        # Create forged query string
        forged_pairs = {
            'from': pairs.get('from', ''),
            target_email: str(target_amount),
            'mac': original_mac  # Use original MAC
        }
        
        # Add any existing comment fields
        for key, value in pairs.items():
            if key.startswith('comment'):
                forged_pairs[key] = value
        
        forged_query = '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
        
        print(f"Forged query: {forged_query}")
        
        return forged_query
    
    def forge_cbc_mac_advanced(self, original_query: str, target_email: str, target_amount: int = 15000) -> str:
        """
        Advanced CBC-MAC forgery using the mathematical property.
        
        Args:
            original_query: Original query string
            target_email: Email to transfer money to
            target_amount: Amount to transfer
            
        Returns:
            Forged query string
        """
        print(f"Advanced CBC-MAC forgery for {target_email} with amount {target_amount}")
        
        # Parse the original query
        pairs = self.parse_query_string(original_query)
        
        # Extract original MAC
        original_mac = pairs.get('mac', '')
        
        # Build original message (without MAC)
        original_message = self.build_message_from_pairs(pairs)
        
        # Create additional transfer
        additional_transfer = f"&{target_email}={target_amount}"
        
        # For CBC-MAC forgery:
        # If M1 has MAC T1, then M1 || (T1 XOR M1') || M1' has MAC T1
        # where M1' is the message we want to append
        
        # Convert original MAC to bytes
        original_mac_bytes = bytes.fromhex(original_mac)
        
        # Create the additional message
        additional_bytes = additional_transfer.encode('utf-8')
        additional_padded = pad(additional_bytes, self.block_size)
        
        # Take first block of additional message
        first_block = additional_padded[:self.block_size]
        
        # XOR with original MAC
        xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
        
        # Create the forged message
        forged_message_bytes = original_message.encode('utf-8') + xor_block + additional_padded[self.block_size:]
        
        # Convert to query string format
        forged_message_str = forged_message_bytes.decode('utf-8', errors='ignore')
        
        # Parse the forged message to extract key-value pairs
        forged_pairs = self.parse_query_string(forged_message_str)
        
        # Ensure we have the required fields
        if 'from' not in forged_pairs:
            forged_pairs['from'] = pairs.get('from', '')
        
        # Add MAC
        forged_pairs['mac'] = original_mac
        
        # Create final query string
        forged_query = '&'.join(f"{key}={value}" for key, value in forged_pairs.items())
        
        print(f"Advanced forged query: {forged_query}")
        
        return forged_query
    
    def execute_attack(self, email: str, target_email: str = None, target_amount: int = 15000) -> str:
        """
        Execute the complete CBC-MAC forgery attack.
        
        Args:
            email: Email of the user operating the challenge
            target_email: Email to transfer money to (defaults to challenge email)
            target_amount: Amount to transfer (defaults to 15000)
            
        Returns:
            Attack result
        """
        try:
            if target_email is None:
                target_email = email
            
            print(f"Starting CBC-MAC forgery attack against {email}")
            print(f"Target: {target_email}, Amount: {target_amount}")
            
            # Step 1: Get challenge message
            print("\nStep 1: Getting challenge message...")
            original_query = self.get_challenge_message(email)
            print(f"Challenge message: {original_query}")
            
            # Step 2: Forge query string
            print("\nStep 2: Forging query string...")
            forged_query = self.forge_cbc_mac_advanced(original_query, target_email, target_amount)
            
            # Step 3: Submit forged query
            print("\nStep 3: Submitting forged query...")
            result = self.submit_answer(email, forged_query)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class CBCMACSimulator:
    """Simulates CBC-MAC for testing purposes."""
    
    def __init__(self, key: bytes = b"test_key_16_bytes"):
        """
        Initialize the CBC-MAC simulator.
        
        Args:
            key: Secret key for CBC-MAC
        """
        self.key = key
        self.block_size = 16
    
    def calculate_cbc_mac(self, message: str) -> str:
        """
        Calculate CBC-MAC for a message.
        
        Args:
            message: Message to authenticate
            
        Returns:
            MAC as hex string
        """
        # Pad the message
        padded_message = pad(message.encode('utf-8'), self.block_size)
        
        # Initialize with zero IV
        iv = b'\x00' * self.block_size
        
        # Encrypt using CBC mode
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_message)
        
        # Return the last block as MAC
        mac = encrypted[-self.block_size:]
        
        return mac.hex()
    
    def verify_cbc_mac(self, message: str, mac: str) -> bool:
        """
        Verify CBC-MAC for a message.
        
        Args:
            message: Message to verify
            mac: MAC to verify against
            
        Returns:
            True if MAC is valid, False otherwise
        """
        calculated_mac = self.calculate_cbc_mac(message)
        return calculated_mac == mac


def main():
    """Main function to demonstrate the CBC-MAC forgery attack."""
    # Configuration
    challenge_email = "user@example.com"
    target_email = "attacker@example.com"
    target_amount = 15000
    
    # Create attack instance
    attack = CBCMACForgeryAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email, target_email, target_amount)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
