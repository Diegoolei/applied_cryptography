#!/usr/bin/env python3
"""
Padding Oracle Attack

This module implements a padding oracle attack against AES-CBC mode.
It exploits the fact that CBC decryption reveals information about padding validity,
allowing an attacker to recover the plaintext byte by byte.
"""

import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import List, Optional, Tuple
import time


class PaddingOracleAttack:
    """Implements padding oracle attack against AES-CBC."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the padding oracle attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.block_size = 16  # AES block size
        
    def get_challenge_ciphertext(self, email: str) -> bytes:
        """
        Get the challenge ciphertext from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Ciphertext as bytes
        """
        url = f"{self.base_url}/cripto/padding-oracle/{email}/challenge"
        
        response = requests.get(url)
        ciphertext_b64 = response.text.strip()
        
        return base64.b64decode(ciphertext_b64)
    
    def test_decryption(self, email: str, ciphertext: bytes) -> str:
        """
        Test decryption with the server (padding oracle).
        
        Args:
            email: Email of the user operating the challenge
            ciphertext: Ciphertext to test
            
        Returns:
            Server response indicating padding validity
        """
        url = f"{self.base_url}/cripto/padding-oracle/{email}/decrypt"
        
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        data = {'message': ciphertext_b64}
        
        try:
            response = requests.post(url, data=data)
            
            if response.status_code == 200:
                return "OK"
            elif response.status_code == 400:
                return response.text.strip()
            else:
                return f"Unexpected status: {response.status_code}"
                
        except Exception as e:
            return f"Error: {e}"
    
    def submit_answer(self, email: str, decrypted_message: str) -> str:
        """
        Submit the decrypted message to the server.
        
        Args:
            email: Email of the user operating the challenge
            decrypted_message: The decrypted secret message
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/padding-oracle/{email}/answer"
        data = {'message': decrypted_message}
        
        response = requests.post(url, data=data)
        return response.text.strip()
    
    def split_into_blocks(self, data: bytes) -> List[bytes]:
        """
        Split data into AES blocks.
        
        Args:
            data: Data to split
            
        Returns:
            List of 16-byte blocks
        """
        return [data[i:i+self.block_size] for i in range(0, len(data), self.block_size)]
    
    def analyze_ciphertext(self, ciphertext: bytes) -> dict:
        """
        Analyze the ciphertext structure.
        
        Args:
            ciphertext: Ciphertext to analyze
            
        Returns:
            Analysis results
        """
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Split into blocks
        blocks = self.split_into_blocks(ciphertext)
        print(f"Number of blocks: {len(blocks)}")
        
        # First block is IV
        iv = blocks[0]
        ciphertext_blocks = blocks[1:]
        
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext blocks: {len(ciphertext_blocks)}")
        
        for i, block in enumerate(ciphertext_blocks):
            print(f"Block {i+1}: {block.hex()}")
        
        return {
            'iv': iv,
            'ciphertext_blocks': ciphertext_blocks,
            'total_blocks': len(blocks),
            'data_blocks': len(ciphertext_blocks)
        }
    
    def decrypt_block(self, email: str, target_block: bytes, previous_block: bytes) -> bytes:
        """
        Decrypt a single block using padding oracle attack.
        
        Args:
            email: Email of the user operating the challenge
            target_block: Block to decrypt
            previous_block: Previous block (for CBC chaining)
            
        Returns:
            Decrypted block
        """
        print(f"Decrypting block: {target_block.hex()}")
        
        # Create a test ciphertext with two blocks
        test_ciphertext = previous_block + target_block
        
        # Initialize decrypted block
        decrypted_block = bytearray(self.block_size)
        
        # Decrypt byte by byte, starting from the last byte
        for byte_pos in range(self.block_size - 1, -1, -1):
            print(f"Decrypting byte {byte_pos}...")
            
            # Create padding for current position
            padding_length = self.block_size - byte_pos
            
            # Modify previous block to create valid padding
            modified_previous = bytearray(previous_block)
            
            # Set padding bytes in the decrypted block
            for i in range(byte_pos + 1, self.block_size):
                modified_previous[i] = decrypted_block[i] ^ padding_length
            
            # Try all possible values for the current byte
            found_byte = None
            for byte_value in range(256):
                # Set the current byte
                modified_previous[byte_pos] = byte_value ^ padding_length
                
                # Test the modified ciphertext
                test_ciphertext_modified = bytes(modified_previous) + target_block
                result = self.test_decryption(email, test_ciphertext_modified)
                
                if result == "OK":
                    # Found the correct byte
                    found_byte = byte_value
                    print(f"Found byte {byte_pos}: {byte_value:02x} ('{chr(byte_value) if 32 <= byte_value <= 126 else '.'}')")
                    break
            
            if found_byte is None:
                raise ValueError(f"Could not decrypt byte {byte_pos}")
            
            decrypted_block[byte_pos] = found_byte
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.01)
        
        return bytes(decrypted_block)
    
    def decrypt_message(self, email: str, ciphertext: bytes) -> str:
        """
        Decrypt the entire message using padding oracle attack.
        
        Args:
            email: Email of the user operating the challenge
            ciphertext: Complete ciphertext (IV + encrypted data)
            
        Returns:
            Decrypted message
        """
        print(f"Starting padding oracle attack against {email}")
        
        # Analyze ciphertext structure
        analysis = self.analyze_ciphertext(ciphertext)
        
        iv = analysis['iv']
        ciphertext_blocks = analysis['ciphertext_blocks']
        
        print(f"Decrypting {len(ciphertext_blocks)} blocks...")
        
        decrypted_blocks = []
        
        # Decrypt each block
        for i, block in enumerate(ciphertext_blocks):
            print(f"\nDecrypting block {i+1}/{len(ciphertext_blocks)}...")
            
            # Use IV for first block, previous ciphertext block for others
            if i == 0:
                previous_block = iv
            else:
                previous_block = ciphertext_blocks[i-1]
            
            # Decrypt the block
            decrypted_block = self.decrypt_block(email, block, previous_block)
            decrypted_blocks.append(decrypted_block)
            
            print(f"Block {i+1} decrypted: {decrypted_block.hex()}")
        
        # Combine all decrypted blocks
        decrypted_data = b''.join(decrypted_blocks)
        
        # Remove PKCS7 padding
        try:
            decrypted_message = unpad(decrypted_data, self.block_size)
            return decrypted_message.decode('utf-8')
        except Exception as e:
            print(f"Error removing padding: {e}")
            return decrypted_data.decode('utf-8', errors='ignore')
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete padding oracle attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        try:
            # Step 1: Get challenge ciphertext
            print("Step 1: Getting challenge ciphertext...")
            ciphertext = self.get_challenge_ciphertext(email)
            print(f"Ciphertext obtained: {len(ciphertext)} bytes")
            
            # Step 2: Decrypt the message
            print("\nStep 2: Decrypting message using padding oracle...")
            decrypted_message = self.decrypt_message(email, ciphertext)
            
            print(f"\nDecrypted message: {decrypted_message}")
            
            # Step 3: Submit answer
            print("\nStep 3: Submitting answer...")
            result = self.submit_answer(email, decrypted_message)
            
            return result
            
        except Exception as e:
            error_msg = f"Error in attack: {e}"
            print(error_msg)
            return error_msg


class PaddingOracleSimulator:
    """Simulates the padding oracle for testing purposes."""
    
    def __init__(self, secret_key: bytes = b"test_key_16_bytes"):
        """
        Initialize the padding oracle simulator.
        
        Args:
            secret_key: The secret key for decryption
        """
        self.secret_key = secret_key
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Encrypt a message using AES-CBC.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Encrypted message with IV prepended
        """
        # Generate random IV
        import os
        iv = os.urandom(16)
        
        # Apply PKCS7 padding
        padded_plaintext = pad(plaintext.encode('utf-8'), 16)
        
        # Encrypt with AES-CBC
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        # Prepend IV
        return iv + ciphertext
    
    def test_decryption(self, ciphertext: bytes) -> str:
        """
        Test decryption and return padding validity.
        
        Args:
            ciphertext: Ciphertext to test
            
        Returns:
            "OK" if padding is valid, "Bad padding bytes" if invalid
        """
        try:
            # Extract IV and ciphertext
            iv = ciphertext[:16]
            encrypted_data = ciphertext[16:]
            
            # Check if length is multiple of block size
            if len(encrypted_data) % 16 != 0:
                return "Bad padding bytes"
            
            # Decrypt
            cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_data)
            
            # Check padding validity
            try:
                unpad(decrypted, 16)
                return "OK"
            except ValueError:
                return "Bad padding bytes"
                
        except Exception:
            return "Bad padding bytes"
    
    def decrypt_message(self, ciphertext: bytes) -> str:
        """
        Decrypt a message for verification.
        
        Args:
            ciphertext: Ciphertext to decrypt
            
        Returns:
            Decrypted message
        """
        # Extract IV and ciphertext
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        # Decrypt
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove padding
        unpadded = unpad(decrypted, 16)
        
        return unpadded.decode('utf-8')


def main():
    """Main function to demonstrate the padding oracle attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = PaddingOracleAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nFinal result: {result}")


if __name__ == "__main__":
    main()
