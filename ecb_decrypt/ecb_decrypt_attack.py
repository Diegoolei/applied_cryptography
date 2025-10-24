#!/usr/bin/env python3
"""
ECB Byte-by-Byte Decryption Attack

This module implements a byte-by-byte decryption attack against AES-ECB mode.
It exploits the deterministic nature of ECB mode to recover a secret message
by analyzing encrypted responses to controlled inputs.
"""

import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import List, Optional, Tuple
import time


class ECBDecryptAttack:
    """Implements ECB byte-by-byte decryption attack."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the ECB decrypt attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.block_size = 16  # AES block size
        
    def encrypt_message(self, email: str, message: str) -> str:
        """
        Send a message to the server for encryption.
        
        Args:
            email: Email of the user operating the challenge
            message: Message to encrypt (will be base64 encoded)
            
        Returns:
            Encrypted response from server
        """
        url = f"{self.base_url}/cripto/ecb-decrypt/{email}/encrypt"
        
        # Encode message to base64
        message_b64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
        
        data = {'message': message_b64}
        response = requests.post(url, data=data)
        
        return response.text.strip()
    
    def submit_answer(self, email: str, decrypted_message: str) -> str:
        """
        Submit the decrypted message to the server.
        
        Args:
            email: Email of the user operating the challenge
            decrypted_message: The decrypted secret message
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/ecb-decrypt/{email}/answer"
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
    
    def determine_secret_length(self, email: str) -> int:
        """
        Determine the length of the secret message.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Length of the secret message
        """
        print("Determinando longitud del mensaje secreto...")
        
        # Test different message lengths
        for length in range(0, 33):  # Test up to 32 bytes
            test_message = "A" * length
            encrypted_response = self.encrypt_message(email, test_message)
            
            # Decode the encrypted response
            encrypted_bytes = base64.b64decode(encrypted_response)
            encrypted_blocks = self.split_into_blocks(encrypted_bytes)
            
            print(f"Longitud {length}: {len(encrypted_blocks)} bloques")
            
            # If we have more than 1 block, we've found the secret length
            if len(encrypted_blocks) > 1:
                # Calculate secret length
                # Total length = our_message + secret + padding
                # We know our_message length and can calculate padding
                total_length = len(encrypted_bytes)
                padding_length = self.block_size - (total_length % self.block_size)
                if padding_length == self.block_size:
                    padding_length = 0
                
                secret_length = total_length - length - padding_length
                print(f"Mensaje secreto tiene aproximadamente {secret_length} bytes")
                return secret_length
        
        return 0
    
    def decrypt_byte_by_byte(self, email: str, secret_length: int) -> str:
        """
        Decrypt the secret message byte by byte.
        
        Args:
            email: Email of the user operating the challenge
            secret_length: Length of the secret message
            
        Returns:
            Decrypted secret message
        """
        print(f"Iniciando descifrado byte por byte de {secret_length} bytes...")
        
        decrypted_secret = ""
        
        for byte_position in range(secret_length):
            print(f"Descifrando byte {byte_position + 1}/{secret_length}...")
            
            # Create a message that aligns the unknown byte at the end of a block
            # We need 15 known bytes + 1 unknown byte in the first block
            known_bytes = "A" * (15 - (byte_position % self.block_size))
            
            # If we're starting a new block, we need to account for previous bytes
            if byte_position > 0 and byte_position % self.block_size == 0:
                # We're starting a new block, so we need to shift our known bytes
                known_bytes = "A" * 15
            
            # Get the target block (the one containing our unknown byte)
            target_block_index = byte_position // self.block_size
            
            # Create a message that puts our unknown byte at the end of the target block
            padding_length = (self.block_size - 1) - (byte_position % self.block_size)
            test_message = known_bytes + "B" * padding_length
            
            # Get encrypted response
            encrypted_response = self.encrypt_message(email, test_message)
            encrypted_bytes = base64.b64decode(encrypted_response)
            encrypted_blocks = self.split_into_blocks(encrypted_bytes)
            
            # Get the target block
            target_block = encrypted_blocks[target_block_index]
            
            # Now try all possible bytes for the unknown position
            found_byte = None
            for byte_value in range(256):
                # Create a message with the known bytes + the byte we're testing
                test_byte = chr(byte_value)
                test_message_with_byte = known_bytes + test_byte
                
                # Get encrypted response
                encrypted_response_test = self.encrypt_message(email, test_message_with_byte)
                encrypted_bytes_test = base64.b64decode(encrypted_response_test)
                encrypted_blocks_test = self.split_into_blocks(encrypted_bytes_test)
                
                # Check if the target block matches
                if encrypted_blocks_test[target_block_index] == target_block:
                    found_byte = test_byte
                    break
            
            if found_byte:
                decrypted_secret += found_byte
                print(f"Byte {byte_position + 1}: '{found_byte}' (ASCII: {ord(found_byte)})")
            else:
                print(f"No se pudo encontrar el byte {byte_position + 1}")
                break
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        return decrypted_secret
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete ECB decryption attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        print(f"Iniciando ataque ECB de descifrado contra {email}")
        
        try:
            # Step 1: Determine secret length
            secret_length = self.determine_secret_length(email)
            if secret_length == 0:
                return "Error: No se pudo determinar la longitud del mensaje secreto"
            
            # Step 2: Decrypt byte by byte
            decrypted_secret = self.decrypt_byte_by_byte(email, secret_length)
            
            if not decrypted_secret:
                return "Error: No se pudo descifrar el mensaje secreto"
            
            print(f"Mensaje secreto descifrado: {decrypted_secret}")
            
            # Step 3: Submit answer
            print("Enviando respuesta al servidor...")
            result = self.submit_answer(email, decrypted_secret)
            
            return result
            
        except Exception as e:
            error_msg = f"Error en el ataque: {e}"
            print(error_msg)
            return error_msg


class ECBOracle:
    """Simulates the ECB oracle for testing purposes."""
    
    def __init__(self, secret_message: str):
        """
        Initialize the ECB oracle.
        
        Args:
            secret_message: The secret message to encrypt
        """
        self.secret_message = secret_message
        self.key = b"test_key_16_bytes"  # 16-byte key for testing
    
    def encrypt(self, user_message: str) -> str:
        """
        Simulate the server's encryption process.
        
        Args:
            user_message: User's message
            
        Returns:
            Encrypted message in base64
        """
        # Concatenate user message with secret message
        full_message = user_message + self.secret_message
        
        # Apply PKCS7 padding
        padded_message = pad(full_message.encode('utf-8'), 16)
        
        # Encrypt with AES-ECB
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted = cipher.encrypt(padded_message)
        
        # Return base64 encoded
        return base64.b64encode(encrypted).decode('utf-8')


def main():
    """Main function to demonstrate the ECB decryption attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = ECBDecryptAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nResultado final: {result}")


if __name__ == "__main__":
    main()
