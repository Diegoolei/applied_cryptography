#!/usr/bin/env python3
"""
CBC Bit Flipping Attack

This module implements a bit flipping attack against AES-CBC mode.
It exploits the malleability of CBC mode to modify ciphertext blocks
and affect the decryption of subsequent blocks in a predictable way.
"""

import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import List, Optional, Tuple
import time


class CBCBitFlipAttack:
    """Implements CBC bit flipping attack."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the CBC bit flip attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        self.block_size = 16  # AES block size
        
    def register_user(self, challenge_email: str, user_email: str, data: str) -> str:
        """
        Register a user and get encrypted profile.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            data: User data (will be base64 encoded)
            
        Returns:
            Encrypted profile with IV (base64 encoded)
        """
        url = f"{self.base_url}/cripto/cbc-bitflip/{challenge_email}/register"
        
        # Encode data to base64
        data_b64 = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        
        form_data = {
            'email': user_email,
            'data': data_b64
        }
        
        response = requests.post(url, data=form_data)
        return response.text.strip()
    
    def submit_answer(self, challenge_email: str, encrypted_message: str) -> str:
        """
        Submit the modified encrypted message to the server.
        
        Args:
            challenge_email: Email of the user operating the challenge
            encrypted_message: Modified encrypted message (base64 encoded)
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/cbc-bitflip/{challenge_email}/answer"
        data = {'message': encrypted_message}
        
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
    
    def analyze_profile_structure(self, profile: str) -> dict:
        """
        Analyze the profile structure and block layout.
        
        Args:
            profile: Profile in plain text
            
        Returns:
            Dictionary with analysis information
        """
        print(f"Perfil: {profile}")
        print(f"Longitud: {len(profile)} bytes")
        
        # Split into attribute-value pairs
        pairs = profile.split(';')
        print(f"Pares atributo-valor: {len(pairs)}")
        
        for i, pair in enumerate(pairs):
            print(f"  {i}: {pair}")
        
        # Convert to bytes and analyze blocks
        profile_bytes = profile.encode('utf-8')
        blocks = self.split_into_blocks(profile_bytes)
        
        print(f"\nBloques (16 bytes cada uno):")
        for i, block in enumerate(blocks):
            print(f"Bloque {i}: {block.hex()} -> '{block.decode('utf-8', errors='ignore')}'")
        
        return {
            'profile': profile,
            'pairs': pairs,
            'blocks': blocks,
            'total_blocks': len(blocks)
        }
    
    def find_role_block(self, profile: str) -> Optional[int]:
        """
        Find which block contains the 'role=user' part.
        
        Args:
            profile: Profile in plain text
            
        Returns:
            Block index containing 'role=user' or None
        """
        profile_bytes = profile.encode('utf-8')
        blocks = self.split_into_blocks(profile_bytes)
        
        for i, block in enumerate(blocks):
            if b'role=user' in block:
                return i
        
        return None
    
    def calculate_bit_flip(self, target_block: bytes, desired_change: bytes) -> bytes:
        """
        Calculate the bit flip needed to achieve desired change.
        
        Args:
            target_block: The block we want to modify
            desired_change: The change we want to make
            
        Returns:
            The bit flip mask to apply
        """
        # CBC bit flipping: C[i] XOR delta = C'[i]
        # When decrypted: P[i+1] = D(C[i+1]) XOR C'[i]
        # So: P[i+1]' = P[i+1] XOR delta
        
        # We want to change 'role=user' to 'role=admin'
        # The change is: 'user' -> 'admin'
        # 'user' = 4 bytes, 'admin' = 5 bytes
        
        # For simplicity, we'll work with the assumption that
        # we can modify the previous block to affect the role block
        
        return bytes(a ^ b for a, b in zip(target_block, desired_change))
    
    def create_bit_flip_attack(self, challenge_email: str, user_email: str) -> str:
        """
        Create a bit flip attack to change role=user to role=admin.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            
        Returns:
            Modified encrypted message (base64 encoded)
        """
        print(f"Iniciando ataque CBC bit flipping contra {challenge_email}")
        
        # Step 1: Create a profile with controlled data
        # We need to control the data field to align blocks properly
        print("\nPaso 1: Creando perfil con datos controlados...")
        
        # Start with a simple data value
        test_data = "TestData"
        encrypted_response = self.register_user(challenge_email, user_email, test_data)
        
        print(f"Respuesta cifrada: {encrypted_response}")
        
        # Decode the encrypted response
        encrypted_bytes = base64.b64decode(encrypted_response)
        
        # Extract IV (first 16 bytes) and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        print(f"IV: {iv.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Split ciphertext into blocks
        ciphertext_blocks = self.split_into_blocks(ciphertext)
        print(f"Número de bloques de texto cifrado: {len(ciphertext_blocks)}")
        
        # Step 2: Analyze the profile structure
        print("\nPaso 2: Analizando estructura del perfil...")
        
        # We need to decrypt to understand the structure
        # For this attack, we'll work with the assumption that
        # the profile follows the pattern: user=email;data=data;role=user
        
        # Step 3: Calculate the bit flip
        print("\nPaso 3: Calculando bit flip necesario...")
        
        # We want to change 'role=user' to 'role=admin'
        # 'user' is 4 bytes, 'admin' is 5 bytes
        # This is tricky because the lengths are different
        
        # Let's try a different approach: modify the data field
        # to create a profile where we can flip bits more easily
        
        # Create data that will put 'role=' at the beginning of a block
        # and 'user' at the end of the previous block
        
        # Calculate the profile structure:
        # user=user_email;data=data;role=user
        # We need to control the data length to align blocks
        
        # Try different data lengths to find the right alignment
        for data_length in range(1, 17):
            test_data = "A" * data_length
            encrypted_response = self.register_user(challenge_email, user_email, test_data)
            
            encrypted_bytes = base64.b64decode(encrypted_response)
            ciphertext = encrypted_bytes[16:]
            ciphertext_blocks = self.split_into_blocks(ciphertext)
            
            print(f"Data length {data_length}: {len(ciphertext_blocks)} blocks")
            
            # For the attack, we'll modify the second-to-last block
            # to affect the last block (which should contain 'role=user')
            if len(ciphertext_blocks) >= 2:
                # Modify the second-to-last block
                modified_blocks = ciphertext_blocks.copy()
                
                # Create a bit flip mask
                # We want to change 'user' to 'admin'
                # But since lengths are different, we'll try to change 'user' to 'admi'
                # and hope the padding works out
                
                # Calculate the XOR mask
                original = b'user'
                target = b'admi'  # First 4 bytes of 'admin'
                
                # We need to modify the previous block to affect this block
                if len(modified_blocks) >= 2:
                    # Modify the second-to-last block
                    mask = bytes(a ^ b for a, b in zip(original, target))
                    
                    # Apply the mask to the second-to-last block
                    modified_blocks[-2] = bytes(a ^ b for a, b in zip(modified_blocks[-2], mask))
                    
                    # Reconstruct the modified ciphertext
                    modified_ciphertext = b''.join(modified_blocks)
                    modified_encrypted = iv + modified_ciphertext
                    
                    return base64.b64encode(modified_encrypted).decode('utf-8')
        
        # If we get here, the attack failed
        raise ValueError("No se pudo crear el ataque bit flipping")
    
    def execute_attack(self, challenge_email: str, user_email: str) -> str:
        """
        Execute the complete CBC bit flipping attack.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            
        Returns:
            Attack result
        """
        try:
            # Create the bit flip attack
            modified_message = self.create_bit_flip_attack(challenge_email, user_email)
            
            print(f"Mensaje modificado: {modified_message}")
            
            # Submit the modified message
            print("\nEnviando mensaje modificado al servidor...")
            result = self.submit_answer(challenge_email, modified_message)
            
            return result
            
        except Exception as e:
            error_msg = f"Error en el ataque: {e}"
            print(error_msg)
            return error_msg


class CBCBitFlipOracle:
    """Simulates the CBC bit flip oracle for testing purposes."""
    
    def __init__(self, secret_key: bytes = b"test_key_16_bytes"):
        """
        Initialize the CBC bit flip oracle.
        
        Args:
            secret_key: The secret key for encryption
        """
        self.secret_key = secret_key
    
    def encrypt_profile(self, user_email: str, data: str) -> str:
        """
        Simulate the server's profile encryption process.
        
        Args:
            user_email: User's email
            data: User's data
            
        Returns:
            Encrypted profile with IV (base64 encoded)
        """
        # Create profile
        profile = f"user={user_email};data={data};role=user"
        
        # Generate random IV
        import os
        iv = os.urandom(16)
        
        # Apply PKCS7 padding
        padded_profile = pad(profile.encode('utf-8'), 16)
        
        # Encrypt with AES-CBC
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_profile)
        
        # Concatenate IV and ciphertext
        result = iv + encrypted
        
        # Return base64 encoded
        return base64.b64encode(result).decode('utf-8')
    
    def decrypt_profile(self, encrypted_data: str) -> str:
        """
        Decrypt a profile for testing purposes.
        
        Args:
            encrypted_data: Base64 encoded encrypted profile
            
        Returns:
            Decrypted profile
        """
        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Decrypt with AES-CBC
        cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # Remove padding
        decrypted = unpad(decrypted_padded, 16)
        
        return decrypted.decode('utf-8')


def main():
    """Main function to demonstrate the CBC bit flipping attack."""
    # Configuration
    challenge_email = "user@example.com"
    user_email = "juan@hotmail.com"
    
    # Create attack instance
    attack = CBCBitFlipAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email, user_email)
    
    print(f"\nResultado final: {result}")


if __name__ == "__main__":
    main()
