#!/usr/bin/env python3
"""
Stream Cipher Bit Flipping Attack

This module implements a bit flipping attack against stream ciphers.
It exploits the malleability of stream ciphers to modify ciphertext bits
and achieve predictable changes in the decrypted plaintext.
"""

import requests
import base64
from typing import List, Optional, Tuple
import time


class StreamBitFlipAttack:
    """Implements stream cipher bit flipping attack."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the stream bit flip attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        
    def register_user(self, challenge_email: str, user_email: str, data: str) -> str:
        """
        Register a user and get encrypted profile.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            data: User data (will be base64 encoded)
            
        Returns:
            Encrypted profile with nonce (base64 encoded)
        """
        url = f"{self.base_url}/cripto/stream-bitflip/{challenge_email}/register"
        
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
        url = f"{self.base_url}/cripto/stream-bitflip/{challenge_email}/answer"
        data = {'message': encrypted_message}
        
        response = requests.post(url, data=data)
        return response.text.strip()
    
    def analyze_profile_structure(self, profile: str) -> dict:
        """
        Analyze the profile structure and find key positions.
        
        Args:
            profile: Profile in plain text
            
        Returns:
            Analysis results
        """
        print(f"Perfil: {profile}")
        print(f"Longitud: {len(profile)} bytes")
        
        # Split into attribute-value pairs
        pairs = profile.split(';')
        print(f"Pares atributo-valor: {len(pairs)}")
        
        for i, pair in enumerate(pairs):
            print(f"  {i}: {pair}")
        
        # Find the role field
        role_start = profile.find('role=')
        if role_start != -1:
            role_end = profile.find(';', role_start)
            if role_end == -1:
                role_end = len(profile)
            role_field = profile[role_start:role_end]
            print(f"Campo role encontrado en posición {role_start}: '{role_field}'")
            
            return {
                'profile': profile,
                'pairs': pairs,
                'role_start': role_start,
                'role_end': role_end,
                'role_field': role_field,
                'role_length': len(role_field)
            }
        else:
            print("Campo 'role=' no encontrado")
            return {
                'profile': profile,
                'pairs': pairs,
                'role_start': -1,
                'role_end': -1,
                'role_field': None,
                'role_length': 0
            }
    
    def calculate_bit_flip(self, original_text: str, target_text: str) -> bytes:
        """
        Calculate the bit flip mask needed to change original_text to target_text.
        
        Args:
            original_text: Original text to change
            target_text: Target text
            
        Returns:
            Bit flip mask as bytes
        """
        # Convert strings to bytes
        original_bytes = original_text.encode('utf-8')
        target_bytes = target_text.encode('utf-8')
        
        # Ensure same length
        if len(original_bytes) != len(target_bytes):
            raise ValueError(f"Los textos deben tener la misma longitud: {len(original_bytes)} vs {len(target_bytes)}")
        
        # Calculate XOR mask
        mask = bytes(a ^ b for a, b in zip(original_bytes, target_bytes))
        
        print(f"Texto original: '{original_text}' -> {original_bytes.hex()}")
        print(f"Texto objetivo: '{target_text}' -> {target_bytes.hex()}")
        print(f"Máscara XOR: {mask.hex()}")
        
        return mask
    
    def apply_bit_flip(self, ciphertext: bytes, mask: bytes, position: int) -> bytes:
        """
        Apply bit flip mask to ciphertext at specified position.
        
        Args:
            ciphertext: Original ciphertext
            mask: Bit flip mask
            position: Position to apply the mask
            
        Returns:
            Modified ciphertext
        """
        if position + len(mask) > len(ciphertext):
            raise ValueError(f"La máscara excede la longitud del texto cifrado")
        
        # Create modified ciphertext
        modified_ciphertext = bytearray(ciphertext)
        
        # Apply mask at specified position
        for i in range(len(mask)):
            modified_ciphertext[position + i] ^= mask[i]
        
        print(f"Aplicando máscara {mask.hex()} en posición {position}")
        print(f"Texto cifrado original: {ciphertext.hex()}")
        print(f"Texto cifrado modificado: {bytes(modified_ciphertext).hex()}")
        
        return bytes(modified_ciphertext)
    
    def create_bit_flip_attack(self, challenge_email: str, user_email: str) -> str:
        """
        Create a bit flip attack to change role=user to role=admin.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            
        Returns:
            Modified encrypted message (base64 encoded)
        """
        print(f"Iniciando ataque de cambio de bits en cifrado de flujo contra {challenge_email}")
        
        # Step 1: Register user with controlled data
        print("\nPaso 1: Registrando usuario con datos controlados...")
        
        # Use simple data to start
        test_data = "TestData"
        encrypted_response = self.register_user(challenge_email, user_email, test_data)
        
        print(f"Respuesta cifrada: {encrypted_response}")
        
        # Decode the encrypted response
        encrypted_bytes = base64.b64decode(encrypted_response)
        
        # Extract nonce (first 16 bytes) and ciphertext
        nonce = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        print(f"Nonce: {nonce.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # Step 2: Analyze the profile structure
        print("\nPaso 2: Analizando estructura del perfil...")
        
        # For this attack, we need to understand where 'role=user' appears
        # We'll work with the assumption that the profile follows:
        # user=email;data=data;role=user
        
        # Step 3: Calculate the bit flip needed
        print("\nPaso 3: Calculando cambio de bits necesario...")
        
        # We want to change 'role=user' to 'role=admin'
        original_role = "role=user"
        target_role = "role=admin"
        
        # Calculate the XOR mask
        mask = self.calculate_bit_flip(original_role, target_role)
        
        # Step 4: Find the position of 'role=user' in the ciphertext
        print("\nPaso 4: Encontrando posición de 'role=user' en el texto cifrado...")
        
        # This is the tricky part - we need to figure out where 'role=user' appears
        # in the encrypted data. We can try different approaches:
        
        # Approach 1: Try to control the data field to align 'role=user' at a known position
        # Approach 2: Use the fact that we know the structure and try different positions
        
        # Let's try approach 1: control the data length to align blocks
        role_position = self.find_role_position(challenge_email, user_email, test_data)
        
        if role_position is None:
            raise ValueError("No se pudo encontrar la posición de 'role=user'")
        
        print(f"Posición de 'role=user' encontrada: {role_position}")
        
        # Step 5: Apply the bit flip
        print("\nPaso 5: Aplicando cambio de bits...")
        
        modified_ciphertext = self.apply_bit_flip(ciphertext, mask, role_position)
        
        # Step 6: Reconstruct the modified message
        modified_message = nonce + modified_ciphertext
        modified_b64 = base64.b64encode(modified_message).decode('utf-8')
        
        print(f"Mensaje modificado: {modified_b64}")
        
        return modified_b64
    
    def find_role_position(self, challenge_email: str, user_email: str, test_data: str) -> Optional[int]:
        """
        Find the position of 'role=user' in the ciphertext.
        
        Args:
            challenge_email: Email of the user operating the challenge
            user_email: Email to register
            test_data: Test data to use
            
        Returns:
            Position of 'role=user' or None if not found
        """
        print("Buscando posición de 'role=user'...")
        
        # Try different data lengths to control the profile structure
        for data_length in range(1, 50):
            test_data_controlled = "A" * data_length
            
            try:
                encrypted_response = self.register_user(challenge_email, user_email, test_data_controlled)
                encrypted_bytes = base64.b64decode(encrypted_response)
                ciphertext = encrypted_bytes[16:]  # Skip nonce
                
                # Calculate expected profile
                expected_profile = f"user={user_email};data={test_data_controlled};role=user"
                role_start = expected_profile.find('role=')
                
                if role_start != -1:
                    print(f"Data length {data_length}: Expected 'role=' at position {role_start}")
                    
                    # For stream ciphers, the position in ciphertext should match
                    # the position in plaintext (assuming the nonce is prepended)
                    if role_start < len(ciphertext):
                        return role_start
                
            except Exception as e:
                print(f"Error con data length {data_length}: {e}")
                continue
        
        return None
    
    def execute_attack(self, challenge_email: str, user_email: str) -> str:
        """
        Execute the complete stream cipher bit flipping attack.
        
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


class StreamBitFlipOracle:
    """Simulates the stream cipher bit flip oracle for testing purposes."""
    
    def __init__(self, secret_key: bytes = b"test_key_16_bytes"):
        """
        Initialize the stream cipher oracle.
        
        Args:
            secret_key: The secret key for encryption
        """
        self.secret_key = secret_key
    
    def encrypt_profile(self, user_email: str, data: str, nonce: bytes = None) -> str:
        """
        Simulate the server's profile encryption process.
        
        Args:
            user_email: User's email
            data: User's data
            nonce: Nonce to use (if None, generates random)
            
        Returns:
            Encrypted profile with nonce (base64 encoded)
        """
        # Create profile
        profile = f"user={user_email};data={data};role=user"
        
        # Generate random nonce if not provided
        if nonce is None:
            import os
            nonce = os.urandom(16)
        
        # Simple stream cipher simulation (XOR with repeated key)
        profile_bytes = profile.encode('utf-8')
        
        # Create keystream by repeating the key
        keystream = (self.secret_key * ((len(profile_bytes) // len(self.secret_key)) + 1))[:len(profile_bytes)]
        
        # Encrypt by XORing with keystream
        encrypted = bytes(a ^ b for a, b in zip(profile_bytes, keystream))
        
        # Concatenate nonce and ciphertext
        result = nonce + encrypted
        
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
        
        # Extract nonce and ciphertext
        nonce = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Create keystream
        keystream = (self.secret_key * ((len(ciphertext) // len(self.secret_key)) + 1))[:len(ciphertext)]
        
        # Decrypt by XORing with keystream
        decrypted = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        
        return decrypted.decode('utf-8')


def main():
    """Main function to demonstrate the stream cipher bit flipping attack."""
    # Configuration
    challenge_email = "user@example.com"
    user_email = "juan@hotmail.com"
    
    # Create attack instance
    attack = StreamBitFlipAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email, user_email)
    
    print(f"\nResultado final: {result}")


if __name__ == "__main__":
    main()
