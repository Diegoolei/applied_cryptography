#!/usr/bin/env python3
"""
ECB Forgery Attack Implementation

This module implements the complete ECB forgery attack for the cybersecurity challenge.
It demonstrates how to exploit the malleability of ECB mode to forge messages with admin privileges.
"""

import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import re
from urllib.parse import quote
from typing import Tuple, Optional, List


class ECBForgeAttack:
    """Implements ECB forgery attack for the cybersecurity challenge."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the ECB forge attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        
    def get_profile(self, email: str, target_email: str, encrypted: bool = False) -> str:
        """
        Get user profile from the server.
        
        Args:
            email: Email of the user operating the challenge
            target_email: Email to register
            encrypted: If True, returns encrypted profile
            
        Returns:
            Profile in plain text or base64 encoded encrypted
        """
        url = f"{self.base_url}/cripto/ecb-forge/{email}/register"
        params = {'email': target_email}
        
        if encrypted:
            params['encrypted'] = 'true'
        
        response = requests.get(url, params=params)
        return response.text.strip()
    
    def submit_answer(self, email: str, encrypted_message: str) -> str:
        """
        Submit answer to the server.
        
        Args:
            email: Email of the user operating the challenge
            encrypted_message: Encrypted message in base64
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/ecb-forge/{email}/answer"
        data = {'message': encrypted_message}
        
        response = requests.post(url, data=data)
        return response.text.strip()
    
    def split_into_blocks(self, data: bytes, block_size: int = 16) -> List[bytes]:
        """
        Split data into blocks of specified size.
        
        Args:
            data: Data to split
            block_size: Block size in bytes
            
        Returns:
            List of blocks
        """
        return [data[i:i+block_size] for i in range(0, len(data), block_size)]
    
    def analyze_profile_structure(self, profile: str) -> List[bytes]:
        """
        Analyze profile structure and show block division.
        
        Args:
            profile: Profile in plain text
            
        Returns:
            List of blocks
        """
        print(f"Perfil: {profile}")
        print(f"Longitud: {len(profile)} bytes")
        
        profile_bytes = profile.encode('utf-8')
        blocks = self.split_into_blocks(profile_bytes)
        
        print(f"\nBloques (16 bytes cada uno):")
        for i, block in enumerate(blocks):
            print(f"Bloque {i}: {block.hex()} -> '{block.decode('utf-8', errors='ignore')}'")
        
        return blocks
    
    def find_admin_block_email(self, challenge_email: str) -> Tuple[Optional[str], Optional[int]]:
        """
        Find email that generates a block containing 'role=admin'.
        
        Args:
            challenge_email: Email of the user operating the challenge
            
        Returns:
            Tuple of (admin_email, admin_block_index) or (None, None) if not found
        """
        print("Buscando email que genere bloque con role=admin...")
        
        # Test different email lengths
        for length in range(6, 25):
            test_email = "a@b.co" + "x" * (length - 6)
            try:
                profile = self.get_profile(challenge_email, test_email)
                blocks = self.split_into_blocks(profile.encode('utf-8'))
                
                # Look for block containing 'role=admin'
                for i, block in enumerate(blocks):
                    if b'role=admin' in block:
                        print(f"Encontrado: {test_email} genera bloque {i} con role=admin")
                        return test_email, i
                        
            except Exception as e:
                print(f"Error probando {test_email}: {e}")
                continue
        
        return None, None
    
    def forge_message(self, challenge_email: str, target_email: str) -> str:
        """
        Forge a message with admin role.
        
        Args:
            challenge_email: Email of the user operating the challenge
            target_email: Target email for the forged message
            
        Returns:
            Forged encrypted message in base64
            
        Raises:
            ValueError: If admin block cannot be found
        """
        print(f"Iniciando ataque ECB contra {challenge_email} con email objetivo {target_email}")
        
        # Step 1: Find email that generates admin block
        admin_email, admin_block_index = self.find_admin_block_email(challenge_email)
        if not admin_email:
            raise ValueError("No se pudo encontrar email que genere bloque con role=admin")
        
        # Step 2: Get target profile
        print(f"\nObteniendo perfil objetivo para {target_email}...")
        target_profile = self.get_profile(challenge_email, target_email)
        target_blocks = self.split_into_blocks(target_profile.encode('utf-8'))
        
        print(f"Perfil objetivo: {target_profile}")
        print(f"Bloques objetivo: {len(target_blocks)}")
        
        # Step 3: Get encrypted versions
        print(f"\nObteniendo versiones cifradas...")
        target_encrypted = self.get_profile(challenge_email, target_email, encrypted=True)
        target_encrypted_bytes = base64.b64decode(target_encrypted)
        target_encrypted_blocks = self.split_into_blocks(target_encrypted_bytes)
        
        admin_encrypted = self.get_profile(challenge_email, admin_email, encrypted=True)
        admin_encrypted_bytes = base64.b64decode(admin_encrypted)
        admin_encrypted_blocks = self.split_into_blocks(admin_encrypted_bytes)
        
        print(f"Bloques cifrados objetivo: {len(target_encrypted_blocks)}")
        print(f"Bloques cifrados admin: {len(admin_encrypted_blocks)}")
        
        # Step 4: Construct forged message
        print(f"\nConstruyendo mensaje falsificado...")
        
        # Take first blocks from target profile and replace last with admin block
        forged_encrypted_blocks = target_encrypted_blocks[:-1]
        forged_encrypted_blocks.append(admin_encrypted_blocks[admin_block_index])
        
        # Reconstruct encrypted message
        forged_encrypted = b''.join(forged_encrypted_blocks)
        forged_message = base64.b64encode(forged_encrypted).decode('utf-8')
        
        print(f"Mensaje falsificado: {forged_message}")
        
        return forged_message
    
    def execute_attack(self, challenge_email: str, target_email: str) -> str:
        """
        Execute the complete ECB forgery attack.
        
        Args:
            challenge_email: Email of the user operating the challenge
            target_email: Target email for the forged message
            
        Returns:
            Attack result
        """
        try:
            forged_message = self.forge_message(challenge_email, target_email)
            
            # Submit answer
            print(f"\nEnviando respuesta al servidor...")
            result = self.submit_answer(challenge_email, forged_message)
            
            return result
            
        except Exception as e:
            error_msg = f"Error en el ataque: {e}"
            print(error_msg)
            return error_msg


def main():
    """Main function to demonstrate the ECB forgery attack."""
    # Configuration
    challenge_email = "user@example.com"
    target_email = "usuario@ejemplo.edu.ar"
    
    # Create attack instance
    attack = ECBForgeAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email, target_email)
    
    print(f"\nResultado final: {result}")


if __name__ == "__main__":
    main()
