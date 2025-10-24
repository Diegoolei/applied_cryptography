#!/usr/bin/env python3
"""
Stream Cipher Keystream Recovery Attack

This module implements a keystream recovery attack against stream ciphers
that reuse the same keystream for multiple messages. It exploits the
mathematical properties of XOR and known plaintext characteristics to
recover the keystream and decrypt all messages.
"""

import requests
import base64
from typing import List, Optional, Tuple
import re
from collections import Counter


class StreamCipherAttack:
    """Implements stream cipher keystream recovery attack."""
    
    def __init__(self, base_url: str = "https://ciberseguridad.diplomatura.unc.edu.ar"):
        """
        Initialize the stream cipher attack.
        
        Args:
            base_url: Base URL of the challenge server
        """
        self.base_url = base_url
        
    def get_challenge_data(self, email: str) -> List[bytes]:
        """
        Get all challenge ciphertexts from the server.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            List of ciphertexts as bytes
        """
        url = f"{self.base_url}/cripto/stream/{email}/challenge"
        
        response = requests.get(url)
        lines = response.text.strip().split('\n')
        
        ciphertexts = []
        for line in lines:
            if line.strip():
                ciphertext = base64.b64decode(line.strip())
                ciphertexts.append(ciphertext)
        
        return ciphertexts
    
    def get_single_ciphertext(self, email: str, message_id: int) -> bytes:
        """
        Get a single ciphertext by ID.
        
        Args:
            email: Email of the user operating the challenge
            message_id: Message ID (0-4)
            
        Returns:
            Ciphertext as bytes
        """
        url = f"{self.base_url}/cripto/stream/{email}/challenge/{message_id}"
        
        response = requests.get(url)
        ciphertext = base64.b64decode(response.text.strip())
        
        return ciphertext
    
    def submit_answer(self, email: str, keystream: bytes) -> str:
        """
        Submit the recovered keystream to the server.
        
        Args:
            email: Email of the user operating the challenge
            keystream: Recovered keystream
            
        Returns:
            Server response
        """
        url = f"{self.base_url}/cripto/stream/{email}/answer"
        
        keystream_b64 = base64.b64encode(keystream).decode('utf-8')
        data = {'keystream': keystream_b64}
        
        response = requests.post(url, data=data)
        return response.text.strip()
    
    def analyze_ciphertexts(self, ciphertexts: List[bytes]) -> dict:
        """
        Analyze the ciphertexts to understand their structure.
        
        Args:
            ciphertexts: List of ciphertexts
            
        Returns:
            Analysis results
        """
        print("Analizando textos cifrados...")
        
        # Check lengths
        lengths = [len(ct) for ct in ciphertexts]
        print(f"Longitudes: {lengths}")
        
        # Check if all have same length
        if len(set(lengths)) == 1:
            print(f"Todos los textos tienen la misma longitud: {lengths[0]} bytes")
        else:
            print("Los textos tienen longitudes diferentes")
        
        # Analyze byte distributions
        for i, ct in enumerate(ciphertexts):
            byte_counts = Counter(ct)
            print(f"Texto {i}: {len(byte_counts)} bytes únicos, más común: {byte_counts.most_common(1)}")
        
        return {
            'lengths': lengths,
            'all_same_length': len(set(lengths)) == 1,
            'common_length': lengths[0] if len(set(lengths)) == 1 else None
        }
    
    def find_repeated_character_messages(self, ciphertexts: List[bytes]) -> List[int]:
        """
        Find messages that are likely repeated characters.
        
        Args:
            ciphertexts: List of ciphertexts
            
        Returns:
            List of message indices that are likely repeated characters
        """
        print("Buscando mensajes con caracteres repetidos...")
        
        repeated_indices = []
        
        for i, ct in enumerate(ciphertexts):
            # For repeated characters, the ciphertext should have low entropy
            # and many repeated byte values
            byte_counts = Counter(ct)
            
            # Calculate entropy (simplified)
            total_bytes = len(ct)
            entropy = 0
            for count in byte_counts.values():
                p = count / total_bytes
                if p > 0:
                    entropy -= p * (p.bit_length() - 1)  # Simplified entropy
            
            # Low entropy suggests repeated characters
            if entropy < 2.0:  # Threshold for repeated characters
                repeated_indices.append(i)
                print(f"Texto {i}: Entropía baja ({entropy:.2f}), probablemente caracteres repetidos")
        
        return repeated_indices
    
    def find_even_number_message(self, ciphertexts: List[bytes], keystream: bytes) -> Optional[int]:
        """
        Find the message that represents an even number.
        
        Args:
            ciphertexts: List of ciphertexts
            keystream: Recovered keystream
            
        Returns:
            Index of the even number message or None
        """
        print("Buscando mensaje que representa un número par...")
        
        for i, ct in enumerate(ciphertexts):
            # Decrypt the message
            decrypted = bytes(a ^ b for a, b in zip(ct, keystream))
            
            try:
                # Try to decode as ASCII
                text = decrypted.decode('ascii')
                
                # Check if it's all digits
                if text.isdigit():
                    # Check if it's even
                    number = int(text)
                    if number % 2 == 0:
                        print(f"Texto {i}: '{text}' es un número par")
                        return i
                    else:
                        print(f"Texto {i}: '{text}' es un número impar")
                else:
                    print(f"Texto {i}: '{text}' no es un número")
                    
            except UnicodeDecodeError:
                print(f"Texto {i}: No se puede decodificar como ASCII")
        
        return None
    
    def recover_keystream_from_repeated_chars(self, ciphertexts: List[bytes], repeated_indices: List[int]) -> bytes:
        """
        Recover keystream from repeated character messages.
        
        Args:
            ciphertexts: List of ciphertexts
            repeated_indices: Indices of repeated character messages
            
        Returns:
            Recovered keystream
        """
        print("Recuperando keystream desde mensajes con caracteres repetidos...")
        
        if len(repeated_indices) < 2:
            raise ValueError("Se necesitan al menos 2 mensajes con caracteres repetidos")
        
        # Get the first repeated character message
        ct1 = ciphertexts[repeated_indices[0]]
        ct2 = ciphertexts[repeated_indices[1]]
        
        # XOR the two ciphertexts
        # If both are repeated characters, XOR will give us the XOR of the characters
        xor_result = bytes(a ^ b for a, b in zip(ct1, ct2))
        
        print(f"XOR de los dos mensajes repetidos: {xor_result.hex()}")
        
        # The XOR result should be constant (same byte repeated)
        # This tells us the XOR of the two repeated characters
        if len(set(xor_result)) == 1:
            char_xor = xor_result[0]
            print(f"XOR constante: {char_xor:02x}")
            
            # Now we need to figure out what the actual characters are
            # We know they're printable ASCII (33-126)
            possible_chars = []
            
            for char1 in range(33, 127):
                char2 = char1 ^ char_xor
                if 33 <= char2 <= 126:
                    possible_chars.append((chr(char1), chr(char2)))
            
            print(f"Posibles pares de caracteres: {possible_chars}")
            
            # Try to determine which character is which
            # We can use the fact that one might be more common
            for char1, char2 in possible_chars:
                # Try both possibilities
                for first_char, second_char in [(char1, char2), (char2, char1)]:
                    keystream1 = bytes(a ^ ord(first_char) for a in ct1)
                    keystream2 = bytes(a ^ ord(second_char) for a in ct2)
                    
                    if keystream1 == keystream2:
                        print(f"Keystream encontrado con caracteres: '{first_char}' y '{second_char}'")
                        return keystream1
        
        raise ValueError("No se pudo recuperar el keystream desde los caracteres repetidos")
    
    def verify_keystream(self, ciphertexts: List[bytes], keystream: bytes) -> dict:
        """
        Verify the recovered keystream by decrypting all messages.
        
        Args:
            ciphertexts: List of ciphertexts
            keystream: Recovered keystream
            
        Returns:
            Verification results
        """
        print("Verificando keystream recuperado...")
        
        results = {
            'decrypted_messages': [],
            'valid_messages': 0,
            'repeated_char_messages': [],
            'even_number_message': None
        }
        
        for i, ct in enumerate(ciphertexts):
            # Decrypt the message
            decrypted = bytes(a ^ b for a, b in zip(ct, keystream))
            
            try:
                # Try to decode as ASCII
                text = decrypted.decode('ascii')
                results['decrypted_messages'].append(text)
                
                print(f"Texto {i}: '{text}'")
                
                # Check if it's valid (printable ASCII, no whitespace)
                if all(33 <= ord(c) <= 126 for c in text):
                    results['valid_messages'] += 1
                    
                    # Check if it's repeated characters
                    if len(set(text)) == 1:
                        results['repeated_char_messages'].append(i)
                        print(f"  -> Caracteres repetidos: '{text[0]}'")
                    
                    # Check if it's an even number
                    if text.isdigit() and int(text) % 2 == 0:
                        results['even_number_message'] = i
                        print(f"  -> Número par: {text}")
                
            except UnicodeDecodeError:
                print(f"Texto {i}: No se puede decodificar como ASCII")
                results['decrypted_messages'].append(None)
        
        return results
    
    def execute_attack(self, email: str) -> str:
        """
        Execute the complete stream cipher attack.
        
        Args:
            email: Email of the user operating the challenge
            
        Returns:
            Attack result
        """
        print(f"Iniciando ataque de cifrado de flujo contra {email}")
        
        try:
            # Step 1: Get challenge data
            print("\nPaso 1: Obteniendo datos del desafío...")
            ciphertexts = self.get_challenge_data(email)
            print(f"Obtenidos {len(ciphertexts)} textos cifrados")
            
            # Step 2: Analyze ciphertexts
            print("\nPaso 2: Analizando textos cifrados...")
            analysis = self.analyze_ciphertexts(ciphertexts)
            
            if not analysis['all_same_length']:
                return "Error: Los textos no tienen la misma longitud"
            
            # Step 3: Find repeated character messages
            print("\nPaso 3: Buscando mensajes con caracteres repetidos...")
            repeated_indices = self.find_repeated_character_messages(ciphertexts)
            
            if len(repeated_indices) < 2:
                return "Error: No se encontraron suficientes mensajes con caracteres repetidos"
            
            # Step 4: Recover keystream
            print("\nPaso 4: Recuperando keystream...")
            keystream = self.recover_keystream_from_repeated_chars(ciphertexts, repeated_indices)
            
            # Step 5: Verify keystream
            print("\nPaso 5: Verificando keystream...")
            verification = self.verify_keystream(ciphertexts, keystream)
            
            if verification['valid_messages'] < 3:
                return "Error: El keystream recuperado no es válido"
            
            # Step 6: Submit answer
            print("\nPaso 6: Enviando respuesta al servidor...")
            result = self.submit_answer(email, keystream)
            
            return result
            
        except Exception as e:
            error_msg = f"Error en el ataque: {e}"
            print(error_msg)
            return error_msg


class StreamCipherOracle:
    """Simulates the stream cipher oracle for testing purposes."""
    
    def __init__(self, keystream: bytes):
        """
        Initialize the stream cipher oracle.
        
        Args:
            keystream: The keystream to use for encryption
        """
        self.keystream = keystream
    
    def encrypt_message(self, plaintext: str) -> bytes:
        """
        Encrypt a message using the keystream.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Encrypted message
        """
        plaintext_bytes = plaintext.encode('ascii')
        
        # Repeat keystream if needed
        repeated_keystream = (self.keystream * ((len(plaintext_bytes) // len(self.keystream)) + 1))[:len(plaintext_bytes)]
        
        # XOR with keystream
        ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, repeated_keystream))
        
        return ciphertext
    
    def decrypt_message(self, ciphertext: bytes) -> str:
        """
        Decrypt a message using the keystream.
        
        Args:
            ciphertext: Message to decrypt
            
        Returns:
            Decrypted message
        """
        # Repeat keystream if needed
        repeated_keystream = (self.keystream * ((len(ciphertext) // len(self.keystream)) + 1))[:len(ciphertext)]
        
        # XOR with keystream
        plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, repeated_keystream))
        
        return plaintext_bytes.decode('ascii')


def main():
    """Main function to demonstrate the stream cipher attack."""
    # Configuration
    challenge_email = "user@example.com"
    
    # Create attack instance
    attack = StreamCipherAttack()
    
    # Execute attack
    result = attack.execute_attack(challenge_email)
    
    print(f"\nResultado final: {result}")


if __name__ == "__main__":
    main()
