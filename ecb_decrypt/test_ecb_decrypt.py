#!/usr/bin/env python3
"""
Test cases for ECB Decryption Attack

This module contains test cases to validate the ECB decryption attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecb_decrypt_attack import ECBDecryptAttack, ECBOracle


class TestECBDecryptAttack(unittest.TestCase):
    """Test cases for ECBDecryptAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = ECBDecryptAttack()
        self.challenge_email = "user@example.com"
    
    def test_split_into_blocks(self):
        """Test block splitting functionality."""
        test_data = b"This is a test message that should be split into blocks"
        blocks = self.attack.split_into_blocks(test_data)
        
        # Each block should be 16 bytes
        for block in blocks:
            self.assertLessEqual(len(block), 16)
        
        # Should have correct number of blocks
        expected_blocks = (len(test_data) + 15) // 16
        self.assertEqual(len(blocks), expected_blocks)
    
    def test_split_into_blocks_exact_multiple(self):
        """Test block splitting with exact multiple of block size."""
        test_data = b"A" * 32  # Exactly 2 blocks
        blocks = self.attack.split_into_blocks(test_data)
        
        self.assertEqual(len(blocks), 2)
        self.assertEqual(len(blocks[0]), 16)
        self.assertEqual(len(blocks[1]), 16)
    
    @patch('ecb_decrypt_attack.requests.post')
    def test_encrypt_message(self, mock_post):
        """Test message encryption request."""
        mock_response = MagicMock()
        mock_response.text = "encrypted_base64_data"
        mock_post.return_value = mock_response
        
        result = self.attack.encrypt_message(self.challenge_email, "test message")
        
        self.assertEqual(result, "encrypted_base64_data")
        mock_post.assert_called_once()
        
        # Check that message was base64 encoded
        call_args = mock_post.call_args
        self.assertIn('message', call_args[1]['data'])
        
        # Verify base64 encoding
        encoded_message = call_args[1]['data']['message']
        try:
            decoded = base64.b64decode(encoded_message)
            self.assertEqual(decoded.decode('utf-8'), "test message")
        except Exception:
            self.fail("Message should be valid base64")
    
    @patch('ecb_decrypt_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        decrypted_message = "This is the secret message"
        result = self.attack.submit_answer(self.challenge_email, decrypted_message)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_determine_secret_length(self):
        """Test secret length determination."""
        # Create a mock oracle for testing
        oracle = ECBOracle("Secret message")
        
        with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
            # Mock responses for different message lengths
            def mock_encrypt_side_effect(email, message):
                return oracle.encrypt(message)
            
            mock_encrypt.side_effect = mock_encrypt_side_effect
            
            secret_length = self.attack.determine_secret_length(self.challenge_email)
            
            # Should detect the secret length
            self.assertGreater(secret_length, 0)
    
    def test_decrypt_byte_by_byte_single_block(self):
        """Test byte-by-byte decryption for single block secret."""
        secret_message = "Secret"
        oracle = ECBOracle(secret_message)
        
        with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
            def mock_encrypt_side_effect(email, message):
                return oracle.encrypt(message)
            
            mock_encrypt.side_effect = mock_encrypt_side_effect
            
            decrypted = self.attack.decrypt_byte_by_byte(self.challenge_email, len(secret_message))
            
            # Should decrypt the secret message
            self.assertEqual(decrypted, secret_message)
    
    def test_decrypt_byte_by_byte_multi_block(self):
        """Test byte-by-byte decryption for multi-block secret."""
        secret_message = "This is a longer secret message that spans multiple blocks"
        oracle = ECBOracle(secret_message)
        
        with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
            def mock_encrypt_side_effect(email, message):
                return oracle.encrypt(message)
            
            mock_encrypt.side_effect = mock_encrypt_side_effect
            
            decrypted = self.attack.decrypt_byte_by_byte(self.challenge_email, len(secret_message))
            
            # Should decrypt the secret message
            self.assertEqual(decrypted, secret_message)
    
    @patch('ecb_decrypt_attack.ECBDecryptAttack.determine_secret_length')
    @patch('ecb_decrypt_attack.ECBDecryptAttack.decrypt_byte_by_byte')
    @patch('ecb_decrypt_attack.ECBDecryptAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_decrypt, mock_length):
        """Test successful attack execution."""
        mock_length.return_value = 6
        mock_decrypt.return_value = "Secret"
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_length.assert_called_once_with(self.challenge_email)
        mock_decrypt.assert_called_once_with(self.challenge_email, 6)
        mock_submit.assert_called_once_with(self.challenge_email, "Secret")
    
    @patch('ecb_decrypt_attack.ECBDecryptAttack.determine_secret_length')
    def test_execute_attack_length_error(self, mock_length):
        """Test attack execution when length determination fails."""
        mock_length.return_value = 0
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("longitud", result)
    
    @patch('ecb_decrypt_attack.ECBDecryptAttack.determine_secret_length')
    @patch('ecb_decrypt_attack.ECBDecryptAttack.decrypt_byte_by_byte')
    def test_execute_attack_decrypt_error(self, mock_decrypt, mock_length):
        """Test attack execution when decryption fails."""
        mock_length.return_value = 6
        mock_decrypt.return_value = ""
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("descifrar", result)


class TestECBOracle(unittest.TestCase):
    """Test cases for ECBOracle class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.secret_message = "Secret message"
        self.oracle = ECBOracle(self.secret_message)
    
    def test_encrypt_basic(self):
        """Test basic encryption functionality."""
        user_message = "Hello"
        encrypted = self.oracle.encrypt(user_message)
        
        # Should return base64 encoded string
        self.assertIsInstance(encrypted, str)
        
        # Should be valid base64
        try:
            decoded = base64.b64decode(encrypted)
            self.assertIsInstance(decoded, bytes)
        except Exception:
            self.fail("Encrypted result should be valid base64")
    
    def test_encrypt_deterministic(self):
        """Test that same input produces same output."""
        user_message = "Test message"
        
        encrypted1 = self.oracle.encrypt(user_message)
        encrypted2 = self.oracle.encrypt(user_message)
        
        # Should be deterministic
        self.assertEqual(encrypted1, encrypted2)
    
    def test_encrypt_different_inputs(self):
        """Test that different inputs produce different outputs."""
        encrypted1 = self.oracle.encrypt("Message 1")
        encrypted2 = self.oracle.encrypt("Message 2")
        
        # Should be different
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_encrypt_block_alignment(self):
        """Test block alignment for different message lengths."""
        # Test messages of different lengths
        for length in range(1, 33):
            message = "A" * length
            encrypted = self.oracle.encrypt(message)
            
            # Decode and check block alignment
            encrypted_bytes = base64.b64decode(encrypted)
            
            # Should be multiple of 16 bytes
            self.assertEqual(len(encrypted_bytes) % 16, 0)
    
    def test_encrypt_secret_concatenation(self):
        """Test that secret message is properly concatenated."""
        user_message = "User"
        encrypted = self.oracle.encrypt(user_message)
        
        # Decrypt to verify concatenation
        encrypted_bytes = base64.b64decode(encrypted)
        cipher = AES.new(self.oracle.key, AES.MODE_ECB)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        # Remove padding
        from Crypto.Util.Padding import unpad
        decrypted = unpad(decrypted_padded, 16).decode('utf-8')
        
        # Should contain both user message and secret
        self.assertIn(user_message, decrypted)
        self.assertIn(self.secret_message, decrypted)
        self.assertEqual(decrypted, user_message + self.secret_message)


class TestECBAttackIntegration(unittest.TestCase):
    """Integration tests for ECB attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = ECBDecryptAttack()
    
    def test_full_attack_simulation(self):
        """Test complete attack simulation."""
        secret_message = "The secret is revealed!"
        oracle = ECBOracle(secret_message)
        
        with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
            def mock_encrypt_side_effect(email, message):
                return oracle.encrypt(message)
            
            mock_encrypt.side_effect = mock_encrypt_side_effect
            
            # Determine secret length
            secret_length = self.attack.determine_secret_length("test@example.com")
            
            # Should detect correct length
            self.assertEqual(secret_length, len(secret_message))
            
            # Decrypt byte by byte
            decrypted = self.attack.decrypt_byte_by_byte("test@example.com", secret_length)
            
            # Should decrypt correctly
            self.assertEqual(decrypted, secret_message)
    
    def test_block_boundary_detection(self):
        """Test detection of block boundaries."""
        # Test with different secret lengths that cross block boundaries
        test_cases = [
            "A",  # 1 byte
            "AB",  # 2 bytes
            "ABCDEFGHIJKLMNOP",  # Exactly 16 bytes
            "ABCDEFGHIJKLMNOPQ",  # 17 bytes (crosses boundary)
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",  # 26 bytes
        ]
        
        for secret in test_cases:
            oracle = ECBOracle(secret)
            
            with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
                def mock_encrypt_side_effect(email, message):
                    return oracle.encrypt(message)
                
                mock_encrypt.side_effect = mock_encrypt_side_effect
                
                # Determine length
                detected_length = self.attack.determine_secret_length("test@example.com")
                
                # Should detect correct length
                self.assertEqual(detected_length, len(secret), 
                               f"Failed for secret: {secret}")
    
    def test_byte_recovery_accuracy(self):
        """Test accuracy of byte recovery."""
        # Test with various byte values
        test_bytes = [0, 1, 127, 128, 255]
        
        for byte_val in test_bytes:
            secret = chr(byte_val)
            oracle = ECBOracle(secret)
            
            with patch.object(self.attack, 'encrypt_message') as mock_encrypt:
                def mock_encrypt_side_effect(email, message):
                    return oracle.encrypt(message)
                
                mock_encrypt.side_effect = mock_encrypt_side_effect
                
                # Decrypt single byte
                decrypted = self.attack.decrypt_byte_by_byte("test@example.com", 1)
                
                # Should recover correct byte
                self.assertEqual(decrypted, secret, 
                               f"Failed to recover byte {byte_val}")


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
