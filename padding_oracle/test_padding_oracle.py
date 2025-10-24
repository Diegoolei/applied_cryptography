#!/usr/bin/env python3
"""
Test cases for Padding Oracle Attack

This module contains test cases to validate the padding oracle attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from padding_oracle_attack import PaddingOracleAttack, PaddingOracleSimulator


class TestPaddingOracleAttack(unittest.TestCase):
    """Test cases for PaddingOracleAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = PaddingOracleAttack()
        self.challenge_email = "user@example.com"
    
    @patch('padding_oracle_attack.requests.get')
    def test_get_challenge_ciphertext(self, mock_get):
        """Test getting challenge ciphertext from server."""
        mock_response = MagicMock()
        mock_response.text = base64.b64encode(b"test_ciphertext_data").decode('utf-8')
        mock_get.return_value = mock_response
        
        ciphertext = self.attack.get_challenge_ciphertext(self.challenge_email)
        
        self.assertEqual(ciphertext, b"test_ciphertext_data")
        mock_get.assert_called_once()
    
    @patch('padding_oracle_attack.requests.post')
    def test_test_decryption_ok(self, mock_post):
        """Test decryption test with OK response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_post.return_value = mock_response
        
        result = self.attack.test_decryption(self.challenge_email, b"test_ciphertext")
        
        self.assertEqual(result, "OK")
        mock_post.assert_called_once()
    
    @patch('padding_oracle_attack.requests.post')
    def test_test_decryption_bad_padding(self, mock_post):
        """Test decryption test with bad padding response."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad padding bytes"
        mock_post.return_value = mock_response
        
        result = self.attack.test_decryption(self.challenge_email, b"test_ciphertext")
        
        self.assertEqual(result, "Bad padding bytes")
        mock_post.assert_called_once()
    
    @patch('padding_oracle_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        decrypted_message = "This is the secret message"
        result = self.attack.submit_answer(self.challenge_email, decrypted_message)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_split_into_blocks(self):
        """Test block splitting functionality."""
        test_data = b"This is a test message that should be split into blocks"
        blocks = self.attack.split_into_blocks(test_data)
        
        # Each block should be 16 bytes or less
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
    
    def test_analyze_ciphertext(self):
        """Test ciphertext analysis."""
        # Create test ciphertext with IV + 2 data blocks
        iv = b"test_iv_16_bytes"
        data_block1 = b"data_block_1_16"
        data_block2 = b"data_block_2_16"
        ciphertext = iv + data_block1 + data_block2
        
        with patch('builtins.print') as mock_print:
            analysis = self.attack.analyze_ciphertext(ciphertext)
        
        # Should return analysis dictionary
        self.assertIsInstance(analysis, dict)
        self.assertIn('iv', analysis)
        self.assertIn('ciphertext_blocks', analysis)
        self.assertIn('total_blocks', analysis)
        self.assertIn('data_blocks', analysis)
        
        # Should have correct structure
        self.assertEqual(analysis['iv'], iv)
        self.assertEqual(len(analysis['ciphertext_blocks']), 2)
        self.assertEqual(analysis['total_blocks'], 3)
        self.assertEqual(analysis['data_blocks'], 2)
        
        # Should have printed analysis info
        mock_print.assert_called()
    
    @patch('padding_oracle_attack.PaddingOracleAttack.test_decryption')
    def test_decrypt_block(self, mock_test_decryption):
        """Test single block decryption."""
        # Mock the oracle responses
        def mock_test_side_effect(email, ciphertext):
            # Simulate finding valid padding after some attempts
            return "OK"
        
        mock_test_decryption.side_effect = mock_test_side_effect
        
        target_block = b"A" * 16
        previous_block = b"B" * 16
        
        # This test is simplified - in reality, decrypt_block would need
        # more sophisticated mocking to simulate the byte-by-byte process
        with patch('builtins.print') as mock_print:
            with patch('time.sleep') as mock_sleep:
                decrypted = self.attack.decrypt_block(self.challenge_email, target_block, previous_block)
        
        self.assertIsInstance(decrypted, bytes)
        self.assertEqual(len(decrypted), 16)
    
    @patch('padding_oracle_attack.PaddingOracleAttack.get_challenge_ciphertext')
    @patch('padding_oracle_attack.PaddingOracleAttack.decrypt_message')
    @patch('padding_oracle_attack.PaddingOracleAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_decrypt, mock_get):
        """Test successful attack execution."""
        mock_get.return_value = b"test_ciphertext"
        mock_decrypt.return_value = "Decrypted message"
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get.assert_called_once_with(self.challenge_email)
        mock_decrypt.assert_called_once_with(self.challenge_email, b"test_ciphertext")
        mock_submit.assert_called_once_with(self.challenge_email, "Decrypted message")
    
    @patch('padding_oracle_attack.PaddingOracleAttack.get_challenge_ciphertext')
    def test_execute_attack_error(self, mock_get):
        """Test attack execution when getting ciphertext fails."""
        mock_get.side_effect = Exception("Network error")
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Network error", result)


class TestPaddingOracleSimulator(unittest.TestCase):
    """Test cases for PaddingOracleSimulator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.simulator = PaddingOracleSimulator()
    
    def test_encrypt_message_basic(self):
        """Test basic message encryption."""
        plaintext = "Hello, World!"
        encrypted = self.simulator.encrypt_message(plaintext)
        
        self.assertIsInstance(encrypted, bytes)
        self.assertGreater(len(encrypted), len(plaintext))
        
        # Should start with IV (16 bytes)
        self.assertEqual(len(encrypted) % 16, 0)
    
    def test_encrypt_message_structure(self):
        """Test encryption structure."""
        plaintext = "Test message"
        encrypted = self.simulator.encrypt_message(plaintext)
        
        # Should be IV + encrypted data
        iv = encrypted[:16]
        encrypted_data = encrypted[16:]
        
        self.assertEqual(len(iv), 16)
        self.assertEqual(len(encrypted_data) % 16, 0)
    
    def test_test_decryption_valid_padding(self):
        """Test decryption test with valid padding."""
        plaintext = "Test message"
        encrypted = self.simulator.encrypt_message(plaintext)
        
        result = self.simulator.test_decryption(encrypted)
        
        self.assertEqual(result, "OK")
    
    def test_test_decryption_invalid_padding(self):
        """Test decryption test with invalid padding."""
        # Create invalid ciphertext
        invalid_ciphertext = b"A" * 32  # Not properly encrypted
        
        result = self.simulator.test_decryption(invalid_ciphertext)
        
        self.assertEqual(result, "Bad padding bytes")
    
    def test_test_decryption_wrong_length(self):
        """Test decryption test with wrong length."""
        # Create ciphertext with wrong length
        wrong_length_ciphertext = b"A" * 31  # Not multiple of 16
        
        result = self.simulator.test_decryption(wrong_length_ciphertext)
        
        self.assertEqual(result, "Bad padding bytes")
    
    def test_decrypt_message(self):
        """Test message decryption."""
        plaintext = "Test message"
        encrypted = self.simulator.encrypt_message(plaintext)
        decrypted = self.simulator.decrypt_message(encrypted)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt-decrypt roundtrip."""
        test_messages = [
            "Hello, World!",
            "Short",
            "A" * 50,  # Long message
            "Special chars: !@#$%^&*()",
            "Unicode: ñáéíóú"
        ]
        
        for message in test_messages:
            encrypted = self.simulator.encrypt_message(message)
            decrypted = self.simulator.decrypt_message(encrypted)
            self.assertEqual(decrypted, message)
    
    def test_different_keys(self):
        """Test that different keys produce different results."""
        key1 = b"key1_16_bytes_ok"
        key2 = b"key2_16_bytes_ok"
        
        simulator1 = PaddingOracleSimulator(key1)
        simulator2 = PaddingOracleSimulator(key2)
        
        plaintext = "Test message"
        encrypted1 = simulator1.encrypt_message(plaintext)
        encrypted2 = simulator2.encrypt_message(plaintext)
        
        # Should be different due to different keys
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_padding_oracle_behavior(self):
        """Test padding oracle behavior with different inputs."""
        plaintext = "Test message"
        encrypted = self.simulator.encrypt_message(plaintext)
        
        # Test with original ciphertext
        result1 = self.simulator.test_decryption(encrypted)
        self.assertEqual(result1, "OK")
        
        # Test with modified ciphertext (should have bad padding)
        modified = bytearray(encrypted)
        modified[20] ^= 1  # Flip one bit
        result2 = self.simulator.test_decryption(bytes(modified))
        self.assertEqual(result2, "Bad padding bytes")


class TestPaddingOracleIntegration(unittest.TestCase):
    """Integration tests for padding oracle attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = PaddingOracleAttack()
        self.simulator = PaddingOracleSimulator()
    
    def test_padding_oracle_attack_simulation(self):
        """Test complete padding oracle attack simulation."""
        # Create test message
        secret_message = "This is a secret message that needs to be decrypted"
        
        # Encrypt the message
        encrypted = self.simulator.encrypt_message(secret_message)
        
        # Simulate the attack by using the simulator as oracle
        with patch.object(self.attack, 'test_decryption') as mock_test:
            def mock_test_side_effect(email, ciphertext):
                return self.simulator.test_decryption(ciphertext)
            
            mock_test.side_effect = mock_test_side_effect
            
            # Decrypt using padding oracle attack
            with patch('builtins.print') as mock_print:
                with patch('time.sleep') as mock_sleep:
                    decrypted = self.attack.decrypt_message("test@example.com", encrypted)
        
        # Should decrypt correctly
        self.assertEqual(decrypted, secret_message)
    
    def test_block_decryption_accuracy(self):
        """Test accuracy of block decryption."""
        # Create test data
        test_data = b"A" * 16  # Single block
        
        # Encrypt
        encrypted = self.simulator.encrypt_message(test_data.decode('utf-8'))
        
        # Extract blocks
        iv = encrypted[:16]
        ciphertext_block = encrypted[16:32]
        
        # Test decryption with oracle
        with patch.object(self.attack, 'test_decryption') as mock_test:
            def mock_test_side_effect(email, ciphertext):
                return self.simulator.test_decryption(ciphertext)
            
            mock_test.side_effect = mock_test_side_effect
            
            with patch('builtins.print') as mock_print:
                with patch('time.sleep') as mock_sleep:
                    decrypted_block = self.attack.decrypt_block("test@example.com", ciphertext_block, iv)
        
        # Should decrypt correctly
        expected_block = pad(test_data, 16)
        self.assertEqual(decrypted_block, expected_block)
    
    def test_padding_validation(self):
        """Test padding validation in different scenarios."""
        test_cases = [
            ("Short message", "Hi"),
            ("Exact block", "A" * 16),
            ("Multiple blocks", "A" * 50),
            ("Special chars", "!@#$%^&*()"),
        ]
        
        for description, message in test_cases:
            encrypted = self.simulator.encrypt_message(message)
            
            # Test with original (should be OK)
            result1 = self.simulator.test_decryption(encrypted)
            self.assertEqual(result1, "OK", f"Failed for {description}")
            
            # Test with modified (should be bad padding)
            modified = bytearray(encrypted)
            modified[20] ^= 1  # Flip one bit
            result2 = self.simulator.test_decryption(bytes(modified))
            self.assertEqual(result2, "Bad padding bytes", f"Failed for {description}")
    
    def test_ciphertext_structure_analysis(self):
        """Test analysis of different ciphertext structures."""
        test_cases = [
            ("Short message", "Hi"),
            ("Medium message", "This is a medium length message"),
            ("Long message", "A" * 100),
        ]
        
        for description, message in test_cases:
            encrypted = self.simulator.encrypt_message(message)
            
            with patch('builtins.print') as mock_print:
                analysis = self.attack.analyze_ciphertext(encrypted)
            
            # Should have correct structure
            self.assertEqual(len(analysis['iv']), 16, f"Failed for {description}")
            self.assertGreater(len(analysis['ciphertext_blocks']), 0, f"Failed for {description}")
            self.assertEqual(analysis['total_blocks'], len(analysis['ciphertext_blocks']) + 1, f"Failed for {description}")


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
