#!/usr/bin/env python3
"""
Test cases for Stream Cipher Bit Flipping Attack

This module contains test cases to validate the stream cipher bit flipping attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
import os
from stream_bitflip_attack import StreamBitFlipAttack, StreamBitFlipOracle


class TestStreamBitFlipAttack(unittest.TestCase):
    """Test cases for StreamBitFlipAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = StreamBitFlipAttack()
        self.challenge_email = "user@example.com"
        self.user_email = "test@example.com"
    
    @patch('stream_bitflip_attack.requests.post')
    def test_register_user(self, mock_post):
        """Test user registration request."""
        mock_response = MagicMock()
        mock_response.text = "encrypted_profile_with_nonce"
        mock_post.return_value = mock_response
        
        result = self.attack.register_user(self.challenge_email, self.user_email, "test data")
        
        self.assertEqual(result, "encrypted_profile_with_nonce")
        mock_post.assert_called_once()
        
        # Check that data was base64 encoded
        call_args = mock_post.call_args
        self.assertIn('email', call_args[1]['data'])
        self.assertIn('data', call_args[1]['data'])
        
        # Verify base64 encoding
        encoded_data = call_args[1]['data']['data']
        try:
            decoded = base64.b64decode(encoded_data)
            self.assertEqual(decoded.decode('utf-8'), "test data")
        except Exception:
            self.fail("Data should be valid base64")
    
    @patch('stream_bitflip_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        encrypted_message = "modified_encrypted_message"
        result = self.attack.submit_answer(self.challenge_email, encrypted_message)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_analyze_profile_structure(self):
        """Test profile structure analysis."""
        profile = "user=test@example.com;data=TestData;role=user"
        
        # Capture print output
        with patch('builtins.print') as mock_print:
            analysis = self.attack.analyze_profile_structure(profile)
        
        # Should return analysis dictionary
        self.assertIsInstance(analysis, dict)
        self.assertIn('profile', analysis)
        self.assertIn('pairs', analysis)
        self.assertIn('role_start', analysis)
        self.assertIn('role_end', analysis)
        self.assertIn('role_field', analysis)
        
        # Should have correct role information
        self.assertEqual(analysis['role_start'], 30)  # Position of 'role='
        self.assertEqual(analysis['role_field'], 'role=user')
        self.assertEqual(analysis['role_length'], 8)
        
        # Should have printed profile info
        mock_print.assert_called()
    
    def test_analyze_profile_structure_no_role(self):
        """Test profile structure analysis when role field is missing."""
        profile = "user=test@example.com;data=TestData"
        
        with patch('builtins.print') as mock_print:
            analysis = self.attack.analyze_profile_structure(profile)
        
        # Should indicate role not found
        self.assertEqual(analysis['role_start'], -1)
        self.assertIsNone(analysis['role_field'])
        self.assertEqual(analysis['role_length'], 0)
    
    def test_calculate_bit_flip(self):
        """Test bit flip calculation."""
        original_text = "role=user"
        target_text = "role=admin"
        
        with patch('builtins.print') as mock_print:
            mask = self.attack.calculate_bit_flip(original_text, target_text)
        
        self.assertIsInstance(mask, bytes)
        self.assertEqual(len(mask), len(original_text))
        
        # Verify the mask works
        original_bytes = original_text.encode('utf-8')
        target_bytes = target_text.encode('utf-8')
        expected_mask = bytes(a ^ b for a, b in zip(original_bytes, target_bytes))
        self.assertEqual(mask, expected_mask)
    
    def test_calculate_bit_flip_different_lengths(self):
        """Test bit flip calculation with different length texts."""
        original_text = "role=user"
        target_text = "role=admin"  # Same length
        
        mask = self.attack.calculate_bit_flip(original_text, target_text)
        self.assertEqual(len(mask), len(original_text))
    
    def test_calculate_bit_flip_invalid_lengths(self):
        """Test bit flip calculation with invalid length texts."""
        original_text = "role=user"
        target_text = "role=admin123"  # Different length
        
        with self.assertRaises(ValueError):
            self.attack.calculate_bit_flip(original_text, target_text)
    
    def test_apply_bit_flip(self):
        """Test applying bit flip mask to ciphertext."""
        ciphertext = b"test_ciphertext_16"
        mask = b"\x01\x02\x03\x04"
        position = 5
        
        with patch('builtins.print') as mock_print:
            modified = self.attack.apply_bit_flip(ciphertext, mask, position)
        
        self.assertIsInstance(modified, bytes)
        self.assertEqual(len(modified), len(ciphertext))
        
        # Verify the modification
        expected = bytearray(ciphertext)
        for i in range(len(mask)):
            expected[position + i] ^= mask[i]
        self.assertEqual(modified, bytes(expected))
    
    def test_apply_bit_flip_invalid_position(self):
        """Test applying bit flip mask with invalid position."""
        ciphertext = b"test_ciphertext_16"
        mask = b"\x01\x02\x03\x04"
        position = 20  # Beyond ciphertext length
        
        with self.assertRaises(ValueError):
            self.attack.apply_bit_flip(ciphertext, mask, position)
    
    @patch('stream_bitflip_attack.StreamBitFlipAttack.register_user')
    def test_find_role_position(self, mock_register):
        """Test finding role position in ciphertext."""
        # Mock register responses
        def mock_register_side_effect(challenge_email, user_email, data):
            # Simulate different responses based on data length
            profile = f"user={user_email};data={data};role=user"
            # Simulate encryption by returning base64 encoded profile
            return base64.b64encode(b"nonce_16_bytes" + profile.encode('utf-8')).decode('utf-8')
        
        mock_register.side_effect = mock_register_side_effect
        
        position = self.attack.find_role_position(self.challenge_email, self.user_email, "test")
        
        # Should find a valid position
        self.assertIsNotNone(position)
        self.assertGreaterEqual(position, 0)
    
    @patch('stream_bitflip_attack.StreamBitFlipAttack.register_user')
    def test_create_bit_flip_attack(self, mock_register):
        """Test bit flip attack creation."""
        # Mock register response
        profile = f"user={self.user_email};data=TestData;role=user"
        encrypted_data = base64.b64encode(b"nonce_16_bytes" + profile.encode('utf-8')).decode('utf-8')
        mock_register.return_value = encrypted_data
        
        result = self.attack.create_bit_flip_attack(self.challenge_email, self.user_email)
        
        self.assertIsInstance(result, str)
        # Should be valid base64
        try:
            base64.b64decode(result)
        except Exception:
            self.fail("Result should be valid base64")
    
    @patch('stream_bitflip_attack.StreamBitFlipAttack.create_bit_flip_attack')
    @patch('stream_bitflip_attack.StreamBitFlipAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_create):
        """Test successful attack execution."""
        mock_create.return_value = "modified_message"
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email, self.user_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_create.assert_called_once_with(self.challenge_email, self.user_email)
        mock_submit.assert_called_once_with(self.challenge_email, "modified_message")
    
    @patch('stream_bitflip_attack.StreamBitFlipAttack.create_bit_flip_attack')
    def test_execute_attack_creation_error(self, mock_create):
        """Test attack execution when creation fails."""
        mock_create.side_effect = ValueError("Attack failed")
        
        result = self.attack.execute_attack(self.challenge_email, self.user_email)
        
        self.assertIn("Error", result)
        self.assertIn("Attack failed", result)


class TestStreamBitFlipOracle(unittest.TestCase):
    """Test cases for StreamBitFlipOracle class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.oracle = StreamBitFlipOracle()
    
    def test_encrypt_profile_basic(self):
        """Test basic profile encryption."""
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        
        # Should return base64 encoded string
        self.assertIsInstance(encrypted, str)
        
        # Should be valid base64
        try:
            decoded = base64.b64decode(encrypted)
            self.assertIsInstance(decoded, bytes)
        except Exception:
            self.fail("Encrypted result should be valid base64")
    
    def test_encrypt_profile_structure(self):
        """Test profile encryption structure."""
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        decrypted = self.oracle.decrypt_profile(encrypted)
        
        # Should contain expected profile structure
        self.assertIn(f"user={user_email}", decrypted)
        self.assertIn(f"data={data}", decrypted)
        self.assertIn("role=user", decrypted)
    
    def test_decrypt_profile(self):
        """Test profile decryption."""
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        decrypted = self.oracle.decrypt_profile(encrypted)
        
        # Should decrypt correctly
        expected_profile = f"user={user_email};data={data};role=user"
        self.assertEqual(decrypted, expected_profile)
    
    def test_encrypt_profile_different_inputs(self):
        """Test that different inputs produce different outputs."""
        encrypted1 = self.oracle.encrypt_profile("user1@test.com", "data1")
        encrypted2 = self.oracle.encrypt_profile("user2@test.com", "data2")
        
        # Should be different due to different nonces
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_encrypt_profile_with_nonce(self):
        """Test profile encryption with specific nonce."""
        user_email = "test@example.com"
        data = "TestData"
        nonce = b"test_nonce_16_by"
        
        encrypted1 = self.oracle.encrypt_profile(user_email, data, nonce)
        encrypted2 = self.oracle.encrypt_profile(user_email, data, nonce)
        
        # Should be identical with same nonce
        self.assertEqual(encrypted1, encrypted2)
    
    def test_bit_flip_mechanism(self):
        """Test the bit flipping mechanism."""
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        decrypted = self.oracle.decrypt_profile(encrypted)
        
        # Verify original profile
        self.assertIn("role=user", decrypted)
        
        # Now test bit flipping
        encrypted_bytes = base64.b64decode(encrypted)
        nonce = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Find position of 'role=user'
        profile = f"user={user_email};data={data};role=user"
        role_start = profile.find('role=')
        
        if role_start != -1:
            # Create bit flip mask
            original_role = "role=user"
            target_role = "role=admin"
            
            mask = bytes(a ^ b for a, b in zip(original_role.encode('utf-8'), target_role.encode('utf-8')))
            
            # Apply bit flip
            modified_ciphertext = bytearray(ciphertext)
            for i in range(len(mask)):
                modified_ciphertext[role_start + i] ^= mask[i]
            
            # Reconstruct
            modified_encrypted = nonce + bytes(modified_ciphertext)
            modified_b64 = base64.b64encode(modified_encrypted).decode('utf-8')
            
            # Decrypt the modified version
            modified_decrypted = self.oracle.decrypt_profile(modified_b64)
            
            # Should now contain 'role=admin'
            self.assertIn("role=admin", modified_decrypted)
            self.assertNotIn("role=user", modified_decrypted)


class TestStreamBitFlipIntegration(unittest.TestCase):
    """Integration tests for stream cipher bit flip attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = StreamBitFlipAttack()
        self.oracle = StreamBitFlipOracle()
    
    def test_full_attack_simulation(self):
        """Test complete attack simulation."""
        user_email = "test@example.com"
        data = "TestData"
        
        # Create encrypted profile
        encrypted = self.oracle.encrypt_profile(user_email, data)
        encrypted_bytes = base64.b64decode(encrypted)
        nonce = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Analyze profile structure
        profile = f"user={user_email};data={data};role=user"
        analysis = self.attack.analyze_profile_structure(profile)
        
        self.assertEqual(analysis['role_field'], 'role=user')
        
        # Calculate bit flip
        mask = self.attack.calculate_bit_flip("role=user", "role=admin")
        
        # Apply bit flip
        role_position = analysis['role_start']
        modified_ciphertext = self.attack.apply_bit_flip(ciphertext, mask, role_position)
        
        # Reconstruct and decrypt
        modified_encrypted = nonce + modified_ciphertext
        modified_b64 = base64.b64encode(modified_encrypted).decode('utf-8')
        
        modified_decrypted = self.oracle.decrypt_profile(modified_b64)
        
        # Should now contain 'role=admin'
        self.assertIn("role=admin", modified_decrypted)
    
    def test_bit_flip_precision(self):
        """Test precision of bit flipping."""
        # Test with different character changes
        test_cases = [
            ("user", "admin"),
            ("user", "root"),
            ("user", "guest"),
        ]
        
        for original, target in test_cases:
            mask = self.attack.calculate_bit_flip(original, target)
            
            # Verify the mask works
            original_bytes = original.encode('utf-8')
            target_bytes = target.encode('utf-8')
            expected_mask = bytes(a ^ b for a, b in zip(original_bytes, target_bytes))
            
            self.assertEqual(mask, expected_mask)
            
            # Test applying the mask
            test_ciphertext = b"A" * len(original)
            modified = self.attack.apply_bit_flip(test_ciphertext, mask, 0)
            
            # Verify the result
            expected_result = bytes(a ^ b for a, b in zip(test_ciphertext, mask))
            self.assertEqual(modified, expected_result)
    
    def test_profile_structure_variations(self):
        """Test attack with different profile structures."""
        test_cases = [
            ("user=test@example.com;data=A;role=user", "Short data"),
            ("user=verylongemail@example.com;data=LongData;role=user", "Long email"),
            ("user=test@example.com;data=Special!@#;role=user", "Special characters"),
        ]
        
        for profile, description in test_cases:
            analysis = self.attack.analyze_profile_structure(profile)
            
            self.assertGreater(analysis['role_start'], 0, f"Failed for {description}")
            self.assertEqual(analysis['role_field'], 'role=user', f"Failed for {description}")
            
            # Test bit flip calculation
            mask = self.attack.calculate_bit_flip("role=user", "role=admin")
            self.assertEqual(len(mask), 8, f"Failed for {description}")


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
