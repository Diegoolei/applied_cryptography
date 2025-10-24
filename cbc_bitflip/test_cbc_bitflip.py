#!/usr/bin/env python3
"""
Test cases for CBC Bit Flipping Attack

This module contains test cases to validate the CBC bit flipping attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from cbc_bitflip_attack import CBCBitFlipAttack, CBCBitFlipOracle


class TestCBCBitFlipAttack(unittest.TestCase):
    """Test cases for CBCBitFlipAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = CBCBitFlipAttack()
        self.challenge_email = "user@example.com"
        self.user_email = "test@example.com"
    
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
    
    @patch('cbc_bitflip_attack.requests.post')
    def test_register_user(self, mock_post):
        """Test user registration request."""
        mock_response = MagicMock()
        mock_response.text = "encrypted_profile_with_iv"
        mock_post.return_value = mock_response
        
        result = self.attack.register_user(self.challenge_email, self.user_email, "test data")
        
        self.assertEqual(result, "encrypted_profile_with_iv")
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
    
    @patch('cbc_bitflip_attack.requests.post')
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
        self.assertIn('blocks', analysis)
        
        # Should have correct number of pairs
        self.assertEqual(len(analysis['pairs']), 3)
        
        # Should have printed profile info
        mock_print.assert_called()
    
    def test_find_role_block(self):
        """Test finding the block containing 'role=user'."""
        profile = "user=test@example.com;data=TestData;role=user"
        role_block_index = self.attack.find_role_block(profile)
        
        self.assertIsNotNone(role_block_index)
        self.assertIsInstance(role_block_index, int)
    
    def test_find_role_block_not_found(self):
        """Test when role block is not found."""
        profile = "user=test@example.com;data=TestData"
        role_block_index = self.attack.find_role_block(profile)
        
        self.assertIsNone(role_block_index)
    
    def test_calculate_bit_flip(self):
        """Test bit flip calculation."""
        target_block = b"role=user\x00\x00\x00\x00\x00\x00"
        desired_change = b"role=admi\x00\x00\x00\x00\x00\x00"
        
        bit_flip = self.attack.calculate_bit_flip(target_block, desired_change)
        
        self.assertIsInstance(bit_flip, bytes)
        self.assertEqual(len(bit_flip), len(target_block))
    
    @patch('cbc_bitflip_attack.CBCBitFlipAttack.register_user')
    def test_create_bit_flip_attack(self, mock_register):
        """Test bit flip attack creation."""
        # Mock register responses
        mock_register.return_value = base64.b64encode(b"iv" + b"ciphertext_block1" + b"ciphertext_block2").decode('utf-8')
        
        result = self.attack.create_bit_flip_attack(self.challenge_email, self.user_email)
        
        self.assertIsInstance(result, str)
        # Should be valid base64
        try:
            base64.b64decode(result)
        except Exception:
            self.fail("Result should be valid base64")
    
    @patch('cbc_bitflip_attack.CBCBitFlipAttack.create_bit_flip_attack')
    @patch('cbc_bitflip_attack.CBCBitFlipAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_create):
        """Test successful attack execution."""
        mock_create.return_value = "modified_message"
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email, self.user_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_create.assert_called_once_with(self.challenge_email, self.user_email)
        mock_submit.assert_called_once_with(self.challenge_email, "modified_message")
    
    @patch('cbc_bitflip_attack.CBCBitFlipAttack.create_bit_flip_attack')
    def test_execute_attack_creation_error(self, mock_create):
        """Test attack execution when creation fails."""
        mock_create.side_effect = ValueError("Attack failed")
        
        result = self.attack.execute_attack(self.challenge_email, self.user_email)
        
        self.assertIn("Error", result)
        self.assertIn("Attack failed", result)


class TestCBCBitFlipOracle(unittest.TestCase):
    """Test cases for CBCBitFlipOracle class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.oracle = CBCBitFlipOracle()
    
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
        
        # Should be different due to random IV
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_encrypt_profile_block_alignment(self):
        """Test block alignment for different profile lengths."""
        test_cases = [
            ("short@test.com", "A"),
            ("medium@test.com", "MediumData"),
            ("verylongemail@test.com", "VeryLongDataField"),
        ]
        
        for user_email, data in test_cases:
            encrypted = self.oracle.encrypt_profile(user_email, data)
            
            # Decode and check block alignment
            encrypted_bytes = base64.b64decode(encrypted)
            
            # Should be multiple of 16 bytes (excluding IV)
            ciphertext_length = len(encrypted_bytes) - 16
            self.assertEqual(ciphertext_length % 16, 0)


class TestCBCBitFlipIntegration(unittest.TestCase):
    """Integration tests for CBC bit flip attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = CBCBitFlipAttack()
        self.oracle = CBCBitFlipOracle()
    
    def test_bit_flip_mechanism(self):
        """Test the bit flipping mechanism."""
        # Create a test profile
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        decrypted = self.oracle.decrypt_profile(encrypted)
        
        # Verify original profile
        self.assertIn("role=user", decrypted)
        
        # Now test bit flipping
        encrypted_bytes = base64.b64decode(encrypted)
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Split into blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        
        # Modify a block to test bit flipping
        if len(blocks) >= 2:
            # Modify the second-to-last block
            modified_blocks = blocks.copy()
            
            # Create a simple bit flip
            mask = b'\x01' * 16  # Flip all bits
            modified_blocks[-2] = bytes(a ^ b for a, b in zip(modified_blocks[-2], mask))
            
            # Reconstruct
            modified_ciphertext = b''.join(modified_blocks)
            modified_encrypted = iv + modified_ciphertext
            modified_b64 = base64.b64encode(modified_encrypted).decode('utf-8')
            
            # Decrypt the modified version
            try:
                modified_decrypted = self.oracle.decrypt_profile(modified_b64)
                # The decryption should work but the content should be different
                self.assertNotEqual(modified_decrypted, decrypted)
            except Exception:
                # Decryption might fail due to padding issues, which is expected
                pass
    
    def test_profile_structure_analysis(self):
        """Test analysis of different profile structures."""
        test_cases = [
            ("user=test@example.com;data=A;role=user", 3),
            ("user=verylongemail@example.com;data=LongData;role=user", 3),
            ("user=short@test.com;data=Short;role=user", 3),
        ]
        
        for profile, expected_pairs in test_cases:
            analysis = self.attack.analyze_profile_structure(profile)
            
            self.assertEqual(len(analysis['pairs']), expected_pairs)
            self.assertIn('user=', analysis['pairs'][0])
            self.assertIn('data=', analysis['pairs'][1])
            self.assertIn('role=user', analysis['pairs'][2])
    
    def test_block_boundary_detection(self):
        """Test detection of block boundaries."""
        # Test with different profile lengths
        test_cases = [
            ("user=a@b.com;data=A;role=user", "Short profile"),
            ("user=medium@test.com;data=MediumData;role=user", "Medium profile"),
            ("user=verylongemail@example.com;data=VeryLongDataField;role=user", "Long profile"),
        ]
        
        for profile, description in test_cases:
            analysis = self.attack.analyze_profile_structure(profile)
            
            # Should have at least one block
            self.assertGreaterEqual(len(analysis['blocks']), 1, f"Failed for {description}")
            
            # Each block should be 16 bytes or less
            for block in analysis['blocks']:
                self.assertLessEqual(len(block), 16, f"Failed for {description}")
    
    def test_role_block_detection(self):
        """Test detection of role block in different scenarios."""
        test_cases = [
            ("user=test@example.com;data=A;role=user", True),
            ("user=verylongemail@example.com;data=LongData;role=user", True),
            ("user=test@example.com;data=TestData;role=admin", False),  # Not 'role=user'
            ("user=test@example.com;data=TestData", False),  # No role field
        ]
        
        for profile, should_find_role in test_cases:
            role_block_index = self.attack.find_role_block(profile)
            
            if should_find_role:
                self.assertIsNotNone(role_block_index, f"Should find role block in: {profile}")
            else:
                self.assertIsNone(role_block_index, f"Should not find role block in: {profile}")


class TestCBCBitFlipAttackScenarios(unittest.TestCase):
    """Test specific attack scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.oracle = CBCBitFlipOracle()
    
    def test_simple_bit_flip_scenario(self):
        """Test a simple bit flip scenario."""
        # Create a profile where we can easily test bit flipping
        user_email = "test@example.com"
        data = "A" * 10  # 10 bytes of data
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        encrypted_bytes = base64.b64decode(encrypted)
        
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Split into blocks
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        
        # Test that we can modify blocks
        self.assertGreaterEqual(len(blocks), 2, "Should have at least 2 blocks")
        
        # Modify a block
        modified_blocks = blocks.copy()
        modified_blocks[0] = b'\x00' * 16  # Replace first block with zeros
        
        # Reconstruct
        modified_ciphertext = b''.join(modified_blocks)
        modified_encrypted = iv + modified_ciphertext
        modified_b64 = base64.b64encode(modified_encrypted).decode('utf-8')
        
        # The modified version should be different
        self.assertNotEqual(modified_b64, encrypted)
    
    def test_padding_validation(self):
        """Test padding validation in bit flip attacks."""
        # Create a profile
        user_email = "test@example.com"
        data = "TestData"
        
        encrypted = self.oracle.encrypt_profile(user_email, data)
        encrypted_bytes = base64.b64decode(encrypted)
        
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        # Modify the last byte of the last block (padding)
        modified_ciphertext = ciphertext[:-1] + b'\x00'
        modified_encrypted = iv + modified_ciphertext
        modified_b64 = base64.b64encode(modified_encrypted).decode('utf-8')
        
        # This should cause a padding error
        with self.assertRaises(Exception):
            self.oracle.decrypt_profile(modified_b64)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
