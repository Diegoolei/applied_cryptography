#!/usr/bin/env python3
"""
Test cases for ECB Forgery Attack

This module contains test cases to validate the ECB forgery attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
from ecb_forge_attack import ECBForgeAttack


class TestECBForgeAttack(unittest.TestCase):
    """Test cases for ECBForgeAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = ECBForgeAttack()
        self.challenge_email = "user@example.com"
        self.target_email = "usuario@ejemplo.edu.ar"
    
    def test_split_into_blocks(self):
        """Test block splitting functionality."""
        test_data = b"user=test@example.com&id=123&role=user"
        blocks = self.attack.split_into_blocks(test_data, block_size=16)
        
        # Should create 3 blocks (48 bytes / 16 = 3 blocks)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(len(blocks[0]), 16)
        self.assertEqual(len(blocks[1]), 16)
        self.assertEqual(len(blocks[2]), 16)
        
        # First block should contain "user=test@examp"
        self.assertTrue(b"user=test@examp" in blocks[0])
    
    def test_split_into_blocks_uneven(self):
        """Test block splitting with uneven data length."""
        test_data = b"short"
        blocks = self.attack.split_into_blocks(test_data, block_size=16)
        
        # Should create 1 block with 5 bytes
        self.assertEqual(len(blocks), 1)
        self.assertEqual(len(blocks[0]), 5)
        self.assertEqual(blocks[0], b"short")
    
    @patch('ecb_forge_attack.requests.get')
    def test_get_profile_plain(self, mock_get):
        """Test getting plain text profile."""
        mock_response = MagicMock()
        mock_response.text = "user=test@example.com&id=123&role=user"
        mock_get.return_value = mock_response
        
        result = self.attack.get_profile(self.challenge_email, self.target_email)
        
        self.assertEqual(result, "user=test@example.com&id=123&role=user")
        mock_get.assert_called_once()
    
    @patch('ecb_forge_attack.requests.get')
    def test_get_profile_encrypted(self, mock_get):
        """Test getting encrypted profile."""
        mock_response = MagicMock()
        mock_response.text = "encrypted_base64_data"
        mock_get.return_value = mock_response
        
        result = self.attack.get_profile(self.challenge_email, self.target_email, encrypted=True)
        
        self.assertEqual(result, "encrypted_base64_data")
        mock_get.assert_called_once()
        
        # Check that encrypted parameter was added
        call_args = mock_get.call_args
        self.assertIn('encrypted', call_args[1]['params'])
        self.assertEqual(call_args[1]['params']['encrypted'], 'true')
    
    @patch('ecb_forge_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        encrypted_message = "test_encrypted_message"
        result = self.attack.submit_answer(self.challenge_email, encrypted_message)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_analyze_profile_structure(self):
        """Test profile structure analysis."""
        profile = "user=test@example.com&id=123&role=user"
        
        # Capture print output
        with patch('builtins.print') as mock_print:
            blocks = self.attack.analyze_profile_structure(profile)
        
        # Should return blocks
        self.assertIsInstance(blocks, list)
        self.assertTrue(len(blocks) > 0)
        
        # Should have printed profile info
        mock_print.assert_called()
    
    @patch('ecb_forge_attack.ECBForgeAttack.get_profile')
    def test_find_admin_block_email_success(self, mock_get_profile):
        """Test finding admin block email successfully."""
        # Mock profile that contains role=admin
        admin_profile = "user=a@b.coxxxxxxxxxxxxxxx&id=123&role=admin"
        mock_get_profile.return_value = admin_profile
        
        admin_email, admin_block_index = self.attack.find_admin_block_email(self.challenge_email)
        
        self.assertIsNotNone(admin_email)
        self.assertIsNotNone(admin_block_index)
        self.assertEqual(admin_email, "a@b.coxxxxxxxxxxxxxxx")
    
    @patch('ecb_forge_attack.ECBForgeAttack.get_profile')
    def test_find_admin_block_email_not_found(self, mock_get_profile):
        """Test when admin block email is not found."""
        # Mock profile that doesn't contain role=admin
        regular_profile = "user=test@example.com&id=123&role=user"
        mock_get_profile.return_value = regular_profile
        
        admin_email, admin_block_index = self.attack.find_admin_block_email(self.challenge_email)
        
        self.assertIsNone(admin_email)
        self.assertIsNone(admin_block_index)
    
    @patch('ecb_forge_attack.ECBForgeAttack.find_admin_block_email')
    @patch('ecb_forge_attack.ECBForgeAttack.get_profile')
    def test_forge_message_success(self, mock_get_profile, mock_find_admin):
        """Test successful message forging."""
        # Mock finding admin block
        mock_find_admin.return_value = ("admin@test.com", 2)
        
        # Mock profiles
        target_profile = "user=target@test.com&id=456&role=user"
        target_encrypted = base64.b64encode(b"encrypted_target_data").decode('utf-8')
        admin_encrypted = base64.b64encode(b"encrypted_admin_data").decode('utf-8')
        
        mock_get_profile.side_effect = [target_profile, target_encrypted, admin_encrypted]
        
        result = self.attack.forge_message(self.challenge_email, self.target_email)
        
        self.assertIsInstance(result, str)
        # Should be base64 encoded
        try:
            base64.b64decode(result)
        except Exception:
            self.fail("Result should be valid base64")
    
    @patch('ecb_forge_attack.ECBForgeAttack.find_admin_block_email')
    def test_forge_message_admin_not_found(self, mock_find_admin):
        """Test forging message when admin block is not found."""
        mock_find_admin.return_value = (None, None)
        
        with self.assertRaises(ValueError):
            self.attack.forge_message(self.challenge_email, self.target_email)
    
    @patch('ecb_forge_attack.ECBForgeAttack.forge_message')
    @patch('ecb_forge_attack.ECBForgeAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_forge):
        """Test successful attack execution."""
        mock_forge.return_value = "forged_message"
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email, self.target_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_forge.assert_called_once_with(self.challenge_email, self.target_email)
        mock_submit.assert_called_once_with(self.challenge_email, "forged_message")
    
    @patch('ecb_forge_attack.ECBForgeAttack.forge_message')
    def test_execute_attack_forge_error(self, mock_forge):
        """Test attack execution when forging fails."""
        mock_forge.side_effect = ValueError("Admin block not found")
        
        result = self.attack.execute_attack(self.challenge_email, self.target_email)
        
        self.assertIn("Error en el ataque", result)
        self.assertIn("Admin block not found", result)


class TestECBAttackIntegration(unittest.TestCase):
    """Integration tests for ECB attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = ECBForgeAttack()
    
    def test_block_alignment_calculation(self):
        """Test block alignment calculations."""
        # Test different email lengths and their block alignments
        test_cases = [
            ("a@b.co", "user=a@b.co&id=123&role=user"),
            ("a@b.cox", "user=a@b.cox&id=123&role=user"),
            ("a@b.coxx", "user=a@b.coxx&id=123&role=user"),
            ("a@b.coxxx", "user=a@b.coxxx&id=123&role=user"),
        ]
        
        for email, expected_profile in test_cases:
            profile_bytes = expected_profile.encode('utf-8')
            blocks = self.attack.split_into_blocks(profile_bytes)
            
            # Each block should be 16 bytes
            for block in blocks:
                self.assertLessEqual(len(block), 16)
    
    def test_padding_analysis(self):
        """Test PKCS7 padding analysis."""
        from Crypto.Util.Padding import pad
        
        test_data = b"user=test@example.com&id=123&role=user"
        padded_data = pad(test_data, 16)
        
        # Should be multiple of 16
        self.assertEqual(len(padded_data) % 16, 0)
        
        # Should be longer than original
        self.assertGreater(len(padded_data), len(test_data))


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
