#!/usr/bin/env python3
"""
Test cases for Length Extension Attack

This module contains test cases to validate the length extension attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import hashlib
import struct
from length_extension_attack import LengthExtensionAttack, SHA256LengthExtension


class TestLengthExtensionAttack(unittest.TestCase):
    """Test cases for LengthExtensionAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = LengthExtensionAttack()
        self.challenge_email = "user@example.com"
    
    @patch('length_extension_attack.requests.get')
    def test_get_challenge_message(self, mock_get):
        """Test getting challenge message from server."""
        mock_response = MagicMock()
        mock_response.text = "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"
        mock_get.return_value = mock_response
        
        challenge = self.attack.get_challenge_message(self.challenge_email)
        
        self.assertEqual(challenge, "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83")
        mock_get.assert_called_once()
    
    @patch('length_extension_attack.requests.get')
    def test_submit_answer(self, mock_get):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_get.return_value = mock_response
        
        forged_query = "user=user@example.com&admin=true&mac=new_mac"
        result = self.attack.submit_answer(self.challenge_email, forged_query)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get.assert_called_once()
    
    def test_parse_query_string(self):
        """Test query string parsing."""
        query_string = "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"
        
        pairs = self.attack.parse_query_string(query_string)
        
        expected_pairs = {
            'user': 'user@example.com',
            'action': 'show',
            'mac': '91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83'
        }
        
        self.assertEqual(pairs, expected_pairs)
    
    def test_parse_query_string_empty(self):
        """Test parsing empty query string."""
        pairs = self.attack.parse_query_string("")
        self.assertEqual(pairs, {})
    
    def test_parse_query_string_single_pair(self):
        """Test parsing single key-value pair."""
        pairs = self.attack.parse_query_string("key=value")
        self.assertEqual(pairs, {'key': 'value'})
    
    def test_build_message_from_pairs(self):
        """Test building message from key-value pairs."""
        pairs = {
            'user': 'user@example.com',
            'action': 'show',
            'mac': '91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        # Should be sorted alphabetically: action, user (excluding mac)
        expected_message = "actionshowuseruser@example.com"
        self.assertEqual(message, expected_message)
    
    def test_build_message_from_pairs_no_mac(self):
        """Test building message when no MAC field exists."""
        pairs = {
            'user': 'user@example.com',
            'action': 'show'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        expected_message = "actionshowuseruser@example.com"
        self.assertEqual(message, expected_message)
    
    def test_build_message_from_pairs_multiple_fields(self):
        """Test building message with multiple fields."""
        pairs = {
            'user': 'user@example.com',
            'action': 'show',
            'role': 'admin',
            'mac': 'some_mac'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        # Should be sorted alphabetically: action, role, user (excluding mac)
        expected_message = "actionshowroleadminuseruser@example.com"
        self.assertEqual(message, expected_message)
    
    def test_sha256_padding(self):
        """Test SHA-256 padding calculation."""
        # Test with different message lengths
        test_cases = [
            (0, 64),      # Empty message
            (1, 63),      # 1 byte message
            (55, 9),      # 55 bytes (just before padding)
            (56, 8),      # 56 bytes (exactly at padding boundary)
            (63, 1),      # 63 bytes
            (64, 64),     # 64 bytes (one block)
            (127, 1),     # 127 bytes
            (128, 64),    # 128 bytes (two blocks)
        ]
        
        for message_length, expected_padding_length in test_cases:
            padding = self.attack.sha256_padding(message_length)
            
            # Check padding length
            self.assertEqual(len(padding), expected_padding_length)
            
            # Check that padding starts with 0x80
            self.assertEqual(padding[0], 0x80)
            
            # Check that padding ends with length
            length_bits = message_length * 8
            expected_length_bytes = struct.pack('>Q', length_bits)
            actual_length_bytes = padding[-8:]
            self.assertEqual(actual_length_bytes, expected_length_bytes)
    
    def test_sha256_padding_structure(self):
        """Test SHA-256 padding structure."""
        message_length = 10
        padding = self.attack.sha256_padding(message_length)
        
        # Check total length is correct
        total_length = message_length + len(padding)
        self.assertEqual(total_length % 64, 0)
        
        # Check padding starts with 0x80
        self.assertEqual(padding[0], 0x80)
        
        # Check middle bytes are zeros
        for i in range(1, len(padding) - 8):
            self.assertEqual(padding[i], 0)
        
        # Check last 8 bytes contain length
        length_bits = message_length * 8
        expected_length_bytes = struct.pack('>Q', length_bits)
        actual_length_bytes = padding[-8:]
        self.assertEqual(actual_length_bytes, expected_length_bytes)
    
    def test_sha256_extend(self):
        """Test SHA-256 length extension."""
        original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        original_length = 32  # 16 bytes secret + 16 bytes message
        extension = "admin" + "true"
        
        new_hash = self.attack.sha256_extend(original_hash, original_length, extension)
        
        # Should return a valid hex string
        self.assertRegex(new_hash, r'^[0-9a-f]{64}$')
        self.assertEqual(len(new_hash), 64)
    
    def test_forge_query_string(self):
        """Test query string forging."""
        original_query = "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"
        
        with patch('builtins.print') as mock_print:
            forged_query = self.attack.forge_query_string(original_query)
        
        # Should be a valid query string
        self.assertIsInstance(forged_query, str)
        self.assertIn('&', forged_query)
        
        # Should contain required fields
        self.assertIn('user=', forged_query)
        self.assertIn('admin=true', forged_query)
        self.assertIn('mac=', forged_query)
        
        # Should be able to parse it
        pairs = self.attack.parse_query_string(forged_query)
        self.assertIn('user', pairs)
        self.assertIn('admin', pairs)
        self.assertIn('mac', pairs)
        self.assertEqual(pairs['admin'], 'true')
    
    @patch('length_extension_attack.LengthExtensionAttack.get_challenge_message')
    @patch('length_extension_attack.LengthExtensionAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get):
        """Test successful attack execution."""
        mock_get.return_value = "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"
        mock_submit.return_value = "¡Ganaste!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once()
    
    @patch('length_extension_attack.LengthExtensionAttack.get_challenge_message')
    def test_execute_attack_error(self, mock_get):
        """Test attack execution when getting challenge fails."""
        mock_get.side_effect = Exception("Network error")
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Network error", result)


class TestSHA256LengthExtension(unittest.TestCase):
    """Test cases for SHA256LengthExtension class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sha256_ext = SHA256LengthExtension()
    
    def test_sha256_padding(self):
        """Test SHA-256 padding calculation."""
        message_length = 20
        padding = self.sha256_ext.sha256_padding(message_length)
        
        # Check padding length
        total_length = message_length + len(padding)
        self.assertEqual(total_length % 64, 0)
        
        # Check padding starts with 0x80
        self.assertEqual(padding[0], 0x80)
        
        # Check last 8 bytes contain length
        length_bits = message_length * 8
        expected_length_bytes = struct.pack('>Q', length_bits)
        actual_length_bytes = padding[-8:]
        self.assertEqual(actual_length_bytes, expected_length_bytes)
    
    def test_sha256_extend_with_iv(self):
        """Test SHA-256 length extension with IV."""
        original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        original_length = 32
        extension = "admin" + "true"
        
        new_hash = self.sha256_ext.sha256_extend_with_iv(original_hash, original_length, extension)
        
        # Should return a valid hex string
        self.assertRegex(new_hash, r'^[0-9a-f]{64}$')
        self.assertEqual(len(new_hash), 64)


class TestLengthExtensionIntegration(unittest.TestCase):
    """Integration tests for length extension attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = LengthExtensionAttack()
    
    def test_message_construction_consistency(self):
        """Test that message construction is consistent."""
        test_cases = [
            {
                'user': 'user@example.com',
                'action': 'show'
            },
            {
                'user': 'test@test.com',
                'action': 'login',
                'role': 'user'
            },
            {
                'a': 'value1',
                'b': 'value2',
                'c': 'value3'
            }
        ]
        
        for pairs in test_cases:
            message = self.attack.build_message_from_pairs(pairs)
            
            # Message should be deterministic
            message2 = self.attack.build_message_from_pairs(pairs)
            self.assertEqual(message, message2)
            
            # Message should be sorted alphabetically
            sorted_keys = sorted(pairs.keys())
            expected_message = ''.join(f"{key}{pairs[key]}" for key in sorted_keys)
            self.assertEqual(message, expected_message)
    
    def test_padding_properties(self):
        """Test properties of SHA-256 padding."""
        for message_length in range(0, 200):
            padding = self.attack.sha256_padding(message_length)
            
            # Total length should be multiple of 64
            total_length = message_length + len(padding)
            self.assertEqual(total_length % 64, 0)
            
            # Padding should start with 0x80
            self.assertEqual(padding[0], 0x80)
            
            # Last 8 bytes should contain length
            length_bits = message_length * 8
            expected_length_bytes = struct.pack('>Q', length_bits)
            actual_length_bytes = padding[-8:]
            self.assertEqual(actual_length_bytes, expected_length_bytes)
    
    def test_query_string_parsing_edge_cases(self):
        """Test query string parsing with edge cases."""
        test_cases = [
            ("", {}),
            ("key=value", {'key': 'value'}),
            ("key1=value1&key2=value2", {'key1': 'value1', 'key2': 'value2'}),
            ("key=", {'key': ''}),
            ("=value", {'': 'value'}),
            ("key=value=with=equals", {'key': 'value=with=equals'}),
            ("key%20=value%20with%20spaces", {'key ': 'value with spaces'}),
        ]
        
        for query_string, expected_pairs in test_cases:
            pairs = self.attack.parse_query_string(query_string)
            self.assertEqual(pairs, expected_pairs)
    
    def test_message_building_edge_cases(self):
        """Test message building with edge cases."""
        test_cases = [
            ({}, ""),
            ({'mac': 'some_mac'}, ""),
            ({'user': 'test@example.com'}, "useruser@example.com"),
            ({'a': '1', 'b': '2', 'c': '3'}, "a1b2c3"),
            ({'z': 'last', 'a': 'first'}, "afirstzlast"),
        ]
        
        for pairs, expected_message in test_cases:
            message = self.attack.build_message_from_pairs(pairs)
            self.assertEqual(message, expected_message)
    
    def test_length_extension_attack_simulation(self):
        """Test complete length extension attack simulation."""
        # Simulate a challenge
        original_query = "user=user@example.com&action=show&mac=91868ee48413b57f2bdffb4ed280a5bfa936887985517b054b3108b8caeacf83"
        
        # Parse original query
        pairs = self.attack.parse_query_string(original_query)
        original_message = self.attack.build_message_from_pairs(pairs)
        
        print(f"Original message: {original_message}")
        
        # Forge query string
        with patch('builtins.print') as mock_print:
            forged_query = self.attack.forge_query_string(original_query)
        
        # Verify forged query structure
        forged_pairs = self.attack.parse_query_string(forged_query)
        
        # Should contain required fields
        self.assertIn('user', forged_pairs)
        self.assertIn('admin', forged_pairs)
        self.assertIn('mac', forged_pairs)
        
        # Admin should be true
        self.assertEqual(forged_pairs['admin'], 'true')
        
        # MAC should be present
        self.assertIsNotNone(forged_pairs['mac'])
        self.assertRegex(forged_pairs['mac'], r'^[0-9a-f]{64}$')
    
    def test_secret_prefix_mac_vulnerability(self):
        """Test the secret prefix MAC vulnerability."""
        # This test demonstrates why secret prefix MACs are vulnerable
        
        # Simulate original message and MAC
        secret = b"secret_key_16_by"  # 16 bytes
        original_message = b"actionshowuseruser@example.com"
        original_data = secret + original_message
        
        # Calculate original MAC
        original_mac = hashlib.sha256(original_data).hexdigest()
        
        # Now perform length extension attack
        extension = b"admin" + b"true"
        
        # Calculate padding for original data
        padding = self.attack.sha256_padding(len(original_data))
        
        # Create extended data
        extended_data = original_data + padding + extension
        
        # Calculate extended MAC
        extended_mac = hashlib.sha256(extended_data).hexdigest()
        
        print(f"Original MAC: {original_mac}")
        print(f"Extended MAC: {extended_mac}")
        
        # The extended MAC should be different from original
        self.assertNotEqual(original_mac, extended_mac)
        
        # Both should be valid SHA-256 hashes
        self.assertRegex(original_mac, r'^[0-9a-f]{64}$')
        self.assertRegex(extended_mac, r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
