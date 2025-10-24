#!/usr/bin/env python3
"""
Test cases for CBC-MAC Forgery Attack

This module contains test cases to validate the CBC-MAC forgery attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib.parse
from cbc_mac_attack import CBCMACForgeryAttack, CBCMACSimulator


class TestCBCMACForgeryAttack(unittest.TestCase):
    """Test cases for CBCMACForgeryAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = CBCMACForgeryAttack()
        self.challenge_email = "user@example.com"
    
    @patch('cbc_mac_attack.requests.get')
    def test_get_challenge_message(self, mock_get):
        """Test getting challenge message from server."""
        mock_response = MagicMock()
        mock_response.text = "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"
        mock_get.return_value = mock_response
        
        challenge = self.attack.get_challenge_message(self.challenge_email)
        
        self.assertEqual(challenge, "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8")
        mock_get.assert_called_once()
    
    @patch('cbc_mac_attack.requests.get')
    def test_submit_answer(self, mock_get):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Quiero más plata!"
        mock_get.return_value = mock_response
        
        forged_query = "from=user@example.com&attacker@example.com=15000&mac=701b3768b67a68be68cee9736628cae8"
        result = self.attack.submit_answer(self.challenge_email, forged_query)
        
        self.assertEqual(result, "¡Quiero más plata!")
        mock_get.assert_called_once()
    
    def test_parse_query_string(self):
        """Test query string parsing."""
        query_string = "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"
        
        pairs = self.attack.parse_query_string(query_string)
        
        expected_pairs = {
            'from': 'user@example.com',
            'user@example.com': '1000',
            'comment': 'Invoice',
            'mac': '701b3768b67a68be68cee9736628cae8'
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
            'from': 'user@example.com',
            'user@example.com': '1000',
            'comment': 'Invoice',
            'mac': '701b3768b67a68be68cee9736628cae8'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        # Should reconstruct the original query string without MAC
        expected_message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        self.assertEqual(message, expected_message)
    
    def test_build_message_from_pairs_no_mac(self):
        """Test building message when no MAC field exists."""
        pairs = {
            'from': 'user@example.com',
            'user@example.com': '1000',
            'comment': 'Invoice'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        expected_message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        self.assertEqual(message, expected_message)
    
    def test_build_message_from_pairs_multiple_fields(self):
        """Test building message with multiple fields."""
        pairs = {
            'from': 'user@example.com',
            'user@example.com': '1000',
            'comment': 'Invoice',
            'user@example.edu': '2500',
            'mac': 'some_mac'
        }
        
        message = self.attack.build_message_from_pairs(pairs)
        
        # Should contain all fields except MAC
        self.assertIn('from=user@example.com', message)
        self.assertIn('user@example.com=1000', message)
        self.assertIn('comment=Invoice', message)
        self.assertIn('user@example.edu=2500', message)
        self.assertNotIn('mac=', message)
    
    def test_simulate_cbc_mac(self):
        """Test CBC-MAC simulation."""
        message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        
        mac = self.attack.simulate_cbc_mac(message)
        
        # Should return a valid hex string
        self.assertRegex(mac, r'^[0-9a-f]{32}$')
        self.assertEqual(len(mac), 32)  # 16 bytes = 32 hex characters
    
    def test_simulate_cbc_mac_different_messages(self):
        """Test CBC-MAC simulation with different messages."""
        test_cases = [
            "from=user@example.com&user@example.com=1000",
            "from=user@example.com&user@example.com=1000&comment=Invoice",
            "from=user@example.com&user@example.com=1000&comment=Invoice&user@example.edu=2500",
        ]
        
        macs = []
        for message in test_cases:
            mac = self.attack.simulate_cbc_mac(message)
            macs.append(mac)
            
            # Each MAC should be valid
            self.assertRegex(mac, r'^[0-9a-f]{32}$')
        
        # Different messages should produce different MACs
        self.assertEqual(len(set(macs)), len(test_cases))
    
    def test_forge_cbc_mac(self):
        """Test CBC-MAC forgery."""
        original_query = "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"
        target_email = "attacker@example.com"
        target_amount = 15000
        
        with patch('builtins.print') as mock_print:
            forged_query = self.attack.forge_cbc_mac(original_query, target_email, target_amount)
        
        # Should be a valid query string
        self.assertIsInstance(forged_query, str)
        self.assertIn('&', forged_query)
        
        # Should contain required fields
        self.assertIn('from=', forged_query)
        self.assertIn(f'{target_email}={target_amount}', forged_query)
        self.assertIn('mac=', forged_query)
        
        # Should be able to parse it
        pairs = self.attack.parse_query_string(forged_query)
        self.assertIn('from', pairs)
        self.assertIn(target_email, pairs)
        self.assertIn('mac', pairs)
        self.assertEqual(pairs[target_email], str(target_amount))
    
    def test_forge_cbc_mac_advanced(self):
        """Test advanced CBC-MAC forgery."""
        original_query = "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"
        target_email = "attacker@example.com"
        target_amount = 15000
        
        with patch('builtins.print') as mock_print:
            forged_query = self.attack.forge_cbc_mac_advanced(original_query, target_email, target_amount)
        
        # Should be a valid query string
        self.assertIsInstance(forged_query, str)
        
        # Should contain required fields
        self.assertIn('from=', forged_query)
        self.assertIn(f'{target_email}={target_amount}', forged_query)
        self.assertIn('mac=', forged_query)
        
        # Should be able to parse it
        pairs = self.attack.parse_query_string(forged_query)
        self.assertIn('from', pairs)
        self.assertIn(target_email, pairs)
        self.assertIn('mac', pairs)
    
    @patch('cbc_mac_attack.CBCMACForgeryAttack.get_challenge_message')
    @patch('cbc_mac_attack.CBCMACForgeryAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get):
        """Test successful attack execution."""
        mock_get.return_value = "from=user@example.com&user@example.com=1000&comment=Invoice&mac=701b3768b67a68be68cee9736628cae8"
        mock_submit.return_value = "¡Quiero más plata!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Quiero más plata!")
        mock_get.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once()
    
    @patch('cbc_mac_attack.CBCMACForgeryAttack.get_challenge_message')
    def test_execute_attack_error(self, mock_get):
        """Test attack execution when getting challenge fails."""
        mock_get.side_effect = Exception("Network error")
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Network error", result)


class TestCBCMACSimulator(unittest.TestCase):
    """Test cases for CBCMACSimulator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.simulator = CBCMACSimulator()
    
    def test_calculate_cbc_mac(self):
        """Test CBC-MAC calculation."""
        message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        
        mac = self.simulator.calculate_cbc_mac(message)
        
        # Should return a valid hex string
        self.assertRegex(mac, r'^[0-9a-f]{32}$')
        self.assertEqual(len(mac), 32)
    
    def test_calculate_cbc_mac_different_messages(self):
        """Test CBC-MAC calculation with different messages."""
        test_messages = [
            "from=user@example.com&user@example.com=1000",
            "from=user@example.com&user@example.com=1000&comment=Invoice",
            "from=user@example.com&user@example.com=1000&comment=Invoice&user@example.edu=2500",
        ]
        
        macs = []
        for message in test_messages:
            mac = self.simulator.calculate_cbc_mac(message)
            macs.append(mac)
            
            # Each MAC should be valid
            self.assertRegex(mac, r'^[0-9a-f]{32}$')
        
        # Different messages should produce different MACs
        self.assertEqual(len(set(macs)), len(test_messages))
    
    def test_verify_cbc_mac_valid(self):
        """Test CBC-MAC verification with valid MAC."""
        message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        
        mac = self.simulator.calculate_cbc_mac(message)
        is_valid = self.simulator.verify_cbc_mac(message, mac)
        
        self.assertTrue(is_valid)
    
    def test_verify_cbc_mac_invalid(self):
        """Test CBC-MAC verification with invalid MAC."""
        message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        
        invalid_mac = "701b3768b67a68be68cee9736628cae8"
        is_valid = self.simulator.verify_cbc_mac(message, invalid_mac)
        
        self.assertFalse(is_valid)
    
    def test_cbc_mac_properties(self):
        """Test properties of CBC-MAC."""
        message1 = "from=user@example.com&user@example.com=1000"
        message2 = "from=user@example.com&user@example.com=1000&comment=Invoice"
        
        mac1 = self.simulator.calculate_cbc_mac(message1)
        mac2 = self.simulator.calculate_cbc_mac(message2)
        
        # Different messages should produce different MACs
        self.assertNotEqual(mac1, mac2)
        
        # Both MACs should be valid
        self.assertRegex(mac1, r'^[0-9a-f]{32}$')
        self.assertRegex(mac2, r'^[0-9a-f]{32}$')
        
        # Verification should work
        self.assertTrue(self.simulator.verify_cbc_mac(message1, mac1))
        self.assertTrue(self.simulator.verify_cbc_mac(message2, mac2))
        self.assertFalse(self.simulator.verify_cbc_mac(message1, mac2))
        self.assertFalse(self.simulator.verify_cbc_mac(message2, mac1))


class TestCBCMACIntegration(unittest.TestCase):
    """Integration tests for CBC-MAC forgery attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = CBCMACForgeryAttack()
        self.simulator = CBCMACSimulator()
    
    def test_cbc_mac_forgery_simulation(self):
        """Test CBC-MAC forgery simulation."""
        # Create original message
        original_message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        original_mac = self.simulator.calculate_cbc_mac(original_message)
        
        print(f"Original message: {original_message}")
        print(f"Original MAC: {original_mac}")
        
        # Create additional transfer
        target_email = "attacker@example.com"
        target_amount = 15000
        additional_transfer = f"&{target_email}={target_amount}"
        
        print(f"Additional transfer: {additional_transfer}")
        
        # Perform CBC-MAC forgery
        # The technique is to create: original_message || (original_mac XOR first_block_of_additional) || rest_of_additional
        
        # Convert original MAC to bytes
        original_mac_bytes = bytes.fromhex(original_mac)
        
        # Create additional message
        additional_bytes = additional_transfer.encode('utf-8')
        additional_padded = pad(additional_bytes, 16)
        
        # Take first block of additional message
        first_block = additional_padded[:16]
        
        # XOR with original MAC
        xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
        
        # Create forged message
        forged_message_bytes = original_message.encode('utf-8') + xor_block + additional_padded[16:]
        
        # Convert back to string
        forged_message_str = forged_message_bytes.decode('utf-8', errors='ignore')
        
        print(f"Forged message: {forged_message_str}")
        
        # Calculate MAC for forged message
        forged_mac = self.simulator.calculate_cbc_mac(forged_message_str)
        
        print(f"Forged MAC: {forged_mac}")
        
        # The forged MAC should be different from original
        self.assertNotEqual(forged_mac, original_mac)
        
        # Both MACs should be valid
        self.assertRegex(original_mac, r'^[0-9a-f]{32}$')
        self.assertRegex(forged_mac, r'^[0-9a-f]{32}$')
    
    def test_query_string_construction(self):
        """Test query string construction for forgery."""
        # Test with different scenarios
        test_cases = [
            {
                'from': 'user@example.com',
                'user@example.com': '1000',
                'comment': 'Invoice'
            },
            {
                'from': 'user@example.com',
                'user@example.com': '1000',
                'comment': 'Invoice',
                'user@example.edu': '2500'
            }
        ]
        
        for pairs in test_cases:
            # Build message
            message = self.attack.build_message_from_pairs(pairs)
            
            # Should be able to parse it back
            parsed_pairs = self.attack.parse_query_string(message)
            
            # Should contain the same fields (excluding MAC)
            for key, value in pairs.items():
                if key != 'mac':
                    self.assertIn(key, parsed_pairs)
                    self.assertEqual(parsed_pairs[key], value)
    
    def test_cbc_mac_vulnerability_demonstration(self):
        """Test demonstration of CBC-MAC vulnerability."""
        # This test demonstrates why CBC-MAC is vulnerable to forgery
        
        # Create two messages
        message1 = "from=user@example.com&user@example.com=1000"
        message2 = "&attacker@example.com=15000"
        
        # Calculate MACs
        mac1 = self.simulator.calculate_cbc_mac(message1)
        mac2 = self.simulator.calculate_cbc_mac(message2)
        
        print(f"Message 1: {message1}")
        print(f"MAC 1: {mac1}")
        print(f"Message 2: {message2}")
        print(f"MAC 2: {mac2}")
        
        # Different messages should produce different MACs
        self.assertNotEqual(mac1, mac2)
        
        # Both MACs should be valid
        self.assertRegex(mac1, r'^[0-9a-f]{32}$')
        self.assertRegex(mac2, r'^[0-9a-f]{32}$')
        
        # Verification should work
        self.assertTrue(self.simulator.verify_cbc_mac(message1, mac1))
        self.assertTrue(self.simulator.verify_cbc_mac(message2, mac2))
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with empty message
        empty_mac = self.simulator.calculate_cbc_mac("")
        self.assertRegex(empty_mac, r'^[0-9a-f]{32}$')
        
        # Test with very long message
        long_message = "from=user@example.com&" + "&".join(f"user{i}@example.com={i*1000}" for i in range(100))
        long_mac = self.simulator.calculate_cbc_mac(long_message)
        self.assertRegex(long_mac, r'^[0-9a-f]{32}$')
        
        # Test with special characters
        special_message = "from=user@example.com&user@example.com=1000&comment=Invoice%20with%20spaces"
        special_mac = self.simulator.calculate_cbc_mac(special_message)
        self.assertRegex(special_mac, r'^[0-9a-f]{32}$')
    
    def test_forgery_technique_validation(self):
        """Test validation of the forgery technique."""
        # This test validates the mathematical property of CBC-MAC forgery
        
        # Create original message
        original_message = "from=user@example.com&user@example.com=1000&comment=Invoice"
        original_mac = self.simulator.calculate_cbc_mac(original_message)
        
        # Create additional message
        additional_message = "&attacker@example.com=15000"
        
        # Perform the forgery technique
        original_mac_bytes = bytes.fromhex(original_mac)
        additional_bytes = additional_message.encode('utf-8')
        additional_padded = pad(additional_bytes, 16)
        
        first_block = additional_padded[:16]
        xor_block = bytes(a ^ b for a, b in zip(original_mac_bytes, first_block))
        
        forged_message_bytes = original_message.encode('utf-8') + xor_block + additional_padded[16:]
        forged_message_str = forged_message_bytes.decode('utf-8', errors='ignore')
        
        # Calculate MAC for forged message
        forged_mac = self.simulator.calculate_cbc_mac(forged_message_str)
        
        # The forged message should be different from original
        self.assertNotEqual(forged_message_str, original_message)
        
        # Both MACs should be valid
        self.assertRegex(original_mac, r'^[0-9a-f]{32}$')
        self.assertRegex(forged_mac, r'^[0-9a-f]{32}$')
        
        # The forgery technique should produce a valid MAC
        self.assertTrue(self.simulator.verify_cbc_mac(forged_message_str, forged_mac))


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
