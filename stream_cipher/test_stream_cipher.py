#!/usr/bin/env python3
"""
Test cases for Stream Cipher Keystream Recovery Attack

This module contains test cases to validate the stream cipher keystream recovery attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
from collections import Counter
from stream_cipher_attack import StreamCipherAttack, StreamCipherOracle


class TestStreamCipherAttack(unittest.TestCase):
    """Test cases for StreamCipherAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = StreamCipherAttack()
        self.challenge_email = "user@example.com"
    
    @patch('stream_cipher_attack.requests.get')
    def test_get_challenge_data(self, mock_get):
        """Test getting challenge data from server."""
        # Mock response with 5 base64 encoded ciphertexts
        mock_response = MagicMock()
        mock_response.text = """hkxtTle46yPd7+HUdCWil1SEcirX6pQkOy6qn4NqS0urGbLZyvId
k5b0ZMGj0N8AHLYs0JygHFqG30A3NlUdD75GuHHIdrwt1gwvcHKp
wQ0iARj/q2OboKGaMGfj0xrKN2WSqtJkf2jp0cQvCw/rW/KZhbZb
3lYYDozTZa0yZn5BEBL+TYmhjSwD1SWlwZheH3xal9VsKm96smlI
snhZemOM3xfp29XgQBGWo2CwRh7j3qAQDxqeq7def3+fLYbt/sYp"""
        mock_get.return_value = mock_response
        
        ciphertexts = self.attack.get_challenge_data(self.challenge_email)
        
        self.assertEqual(len(ciphertexts), 5)
        self.assertIsInstance(ciphertexts[0], bytes)
        mock_get.assert_called_once()
    
    @patch('stream_cipher_attack.requests.get')
    def test_get_single_ciphertext(self, mock_get):
        """Test getting a single ciphertext by ID."""
        mock_response = MagicMock()
        mock_response.text = "hkxtTle46yPd7+HUdCWil1SEcirX6pQkOy6qn4NqS0urGbLZyvId"
        mock_get.return_value = mock_response
        
        ciphertext = self.attack.get_single_ciphertext(self.challenge_email, 0)
        
        self.assertIsInstance(ciphertext, bytes)
        mock_get.assert_called_once()
    
    @patch('stream_cipher_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        keystream = b"test_keystream_16_bytes"
        result = self.attack.submit_answer(self.challenge_email, keystream)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
        
        # Check that keystream was base64 encoded
        call_args = mock_post.call_args
        keystream_b64 = call_args[1]['data']['keystream']
        self.assertEqual(keystream_b64, base64.b64encode(keystream).decode('utf-8'))
    
    def test_analyze_ciphertexts_same_length(self):
        """Test ciphertext analysis with same length messages."""
        ciphertexts = [
            b"A" * 20,
            b"B" * 20,
            b"C" * 20,
            b"D" * 20,
            b"E" * 20
        ]
        
        with patch('builtins.print') as mock_print:
            analysis = self.attack.analyze_ciphertexts(ciphertexts)
        
        self.assertTrue(analysis['all_same_length'])
        self.assertEqual(analysis['common_length'], 20)
        self.assertEqual(len(analysis['lengths']), 5)
    
    def test_analyze_ciphertexts_different_lengths(self):
        """Test ciphertext analysis with different length messages."""
        ciphertexts = [
            b"A" * 20,
            b"B" * 25,
            b"C" * 20,
            b"D" * 30,
            b"E" * 20
        ]
        
        with patch('builtins.print') as mock_print:
            analysis = self.attack.analyze_ciphertexts(ciphertexts)
        
        self.assertFalse(analysis['all_same_length'])
        self.assertIsNone(analysis['common_length'])
    
    def test_find_repeated_character_messages(self):
        """Test finding repeated character messages."""
        # Create test ciphertexts with different entropy levels
        ciphertexts = [
            b"A" * 20,  # Low entropy - repeated character
            b"ABCDEFGHIJKLMNOPQRST",  # High entropy - varied characters
            b"B" * 20,  # Low entropy - repeated character
            b"12345678901234567890",  # Medium entropy
            b"C" * 20   # Low entropy - repeated character
        ]
        
        with patch('builtins.print') as mock_print:
            repeated_indices = self.attack.find_repeated_character_messages(ciphertexts)
        
        # Should find messages 0, 2, and 4 as repeated characters
        self.assertIn(0, repeated_indices)
        self.assertIn(2, repeated_indices)
        self.assertIn(4, repeated_indices)
        self.assertNotIn(1, repeated_indices)
        self.assertNotIn(3, repeated_indices)
    
    def test_recover_keystream_from_repeated_chars(self):
        """Test keystream recovery from repeated character messages."""
        # Create test keystream
        keystream = b"test_keystream_16"
        
        # Create oracle for testing
        oracle = StreamCipherOracle(keystream)
        
        # Create repeated character messages
        msg1 = "A" * 20
        msg2 = "B" * 20
        
        ct1 = oracle.encrypt_message(msg1)
        ct2 = oracle.encrypt_message(msg2)
        
        ciphertexts = [ct1, ct2, b"dummy", b"dummy", b"dummy"]
        
        with patch('builtins.print') as mock_print:
            recovered_keystream = self.attack.recover_keystream_from_repeated_chars(ciphertexts, [0, 1])
        
        # Should recover the keystream (truncated to message length)
        expected_keystream = keystream[:20]
        self.assertEqual(recovered_keystream, expected_keystream)
    
    def test_recover_keystream_insufficient_messages(self):
        """Test keystream recovery with insufficient repeated character messages."""
        ciphertexts = [b"A" * 20, b"B" * 20, b"C" * 20, b"D" * 20, b"E" * 20]
        
        with self.assertRaises(ValueError):
            self.attack.recover_keystream_from_repeated_chars(ciphertexts, [0])
    
    def test_find_even_number_message(self):
        """Test finding even number message."""
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        # Create test messages
        messages = ["12345678", "AAAAAAAA", "BBBBBBBB", "87654321", "CCCCCCCC"]
        ciphertexts = [oracle.encrypt_message(msg) for msg in messages]
        
        with patch('builtins.print') as mock_print:
            even_index = self.attack.find_even_number_message(ciphertexts, keystream)
        
        # Message 0 ("12345678") should be the even number
        self.assertEqual(even_index, 0)
    
    def test_find_even_number_message_no_even(self):
        """Test finding even number message when none exists."""
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        # Create test messages with only odd numbers
        messages = ["12345679", "AAAAAAAA", "BBBBBBBB", "87654321", "CCCCCCCC"]
        ciphertexts = [oracle.encrypt_message(msg) for msg in messages]
        
        with patch('builtins.print') as mock_print:
            even_index = self.attack.find_even_number_message(ciphertexts, keystream)
        
        self.assertIsNone(even_index)
    
    def test_verify_keystream(self):
        """Test keystream verification."""
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        # Create test messages
        messages = ["12345678", "AAAAAAAA", "BBBBBBBB", "87654321", "CCCCCCCC"]
        ciphertexts = [oracle.encrypt_message(msg) for msg in messages]
        
        with patch('builtins.print') as mock_print:
            verification = self.attack.verify_keystream(ciphertexts, keystream)
        
        self.assertEqual(verification['valid_messages'], 5)
        self.assertEqual(len(verification['decrypted_messages']), 5)
        self.assertEqual(verification['repeated_char_messages'], [1, 2, 4])
        self.assertEqual(verification['even_number_message'], 0)
        
        # Check decrypted messages
        for i, decrypted in enumerate(verification['decrypted_messages']):
            self.assertEqual(decrypted, messages[i])
    
    @patch('stream_cipher_attack.StreamCipherAttack.get_challenge_data')
    @patch('stream_cipher_attack.StreamCipherAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get_data):
        """Test successful attack execution."""
        # Create test data
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        messages = ["12345678", "AAAAAAAA", "BBBBBBBB", "87654321", "CCCCCCCC"]
        ciphertexts = [oracle.encrypt_message(msg) for msg in messages]
        
        mock_get_data.return_value = ciphertexts
        mock_submit.return_value = "¡Ganaste!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get_data.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once()
    
    @patch('stream_cipher_attack.StreamCipherAttack.get_challenge_data')
    def test_execute_attack_different_lengths(self, mock_get_data):
        """Test attack execution with different length messages."""
        ciphertexts = [
            b"A" * 20,
            b"B" * 25,
            b"C" * 20,
            b"D" * 30,
            b"E" * 20
        ]
        
        mock_get_data.return_value = ciphertexts
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("misma longitud", result)


class TestStreamCipherOracle(unittest.TestCase):
    """Test cases for StreamCipherOracle class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.keystream = b"test_keystream_16"
        self.oracle = StreamCipherOracle(self.keystream)
    
    def test_encrypt_message_basic(self):
        """Test basic message encryption."""
        plaintext = "Hello, World!"
        ciphertext = self.oracle.encrypt_message(plaintext)
        
        self.assertIsInstance(ciphertext, bytes)
        self.assertEqual(len(ciphertext), len(plaintext))
    
    def test_encrypt_message_keystream_repetition(self):
        """Test encryption with keystream repetition."""
        plaintext = "A" * 50  # Longer than keystream
        ciphertext = self.oracle.encrypt_message(plaintext)
        
        self.assertEqual(len(ciphertext), len(plaintext))
    
    def test_decrypt_message(self):
        """Test message decryption."""
        plaintext = "Test message"
        ciphertext = self.oracle.encrypt_message(plaintext)
        decrypted = self.oracle.decrypt_message(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt-decrypt roundtrip."""
        test_messages = [
            "Hello, World!",
            "AAAAAAAA",
            "12345678",
            "Special chars: !@#$%^&*()",
            "A" * 100  # Long message
        ]
        
        for message in test_messages:
            ciphertext = self.oracle.encrypt_message(message)
            decrypted = self.oracle.decrypt_message(ciphertext)
            self.assertEqual(decrypted, message)
    
    def test_different_keystreams(self):
        """Test that different keystreams produce different results."""
        keystream1 = b"keystream1_16"
        keystream2 = b"keystream2_16"
        
        oracle1 = StreamCipherOracle(keystream1)
        oracle2 = StreamCipherOracle(keystream2)
        
        plaintext = "Test message"
        ciphertext1 = oracle1.encrypt_message(plaintext)
        ciphertext2 = oracle2.encrypt_message(plaintext)
        
        self.assertNotEqual(ciphertext1, ciphertext2)
    
    def test_same_keystream_same_result(self):
        """Test that same keystream produces same result."""
        plaintext = "Test message"
        ciphertext1 = self.oracle.encrypt_message(plaintext)
        ciphertext2 = self.oracle.encrypt_message(plaintext)
        
        self.assertEqual(ciphertext1, ciphertext2)


class TestStreamCipherIntegration(unittest.TestCase):
    """Integration tests for stream cipher attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = StreamCipherAttack()
    
    def test_full_attack_simulation(self):
        """Test complete attack simulation."""
        # Create test keystream
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        # Create test messages matching the challenge requirements
        messages = [
            "12345678",  # Even number
            "AAAAAAAA",  # Repeated character
            "BBBBBBBB",  # Repeated character
            "87654321",  # Odd number
            "CCCCCCCC"   # Repeated character
        ]
        
        ciphertexts = [oracle.encrypt_message(msg) for msg in messages]
        
        with patch('builtins.print') as mock_print:
            # Test individual components
            analysis = self.attack.analyze_ciphertexts(ciphertexts)
            repeated_indices = self.attack.find_repeated_character_messages(ciphertexts)
            recovered_keystream = self.attack.recover_keystream_from_repeated_chars(ciphertexts, repeated_indices)
            verification = self.attack.verify_keystream(ciphertexts, recovered_keystream)
        
        # Verify results
        self.assertTrue(analysis['all_same_length'])
        self.assertEqual(len(repeated_indices), 3)  # Should find 3 repeated character messages
        self.assertEqual(recovered_keystream, keystream[:len(messages[0])])
        self.assertEqual(verification['valid_messages'], 5)
        self.assertEqual(verification['even_number_message'], 0)
    
    def test_keystream_recovery_accuracy(self):
        """Test accuracy of keystream recovery."""
        test_cases = [
            ("A", "B"),  # Simple case
            ("X", "Y"),  # Different characters
            ("1", "2"),  # Digits
            ("!", "@"),  # Special characters
        ]
        
        for char1, char2 in test_cases:
            keystream = b"test_keystream_16"
            oracle = StreamCipherOracle(keystream)
            
            msg1 = char1 * 20
            msg2 = char2 * 20
            
            ct1 = oracle.encrypt_message(msg1)
            ct2 = oracle.encrypt_message(msg2)
            
            ciphertexts = [ct1, ct2, b"dummy", b"dummy", b"dummy"]
            
            with patch('builtins.print') as mock_print:
                recovered_keystream = self.attack.recover_keystream_from_repeated_chars(ciphertexts, [0, 1])
            
            expected_keystream = keystream[:20]
            self.assertEqual(recovered_keystream, expected_keystream, 
                           f"Failed for characters '{char1}' and '{char2}'")
    
    def test_message_characteristics_detection(self):
        """Test detection of message characteristics."""
        keystream = b"test_keystream_16"
        oracle = StreamCipherOracle(keystream)
        
        # Test various message types
        test_cases = [
            ("12345678", "even_number"),
            ("12345679", "odd_number"),
            ("AAAAAAAA", "repeated_char"),
            ("ABCDEFGH", "varied_chars"),
            ("!@#$%^&*", "special_chars"),
        ]
        
        for message, expected_type in test_cases:
            ciphertext = oracle.encrypt_message(message)
            
            with patch('builtins.print') as mock_print:
                verification = self.attack.verify_keystream([ciphertext], keystream)
            
            decrypted = verification['decrypted_messages'][0]
            self.assertEqual(decrypted, message)
            
            # Check specific characteristics
            if expected_type == "even_number":
                self.assertTrue(decrypted.isdigit() and int(decrypted) % 2 == 0)
            elif expected_type == "odd_number":
                self.assertTrue(decrypted.isdigit() and int(decrypted) % 2 == 1)
            elif expected_type == "repeated_char":
                self.assertEqual(len(set(decrypted)), 1)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
