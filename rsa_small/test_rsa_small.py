#!/usr/bin/env python3
"""
Test cases for RSA Small Key Attack

This module contains test cases to validate the RSA small key attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
import json
import math
from Crypto.Util.number import bytes_to_long, long_to_bytes
from rsa_small_attack import RSASmallKeyAttack, RSASimulator


class TestRSASmallKeyAttack(unittest.TestCase):
    """Test cases for RSASmallKeyAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = RSASmallKeyAttack()
        self.challenge_email = "user@example.com"
    
    @patch('rsa_small_attack.requests.get')
    def test_get_challenge_data(self, mock_get):
        """Test getting challenge data from server."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ciphertext": "F332Sky0PE/V66kPNpptl31WvFcV7DrpBQNhy6A/CxE=",
            "publicKey": {
                "n": 77262254401757173704176537879040630528030014454582493152384619617572796723617,
                "e": 65537
            }
        }
        mock_get.return_value = mock_response
        
        data = self.attack.get_challenge_data(self.challenge_email)
        
        self.assertIn('ciphertext', data)
        self.assertIn('publicKey', data)
        self.assertEqual(data['publicKey']['e'], 65537)
        mock_get.assert_called_once()
    
    @patch('rsa_small_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        plaintext = "Hello, World!"
        result = self.attack.submit_answer(self.challenge_email, plaintext)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_parse_challenge_data(self):
        """Test parsing challenge data."""
        data = {
            "ciphertext": "F332Sky0PE/V66kPNpptl31WvFcV7DrpBQNhy6A/CxE=",
            "publicKey": {
                "n": 77262254401757173704176537879040630528030014454582493152384619617572796723617,
                "e": 65537
            }
        }
        
        ciphertext_bytes, n, e = self.attack.parse_challenge_data(data)
        
        self.assertIsInstance(ciphertext_bytes, bytes)
        self.assertEqual(e, 65537)
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)
    
    def test_trial_division(self):
        """Test trial division factorization."""
        # Test with small composite numbers
        test_cases = [
            (15, 3),      # 15 = 3 * 5
            (21, 3),      # 21 = 3 * 7
            (35, 5),      # 35 = 5 * 7
            (49, 7),      # 49 = 7 * 7
            (77, 7),      # 77 = 7 * 11
        ]
        
        for n, expected_factor in test_cases:
            factor = self.attack.trial_division(n)
            self.assertEqual(factor, expected_factor)
            self.assertEqual(n % factor, 0)
    
    def test_trial_division_prime(self):
        """Test trial division with prime numbers."""
        primes = [17, 19, 23, 29, 31, 37, 41, 43, 47]
        
        for prime in primes:
            factor = self.attack.trial_division(prime)
            self.assertIsNone(factor)
    
    def test_pollard_rho(self):
        """Test Pollard's rho algorithm."""
        # Test with small composite numbers
        test_cases = [15, 21, 35, 49, 77, 91, 143]
        
        for n in test_cases:
            factor = self.attack.pollard_rho(n)
            if factor:
                self.assertGreater(factor, 1)
                self.assertLess(factor, n)
                self.assertEqual(n % factor, 0)
    
    def test_fermat_factorization(self):
        """Test Fermat's factorization method."""
        # Test with numbers that are products of two close primes
        test_cases = [
            (15, (3, 5)),
            (21, (3, 7)),
            (35, (5, 7)),
            (143, (11, 13)),
        ]
        
        for n, expected_factors in test_cases:
            factors = self.attack.fermat_factorization(n)
            if factors:
                p, q = factors
                self.assertEqual(p * q, n)
                self.assertIn(p, expected_factors)
                self.assertIn(q, expected_factors)
    
    def test_factorize(self):
        """Test complete factorization."""
        # Test with small composite numbers
        test_cases = [
            (15, (3, 5)),
            (21, (3, 7)),
            (35, (5, 7)),
            (77, (7, 11)),
            (143, (11, 13)),
        ]
        
        for n, expected_factors in test_cases:
            p, q = self.attack.factorize(n)
            self.assertEqual(p * q, n)
            self.assertIn(p, expected_factors)
            self.assertIn(q, expected_factors)
    
    def test_calculate_private_key(self):
        """Test private key calculation."""
        # Test with known values
        p, q, e = 3, 5, 7
        expected_d = 3  # 7 * 3 ≡ 1 (mod 8)
        
        d = self.attack.calculate_private_key(p, q, e)
        self.assertEqual(d, expected_d)
        
        # Verify: e * d ≡ 1 (mod phi)
        phi = (p - 1) * (q - 1)
        self.assertEqual((e * d) % phi, 1)
    
    def test_modular_inverse(self):
        """Test modular inverse calculation."""
        test_cases = [
            (3, 7, 5),      # 3 * 5 ≡ 1 (mod 7)
            (5, 11, 9),     # 5 * 9 ≡ 1 (mod 11)
            (7, 13, 2),     # 7 * 2 ≡ 1 (mod 13)
            (1, 5, 1),      # 1 * 1 ≡ 1 (mod 5)
        ]
        
        for a, m, expected in test_cases:
            result = self.attack.modular_inverse(a, m)
            self.assertEqual(result, expected)
            self.assertEqual((a * result) % m, 1)
    
    def test_modular_inverse_invalid(self):
        """Test modular inverse with invalid inputs."""
        with self.assertRaises(ValueError):
            self.attack.modular_inverse(2, 4)  # gcd(2, 4) = 2 ≠ 1
        
        with self.assertRaises(ValueError):
            self.attack.modular_inverse(6, 9)  # gcd(6, 9) = 3 ≠ 1
    
    def test_decrypt_rsa(self):
        """Test RSA decryption."""
        # Test with small values
        p, q, e = 3, 5, 7
        n = p * q
        d = self.attack.calculate_private_key(p, q, e)
        
        # Test message
        message = b"test"
        m = bytes_to_long(message)
        
        # Encrypt
        c = pow(m, e, n)
        ciphertext = long_to_bytes(c)
        
        # Decrypt
        decrypted = self.attack.decrypt_rsa(ciphertext, n, d)
        
        self.assertEqual(decrypted, message)
    
    def test_remove_pkcs1_padding(self):
        """Test PKCS#1 v1.5 padding removal."""
        # Test with valid padding
        data = b"Hello"
        padded_data = b'\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff\x00' + data
        
        result = self.attack.remove_pkcs1_padding(padded_data)
        self.assertEqual(result, data)
    
    def test_remove_pkcs1_padding_invalid(self):
        """Test PKCS#1 v1.5 padding removal with invalid padding."""
        # Test with invalid first byte
        with self.assertRaises(ValueError):
            self.attack.remove_pkcs1_padding(b'\x01\x02\xff\x00Hello')
        
        # Test with invalid second byte
        with self.assertRaises(ValueError):
            self.attack.remove_pkcs1_padding(b'\x00\x01\xff\x00Hello')
        
        # Test with no separator
        with self.assertRaises(ValueError):
            self.attack.remove_pkcs1_padding(b'\x00\x02\xff\xff\xff')
    
    def test_perform_small_key_attack(self):
        """Test complete small key attack."""
        # Create test data
        p, q, e = 3, 5, 7
        n = p * q
        d = self.attack.calculate_private_key(p, q, e)
        
        # Create test message
        message = "Hello, World!"
        message_bytes = message.encode('utf-8')
        
        # Add PKCS#1 v1.5 padding
        padded_data = b'\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff\x00' + message_bytes
        
        # Encrypt
        m = bytes_to_long(padded_data)
        c = pow(m, e, n)
        ciphertext = long_to_bytes(c)
        
        # Perform attack
        with patch('builtins.print') as mock_print:
            result = self.attack.perform_small_key_attack(ciphertext, n, e)
        
        self.assertEqual(result, message)
    
    @patch('rsa_small_attack.RSASmallKeyAttack.get_challenge_data')
    @patch('rsa_small_attack.RSASmallKeyAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get):
        """Test successful attack execution."""
        mock_get.return_value = {
            "ciphertext": "F332Sky0PE/V66kPNpptl31WvFcV7DrpBQNhy6A/CxE=",
            "publicKey": {
                "n": 15,  # Small number for testing
                "e": 7
            }
        }
        mock_submit.return_value = "¡Ganaste!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once()
    
    @patch('rsa_small_attack.RSASmallKeyAttack.get_challenge_data')
    def test_execute_attack_error(self, mock_get):
        """Test attack execution when getting challenge fails."""
        mock_get.side_effect = Exception("Network error")
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Network error", result)


class TestRSASimulator(unittest.TestCase):
    """Test cases for RSASimulator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Use small primes for testing
        self.p, self.q, self.e = 3, 5, 7
        self.simulator = RSASimulator(self.p, self.q, self.e)
    
    def test_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        plaintext = "Hello, World!"
        
        # Encrypt
        ciphertext = self.simulator.encrypt(plaintext)
        
        # Decrypt
        decrypted = self.simulator.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_different_messages(self):
        """Test encryption with different messages."""
        messages = [
            "Short",
            "This is a longer message",
            "Special characters: !@#$%^&*()",
            "Unicode: ñáéíóú",
        ]
        
        for message in messages:
            ciphertext = self.simulator.encrypt(message)
            decrypted = self.simulator.decrypt(ciphertext)
            self.assertEqual(decrypted, message)
    
    def test_pkcs1_padding(self):
        """Test PKCS#1 v1.5 padding."""
        data = b"test"
        padded_data = self.simulator.add_pkcs1_padding(data)
        
        # Check padding structure
        self.assertEqual(padded_data[0], 0x00)
        self.assertEqual(padded_data[1], 0x02)
        
        # Find separator
        separator_index = None
        for i in range(2, len(padded_data)):
            if padded_data[i] == 0x00:
                separator_index = i
                break
        
        self.assertIsNotNone(separator_index)
        
        # Check data
        actual_data = padded_data[separator_index + 1:]
        self.assertEqual(actual_data, data)
    
    def test_pkcs1_padding_removal(self):
        """Test PKCS#1 v1.5 padding removal."""
        data = b"test"
        padded_data = self.simulator.add_pkcs1_padding(data)
        
        removed_data = self.simulator.remove_pkcs1_padding(padded_data)
        self.assertEqual(removed_data, data)
    
    def test_modular_inverse(self):
        """Test modular inverse calculation."""
        test_cases = [
            (3, 7, 5),
            (5, 11, 9),
            (7, 13, 2),
        ]
        
        for a, m, expected in test_cases:
            result = self.simulator.modular_inverse(a, m)
            self.assertEqual(result, expected)
            self.assertEqual((a * result) % m, 1)


class TestRSASmallKeyIntegration(unittest.TestCase):
    """Integration tests for RSA small key attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = RSASmallKeyAttack()
        self.simulator = RSASimulator(3, 5, 7)
    
    def test_complete_attack_simulation(self):
        """Test complete attack simulation."""
        # Create test message
        plaintext = "Hello, World!"
        
        # Encrypt using simulator
        ciphertext = self.simulator.encrypt(plaintext)
        
        print(f"Original plaintext: {plaintext}")
        print(f"Ciphertext: {ciphertext.hex()}")
        
        # Perform attack
        with patch('builtins.print') as mock_print:
            recovered_plaintext = self.attack.perform_small_key_attack(
                ciphertext, self.simulator.n, self.simulator.e
            )
        
        print(f"Recovered plaintext: {recovered_plaintext}")
        
        # Should match original
        self.assertEqual(recovered_plaintext, plaintext)
    
    def test_factorization_methods_comparison(self):
        """Test comparison of different factorization methods."""
        test_numbers = [15, 21, 35, 77, 143, 221]
        
        for n in test_numbers:
            print(f"\nTesting factorization of {n}")
            
            # Try different methods
            methods = [
                ("Trial Division", lambda x: self.attack.trial_division(x)),
                ("Pollard's Rho", lambda x: self.attack.pollard_rho(x)),
                ("Fermat", lambda x: self.attack.fermat_factorization(x)),
            ]
            
            for method_name, method_func in methods:
                try:
                    result = method_func(n)
                    if result:
                        if isinstance(result, tuple):
                            p, q = result
                            print(f"{method_name}: {p} * {q} = {n}")
                        else:
                            other = n // result
                            print(f"{method_name}: {result} * {other} = {n}")
                        break
                except Exception as e:
                    print(f"{method_name}: Failed - {e}")
    
    def test_rsa_key_generation(self):
        """Test RSA key generation and properties."""
        p, q, e = 3, 5, 7
        n = p * q
        phi = (p - 1) * (q - 1)
        d = self.attack.modular_inverse(e, phi)
        
        print(f"RSA Key Generation:")
        print(f"p = {p}")
        print(f"q = {q}")
        print(f"n = p * q = {n}")
        print(f"phi = (p-1) * (q-1) = {phi}")
        print(f"e = {e}")
        print(f"d = {d}")
        
        # Verify properties
        self.assertEqual(n, p * q)
        self.assertEqual(phi, (p - 1) * (q - 1))
        self.assertEqual((e * d) % phi, 1)
        
        # Test encryption/decryption
        message = 5
        encrypted = pow(message, e, n)
        decrypted = pow(encrypted, d, n)
        
        self.assertEqual(decrypted, message)
    
    def test_pkcs1_padding_edge_cases(self):
        """Test PKCS#1 v1.5 padding with edge cases."""
        test_cases = [
            b"",           # Empty string
            b"a",          # Single character
            b"ab",         # Two characters
            b"abc",        # Three characters
            b"Hello",      # Short string
            b"A" * 10,     # Longer string
        ]
        
        for data in test_cases:
            try:
                padded_data = self.simulator.add_pkcs1_padding(data)
                removed_data = self.simulator.remove_pkcs1_padding(padded_data)
                self.assertEqual(removed_data, data)
            except ValueError as e:
                print(f"Padding failed for {data}: {e}")
    
    def test_large_small_numbers(self):
        """Test with larger 'small' numbers."""
        # Test with 32-bit numbers (still small for modern standards)
        p, q = 65521, 65537  # Two large primes
        e = 65537
        
        simulator = RSASimulator(p, q, e)
        
        plaintext = "This is a test message for larger small numbers."
        
        # Encrypt
        ciphertext = simulator.encrypt(plaintext)
        
        # Decrypt
        decrypted = simulator.decrypt(ciphertext)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_attack_with_different_exponents(self):
        """Test attack with different public exponents."""
        exponents = [3, 5, 7, 17, 65537]
        
        for e in exponents:
            simulator = RSASimulator(3, 5, e)
            plaintext = f"Test message with exponent {e}"
            
            # Encrypt
            ciphertext = simulator.encrypt(plaintext)
            
            # Perform attack
            with patch('builtins.print') as mock_print:
                recovered_plaintext = self.attack.perform_small_key_attack(
                    ciphertext, simulator.n, e
                )
            
            self.assertEqual(recovered_plaintext, plaintext)
    
    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Test with invalid modulus
        with self.assertRaises(ValueError):
            self.attack.factorize(1)
        
        # Test with prime number
        with self.assertRaises(ValueError):
            self.attack.factorize(17)
        
        # Test with invalid padding
        with self.assertRaises(ValueError):
            self.attack.remove_pkcs1_padding(b"invalid")
        
        # Test with invalid modular inverse
        with self.assertRaises(ValueError):
            self.attack.modular_inverse(2, 4)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
