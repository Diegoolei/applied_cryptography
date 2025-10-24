#!/usr/bin/env python3
"""
Test cases for RSA Broadcast Attack

This module contains test cases to validate the RSA broadcast attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes
from rsa_broadcast_attack import RSABroadcastAttack, RSASimulator


class TestRSABroadcastAttack(unittest.TestCase):
    """Test cases for RSABroadcastAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = RSABroadcastAttack()
        self.challenge_email = "user@example.com"
    
    @patch('rsa_broadcast_attack.requests.get')
    def test_get_challenge_data(self, mock_get):
        """Test getting challenge data from server."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ciphertext": "fA1dwPZ+94Lj/S65idejlvOB2fb5Sw6k8fRevwCQWPXfeVhK4laDrfCqtO3ur6j9kUC9MxK/+bcW0KE5+ekLcRGoUBgkqodbIc19SP+moCd7cKy6VI2NXKegk+DtB5Ficx9E7cMxkHGbBY+s6K4VpdFISdZ12Q+vo2m/6hUuATU=",
            "publicKey": {
                "n": 147047715672033722527605907723369277416162216385083563865034832107366464490579979621410366177514492842244138250940295321770532546136830989548043697399223326555962322487773490729435735989687351869208367155496860176081715514389603624293096943370178121696261127390891963060276874965266061247044585088695288965247,
                "e": 3
            }
        }
        mock_get.return_value = mock_response
        
        data = self.attack.get_challenge_data(self.challenge_email)
        
        self.assertIn('ciphertext', data)
        self.assertIn('publicKey', data)
        self.assertEqual(data['publicKey']['e'], 3)
        mock_get.assert_called_once()
    
    @patch('rsa_broadcast_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        plaintext = "Professional wrestling: ballet for the common man."
        result = self.attack.submit_answer(self.challenge_email, plaintext)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_parse_challenge_data(self):
        """Test parsing challenge data."""
        data = {
            "ciphertext": "fA1dwPZ+94Lj/S65idejlvOB2fb5Sw6k8fRevwCQWPXfeVhK4laDrfCqtO3ur6j9kUC9MxK/+bcW0KE5+ekLcRGoUBgkqodbIc19SP+moCd7cKy6VI2NXKegk+DtB5Ficx9E7cMxkHGbBY+s6K4VpdFISdZ12Q+vo2m/6hUuATU=",
            "publicKey": {
                "n": 147047715672033722527605907723369277416162216385083563865034832107366464490579979621410366177514492842244138250940295321770532546136830989548043697399223326555962322487773490729435735989687351869208367155496860176081715514389603624293096943370178121696261127390891963060276874965266061247044585088695288965247,
                "e": 3
            }
        }
        
        ciphertext_bytes, n, e = self.attack.parse_challenge_data(data)
        
        self.assertIsInstance(ciphertext_bytes, bytes)
        self.assertEqual(e, 3)
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)
    
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
        # Test case where no inverse exists
        with self.assertRaises(ValueError):
            self.attack.modular_inverse(2, 4)  # gcd(2, 4) = 2 ≠ 1
        
        with self.assertRaises(ValueError):
            self.attack.modular_inverse(6, 9)  # gcd(6, 9) = 3 ≠ 1
    
    def test_chinese_remainder_theorem(self):
        """Test Chinese Remainder Theorem implementation."""
        # Test case: x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)
        # Solution: x = 23
        remainders = [2, 3, 2]
        moduli = [3, 5, 7]
        
        result = self.attack.chinese_remainder_theorem(remainders, moduli)
        
        # Verify the result
        self.assertEqual(result % 3, 2)
        self.assertEqual(result % 5, 3)
        self.assertEqual(result % 7, 2)
        self.assertEqual(result, 23)
    
    def test_chinese_remainder_theorem_large(self):
        """Test Chinese Remainder Theorem with larger numbers."""
        # Test case with larger moduli
        remainders = [5, 7, 11]
        moduli = [13, 17, 19]
        
        result = self.attack.chinese_remainder_theorem(remainders, moduli)
        
        # Verify the result
        self.assertEqual(result % 13, 5)
        self.assertEqual(result % 17, 7)
        self.assertEqual(result % 19, 11)
    
    def test_chinese_remainder_theorem_mismatched_lengths(self):
        """Test Chinese Remainder Theorem with mismatched lengths."""
        remainders = [1, 2]
        moduli = [3, 5, 7]
        
        with self.assertRaises(ValueError):
            self.attack.chinese_remainder_theorem(remainders, moduli)
    
    def test_cube_root(self):
        """Test cube root calculation."""
        test_cases = [
            (0, 0),
            (1, 1),
            (8, 2),
            (27, 3),
            (64, 4),
            (125, 5),
            (1000, 10),
            (8000, 20),
        ]
        
        for n, expected in test_cases:
            result = self.attack.cube_root(n)
            self.assertEqual(result, expected)
    
    def test_cube_root_large(self):
        """Test cube root calculation with larger numbers."""
        # Test with a large perfect cube
        large_cube = 123456789 ** 3
        result = self.attack.cube_root(large_cube)
        self.assertEqual(result, 123456789)
    
    def test_cube_root_non_perfect_cube(self):
        """Test cube root calculation with non-perfect cubes."""
        # Test with numbers that are not perfect cubes
        test_cases = [9, 10, 26, 28, 65, 124]
        
        for n in test_cases:
            result = self.attack.cube_root(n)
            # The result should be close to the actual cube root
            actual_cube_root = n ** (1/3)
            self.assertLessEqual(abs(result - actual_cube_root), 1)
    
    def test_perform_broadcast_attack(self):
        """Test performing broadcast attack."""
        # Create test data
        plaintext = "Test message"
        plaintext_bytes = plaintext.encode('utf-8')
        m = bytes_to_long(plaintext_bytes)
        
        # Create test moduli (small for testing)
        moduli = [17, 19, 23]  # Small primes for testing
        
        # Create ciphertexts
        ciphertexts = []
        for n in moduli:
            c = pow(m, 3, n)
            ciphertext_bytes = long_to_bytes(c)
            ciphertexts.append(ciphertext_bytes)
        
        # Perform attack
        result = self.attack.perform_broadcast_attack(ciphertexts, moduli)
        
        self.assertEqual(result, plaintext)
    
    def test_perform_broadcast_attack_insufficient_ciphertexts(self):
        """Test broadcast attack with insufficient ciphertexts."""
        ciphertexts = [b"ciphertext1", b"ciphertext2"]
        moduli = [17, 19]
        
        with self.assertRaises(ValueError):
            self.attack.perform_broadcast_attack(ciphertexts, moduli)
    
    def test_perform_broadcast_attack_mismatched_lengths(self):
        """Test broadcast attack with mismatched lengths."""
        ciphertexts = [b"ciphertext1", b"ciphertext2", b"ciphertext3"]
        moduli = [17, 19]
        
        with self.assertRaises(ValueError):
            self.attack.perform_broadcast_attack(ciphertexts, moduli)
    
    @patch('rsa_broadcast_attack.RSABroadcastAttack.get_challenge_data')
    @patch('rsa_broadcast_attack.RSABroadcastAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get):
        """Test successful attack execution."""
        # Mock challenge data
        mock_data = {
            "ciphertext": "fA1dwPZ+94Lj/S65idejlvOB2fb5Sw6k8fRevwCQWPXfeVhK4laDrfCqtO3ur6j9kUC9MxK/+bcW0KE5+ekLcRGoUBgkqodbIc19SP+moCd7cKy6VI2NXKegk+DtB5Ficx9E7cMxkHGbBY+s6K4VpdFISdZ12Q+vo2m/6hUuATU=",
            "publicKey": {
                "n": 147047715672033722527605907723369277416162216385083563865034832107366464490579979621410366177514492842244138250940295321770532546136830989548043697399223326555962322487773490729435735989687351869208367155496860176081715514389603624293096943370178121696261127390891963060276874965266061247044585088695288965247,
                "e": 3
            }
        }
        mock_get.return_value = mock_data
        mock_submit.return_value = "¡Ganaste!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email, 3)
        
        self.assertEqual(result, "¡Ganaste!")
        self.assertEqual(mock_get.call_count, 3)
        mock_submit.assert_called_once()
    
    @patch('rsa_broadcast_attack.RSABroadcastAttack.get_challenge_data')
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
        self.simulator = RSASimulator()
    
    def test_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        plaintext = "Hello, World!"
        n = 17 * 19  # Small composite for testing
        e = 3
        d = 7  # Private exponent (calculated for this example)
        
        # Encrypt
        ciphertext = self.simulator.encrypt(plaintext, n, e)
        
        # Decrypt
        decrypted = self.simulator.decrypt(ciphertext, n, d)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_encrypt_different_messages(self):
        """Test encryption with different messages."""
        messages = [
            "Short",
            "This is a longer message",
            "Special characters: !@#$%^&*()",
            "Unicode: ñáéíóú",
        ]
        
        n = 17 * 19
        e = 3
        
        for message in messages:
            ciphertext = self.simulator.encrypt(message, n, e)
            
            # Ciphertext should be different for different messages
            self.assertIsInstance(ciphertext, bytes)
            self.assertGreater(len(ciphertext), 0)
    
    def test_encrypt_deterministic(self):
        """Test that encryption is deterministic."""
        plaintext = "Deterministic test"
        n = 17 * 19
        e = 3
        
        # Encrypt same message multiple times
        ciphertext1 = self.simulator.encrypt(plaintext, n, e)
        ciphertext2 = self.simulator.encrypt(plaintext, n, e)
        
        # Should be identical (textbook RSA)
        self.assertEqual(ciphertext1, ciphertext2)


class TestRSABroadcastIntegration(unittest.TestCase):
    """Integration tests for RSA broadcast attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = RSABroadcastAttack()
        self.simulator = RSASimulator()
    
    def test_broadcast_attack_simulation(self):
        """Test complete broadcast attack simulation."""
        # Create test plaintext
        plaintext = "Professional wrestling: ballet for the common man."
        plaintext_bytes = plaintext.encode('utf-8')
        m = bytes_to_long(plaintext_bytes)
        
        print(f"Original plaintext: {plaintext}")
        print(f"Plaintext as integer: {m}")
        
        # Create test moduli (small for testing)
        moduli = [17, 19, 23]
        
        # Create ciphertexts
        ciphertexts = []
        for i, n in enumerate(moduli):
            c = pow(m, 3, n)
            ciphertext_bytes = long_to_bytes(c)
            ciphertexts.append(ciphertext_bytes)
            
            print(f"Ciphertext {i+1}: {c} (mod {n})")
            print(f"Ciphertext {i+1} bytes: {len(ciphertext_bytes)} bytes")
        
        # Perform broadcast attack
        recovered_plaintext = self.attack.perform_broadcast_attack(ciphertexts, moduli)
        
        print(f"Recovered plaintext: {recovered_plaintext}")
        
        # Should match original
        self.assertEqual(recovered_plaintext, plaintext)
    
    def test_chinese_remainder_theorem_properties(self):
        """Test properties of Chinese Remainder Theorem."""
        # Test with pairwise coprime moduli
        moduli = [3, 5, 7, 11, 13]
        remainders = [1, 2, 3, 4, 5]
        
        result = self.attack.chinese_remainder_theorem(remainders, moduli)
        
        # Verify all congruences
        for i, (r, m) in enumerate(zip(remainders, moduli)):
            self.assertEqual(result % m, r, f"Failed for congruence {i+1}")
        
        # Test uniqueness (result should be unique mod product of moduli)
        product = 1
        for m in moduli:
            product *= m
        
        # Any other solution should differ by a multiple of the product
        other_solution = result + product
        for i, (r, m) in enumerate(zip(remainders, moduli)):
            self.assertEqual(other_solution % m, r, f"Failed for congruence {i+1} with other solution")
    
    def test_cube_root_accuracy(self):
        """Test accuracy of cube root calculation."""
        test_cases = [
            (0, 0),
            (1, 1),
            (8, 2),
            (27, 3),
            (64, 4),
            (125, 5),
            (1000, 10),
            (8000, 20),
            (27000, 30),
            (64000, 40),
        ]
        
        for n, expected in test_cases:
            result = self.attack.cube_root(n)
            self.assertEqual(result, expected, f"Failed for n={n}")
            
            # Verify it's actually a cube root
            cube = result ** 3
            self.assertLessEqual(cube, n)
            self.assertLess(n, (result + 1) ** 3)
    
    def test_modular_inverse_properties(self):
        """Test properties of modular inverse."""
        test_cases = [
            (3, 7),
            (5, 11),
            (7, 13),
            (11, 17),
            (13, 19),
        ]
        
        for a, m in test_cases:
            inv = self.attack.modular_inverse(a, m)
            
            # Verify it's actually the inverse
            self.assertEqual((a * inv) % m, 1)
            
            # Verify it's in the correct range
            self.assertGreaterEqual(inv, 0)
            self.assertLess(inv, m)
    
    def test_rsa_broadcast_attack_edge_cases(self):
        """Test edge cases for RSA broadcast attack."""
        # Test with very small moduli
        plaintext = "Test"
        moduli = [3, 5, 7]
        
        plaintext_bytes = plaintext.encode('utf-8')
        m = bytes_to_long(plaintext_bytes)
        
        ciphertexts = []
        for n in moduli:
            c = pow(m, 3, n)
            ciphertext_bytes = long_to_bytes(c)
            ciphertexts.append(ciphertext_bytes)
        
        result = self.attack.perform_broadcast_attack(ciphertexts, moduli)
        self.assertEqual(result, plaintext)
    
    def test_rsa_broadcast_attack_large_message(self):
        """Test broadcast attack with larger message."""
        # Test with a longer message
        plaintext = "This is a much longer message that should still work with the broadcast attack."
        moduli = [17, 19, 23]
        
        plaintext_bytes = plaintext.encode('utf-8')
        m = bytes_to_long(plaintext_bytes)
        
        ciphertexts = []
        for n in moduli:
            c = pow(m, 3, n)
            ciphertext_bytes = long_to_bytes(c)
            ciphertexts.append(ciphertext_bytes)
        
        result = self.attack.perform_broadcast_attack(ciphertexts, moduli)
        self.assertEqual(result, plaintext)
    
    def test_rsa_broadcast_attack_special_characters(self):
        """Test broadcast attack with special characters."""
        # Test with special characters
        plaintext = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        moduli = [17, 19, 23]
        
        plaintext_bytes = plaintext.encode('utf-8')
        m = bytes_to_long(plaintext_bytes)
        
        ciphertexts = []
        for n in moduli:
            c = pow(m, 3, n)
            ciphertext_bytes = long_to_bytes(c)
            ciphertexts.append(ciphertext_bytes)
        
        result = self.attack.perform_broadcast_attack(ciphertexts, moduli)
        self.assertEqual(result, plaintext)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
