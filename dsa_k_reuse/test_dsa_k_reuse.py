#!/usr/bin/env python3
"""
Test cases for DSA k-Reuse Attack

This module contains test cases to validate the DSA k-reuse attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import base64
import json
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes
from dsa_k_reuse_attack import DSAKReuseAttack, DSASimulator


class TestDSAKReuseAttack(unittest.TestCase):
    """Test cases for DSAKReuseAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = DSAKReuseAttack()
        self.challenge_email = "user@example.com"
    
    @patch('dsa_k_reuse_attack.requests.get')
    def test_get_public_key(self, mock_get):
        """Test getting public key from server."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "P": 31268084165942947135796502069919816727208016806045493372632797892380919611987093284195915092592077802153306895563614968192315801843075556180554303488255204981134987702833238564893904838788367973505552199973350221907429293459545253254555578122597127640244107042686147401380311498768029769014448671747659339426340043775634884507714081793158133495281811873417066394512846423883658377252643029597073061769424860341483611149280788816490621303819838791746764911858635843344849999215164642482379084407617551516111517527742743952951714303232907530207592240488493121634985527072855574610201451962952144745939176377773626647809,
            "Q": 65912913038584402033818304986704188702622061055450140068365582229606683391593,
            "G": 30045722200170015496665983411251456840450134551383433885392755805264509404980958755758094110819282336749516756278601763841307543396773684763712854525625774274791781616064876821881320771462077354317463952287443416684650843119602760974959989342080581266791651785019114280760818696225428783895545308877102731600230126345781761769266363990797883047018209191875165697667881207854921629774821659759774174046969524493791821904398247540920101862303731744029253943217908664613167421131915410019126846886824800407446027570705537708452026685039466398503051302599136047622628378963050548778238740878372708733519087319390184679386,
            "Y": 14465438857568916492659984604590590726816065555515979528079983898754304460212162903424055395813750140230719353512398829490433674570909821489111082972226845827632688326715261827012196277410840241961948629201005315216170183526083387225931008557580507184584528938082047432531417196619985185750914942744913133369326163116675962411086354840682033279297883759064350484526430888294484927315056695217364996919767346538002200260257391529572612572731897866046551899259031086619308640900816768225880933280510242461800915673432447703863685061245710553251929301884063159867998852127837859977247261454234637131101570801451030769941
        }
        mock_get.return_value = mock_response
        
        public_key = self.attack.get_public_key(self.challenge_email)
        
        self.assertIn('P', public_key)
        self.assertIn('Q', public_key)
        self.assertIn('G', public_key)
        self.assertIn('Y', public_key)
        mock_get.assert_called_once()
    
    @patch('dsa_k_reuse_attack.requests.post')
    def test_sign_message(self, mock_post):
        """Test signing message."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "r": 26423141027041248727688338046163353743028074041350839573464468990462843161502,
            "s": 48525605644189209712634666387744409529815804584162398750704477839295023042009
        }
        mock_post.return_value = mock_response
        
        message = base64.b64encode(b"test_message").decode('utf-8')
        signature = self.attack.sign_message(self.challenge_email, message)
        
        self.assertIn('r', signature)
        self.assertIn('s', signature)
        mock_post.assert_called_once()
    
    @patch('dsa_k_reuse_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        private_key = 123456789
        result = self.attack.submit_answer(self.challenge_email, private_key)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_sha256_hash(self):
        """Test SHA-256 hash calculation."""
        test_cases = [
            (b"hello", "2cf24dba4f21ba0b4e3c2b70c9303ba7164eef2b5ef4dce8f2e5cdb9c666b489"),
            (b"world", "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"),
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"test", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        ]
        
        for data, expected_hex in test_cases:
            result = self.attack.sha256_hash(data)
            expected_int = int(expected_hex, 16)
            self.assertEqual(result, expected_int)
    
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
    
    def test_find_k_reuse(self):
        """Test finding k reuse in signatures."""
        signatures = [
            {"r": 1, "s": 100},
            {"r": 2, "s": 200},
            {"r": 1, "s": 300},  # Same r as first signature
            {"r": 3, "s": 400},
            {"r": 2, "s": 500},  # Same r as second signature
        ]
        
        reuse_indices = self.attack.find_k_reuse(signatures)
        
        # Should find indices 0, 2 (r=1) and 1, 4 (r=2)
        expected_indices = [0, 1, 2, 4]
        self.assertEqual(sorted(reuse_indices), expected_indices)
    
    def test_find_k_reuse_no_reuse(self):
        """Test finding k reuse when no reuse exists."""
        signatures = [
            {"r": 1, "s": 100},
            {"r": 2, "s": 200},
            {"r": 3, "s": 300},
        ]
        
        reuse_indices = self.attack.find_k_reuse(signatures)
        
        self.assertEqual(len(reuse_indices), 0)
    
    def test_recover_k(self):
        """Test k recovery from two messages."""
        # Test with known values
        message1 = b"message1"
        message2 = b"message2"
        s1 = 100
        s2 = 200
        q = 23
        
        # Calculate expected k
        h1 = self.attack.sha256_hash(message1)
        h2 = self.attack.sha256_hash(message2)
        
        # k = (h1 - h2) * (s1 - s2)^(-1) mod q
        numerator = (h1 - h2) % q
        denominator = (s1 - s2) % q
        denominator_inv = self.attack.modular_inverse(denominator, q)
        expected_k = (numerator * denominator_inv) % q
        
        # Test recovery
        recovered_k = self.attack.recover_k(message1, message2, s1, s2, q)
        
        self.assertEqual(recovered_k, expected_k)
    
    def test_recover_private_key(self):
        """Test private key recovery."""
        # Test with known values
        message = b"test_message"
        r = 5
        s = 100
        k = 7
        q = 23
        
        # Calculate expected private key
        h = self.attack.sha256_hash(message)
        
        # x = (s * k - h) * r^(-1) mod q
        numerator = (s * k - h) % q
        r_inv = self.attack.modular_inverse(r, q)
        expected_x = (numerator * r_inv) % q
        
        # Test recovery
        recovered_x = self.attack.recover_private_key(message, r, s, k, q)
        
        self.assertEqual(recovered_x, expected_x)
    
    @patch('dsa_k_reuse_attack.DSAKReuseAttack.get_public_key')
    @patch('dsa_k_reuse_attack.DSAKReuseAttack.sign_message')
    @patch('dsa_k_reuse_attack.DSAKReuseAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_sign, mock_get):
        """Test successful attack execution."""
        # Mock public key
        mock_get.return_value = {
            "P": 23, "Q": 11, "G": 5, "Y": 3
        }
        
        # Mock signatures with k reuse
        mock_sign.side_effect = [
            {"r": 5, "s": 100},
            {"r": 6, "s": 200},
            {"r": 5, "s": 300},  # Same r as first signature
        ]
        
        mock_submit.return_value = "¡Ganaste!"
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get.assert_called_once()
        self.assertEqual(mock_sign.call_count, 3)
        mock_submit.assert_called_once()
    
    @patch('dsa_k_reuse_attack.DSAKReuseAttack.get_public_key')
    def test_execute_attack_error(self, mock_get):
        """Test attack execution when getting public key fails."""
        mock_get.side_effect = Exception("Network error")
        
        with patch('builtins.print') as mock_print:
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Network error", result)


class TestDSASimulator(unittest.TestCase):
    """Test cases for DSASimulator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Use small parameters for testing
        self.p = 23
        self.q = 11
        self.g = 5
        self.x = 7
        self.simulator = DSASimulator(self.p, self.q, self.g, self.x)
    
    def test_sign(self):
        """Test DSA signing."""
        message = b"test_message"
        k = 3
        
        r, s = self.simulator.sign(message, k)
        
        # Verify r calculation
        expected_r = pow(self.g, k, self.p) % self.q
        self.assertEqual(r, expected_r)
        
        # Verify s calculation
        h = bytes_to_long(hashlib.sha256(message).digest())
        k_inv = self.simulator.modular_inverse(k, self.q)
        expected_s = (k_inv * (h + self.x * r)) % self.q
        self.assertEqual(s, expected_s)
    
    def test_sign_different_messages(self):
        """Test signing different messages."""
        messages = [b"message1", b"message2", b"message3"]
        k = 5
        
        signatures = []
        for message in messages:
            r, s = self.simulator.sign(message, k)
            signatures.append((r, s))
        
        # All signatures should have the same r (same k)
        r_values = [sig[0] for sig in signatures]
        self.assertEqual(len(set(r_values)), 1)
        
        # But different s values (different messages)
        s_values = [sig[1] for sig in signatures]
        self.assertEqual(len(set(s_values)), len(messages))
    
    def test_sign_different_k(self):
        """Test signing with different k values."""
        message = b"test_message"
        k_values = [3, 5, 7]
        
        signatures = []
        for k in k_values:
            r, s = self.simulator.sign(message, k)
            signatures.append((r, s))
        
        # All signatures should have different r values (different k)
        r_values = [sig[0] for sig in signatures]
        self.assertEqual(len(set(r_values)), len(k_values))
        
        # All signatures should have different s values
        s_values = [sig[1] for sig in signatures]
        self.assertEqual(len(set(s_values)), len(k_values))


class TestDSAKReuseIntegration(unittest.TestCase):
    """Integration tests for DSA k-reuse attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = DSAKReuseAttack()
        self.simulator = DSASimulator(23, 11, 5, 7)
    
    def test_complete_k_reuse_attack_simulation(self):
        """Test complete k-reuse attack simulation."""
        # Create test scenario with k reuse
        message1 = b"message1"
        message2 = b"message2"
        k = 5  # Same k for both messages
        
        # Sign both messages with same k
        r1, s1 = self.simulator.sign(message1, k)
        r2, s2 = self.simulator.sign(message2, k)
        
        print(f"Message 1: {message1}")
        print(f"Message 2: {message2}")
        print(f"Signature 1: r={r1}, s={s1}")
        print(f"Signature 2: r={r2}, s={s2}")
        
        # Verify r values are the same (k reuse)
        self.assertEqual(r1, r2)
        
        # Recover k
        recovered_k = self.attack.recover_k(message1, message2, s1, s2, self.simulator.q)
        print(f"Recovered k: {recovered_k}")
        
        # Should match original k
        self.assertEqual(recovered_k, k)
        
        # Recover private key
        recovered_x = self.attack.recover_private_key(message1, r1, s1, recovered_k, self.simulator.q)
        print(f"Recovered private key: {recovered_x}")
        
        # Should match original private key
        self.assertEqual(recovered_x, self.simulator.x)
    
    def test_k_reuse_attack_with_multiple_signatures(self):
        """Test k-reuse attack with multiple signatures."""
        # Create multiple messages
        messages = [f"message_{i}".encode('utf-8') for i in range(5)]
        
        # Sign some messages with same k
        k1 = 3
        k2 = 7
        
        signatures = []
        for i, message in enumerate(messages):
            if i < 3:
                k = k1  # First 3 messages use same k
            else:
                k = k2  # Last 2 messages use different k
            
            r, s = self.simulator.sign(message, k)
            signatures.append({"r": r, "s": s})
        
        # Find k reuse
        reuse_indices = self.attack.find_k_reuse(signatures)
        
        # Should find indices 0, 1, 2 (same k)
        expected_indices = [0, 1, 2]
        self.assertEqual(sorted(reuse_indices), expected_indices)
        
        # Test k recovery using first two signatures
        msg1 = messages[0]
        msg2 = messages[1]
        s1 = signatures[0]['s']
        s2 = signatures[1]['s']
        
        recovered_k = self.attack.recover_k(msg1, msg2, s1, s2, self.simulator.q)
        self.assertEqual(recovered_k, k1)
        
        # Test private key recovery
        recovered_x = self.attack.recover_private_key(msg1, signatures[0]['r'], s1, recovered_k, self.simulator.q)
        self.assertEqual(recovered_x, self.simulator.x)
    
    def test_dsa_signature_verification(self):
        """Test DSA signature verification."""
        message = b"test_message"
        k = 5
        
        # Sign message
        r, s = self.simulator.sign(message, k)
        
        # Verify signature manually
        # r = (g^k mod p) mod q
        expected_r = pow(self.simulator.g, k, self.simulator.p) % self.simulator.q
        self.assertEqual(r, expected_r)
        
        # s = k^(-1) * (h + x*r) mod q
        h = bytes_to_long(hashlib.sha256(message).digest())
        k_inv = self.simulator.modular_inverse(k, self.simulator.q)
        expected_s = (k_inv * (h + self.simulator.x * r)) % self.simulator.q
        self.assertEqual(s, expected_s)
    
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
    
    def test_sha256_hash_properties(self):
        """Test properties of SHA-256 hash."""
        test_cases = [
            b"hello",
            b"world",
            b"test",
            b"",
            b"a" * 1000,
        ]
        
        for data in test_cases:
            hash_int = self.attack.sha256_hash(data)
            
            # Should be a positive integer
            self.assertGreater(hash_int, 0)
            
            # Should be deterministic
            hash_int2 = self.attack.sha256_hash(data)
            self.assertEqual(hash_int, hash_int2)
            
            # Different data should produce different hashes
            if data != b"hello":
                hello_hash = self.attack.sha256_hash(b"hello")
                self.assertNotEqual(hash_int, hello_hash)
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with very small values
        message = b"a"
        k = 1
        q = 3
        
        r, s = self.simulator.sign(message, k)
        
        # Should still produce valid signature
        self.assertGreaterEqual(r, 0)
        self.assertLess(r, q)
        self.assertGreaterEqual(s, 0)
        self.assertLess(s, q)
        
        # Test k recovery with small values
        message2 = b"b"
        r2, s2 = self.simulator.sign(message2, k)
        
        recovered_k = self.attack.recover_k(message, message2, s, s2, q)
        self.assertEqual(recovered_k, k)
    
    def test_large_values(self):
        """Test with larger values."""
        # Test with larger message
        message = b"This is a much longer message that should still work with the k-reuse attack."
        k = 13
        
        r, s = self.simulator.sign(message, k)
        
        # Should produce valid signature
        self.assertGreaterEqual(r, 0)
        self.assertLess(r, self.simulator.q)
        self.assertGreaterEqual(s, 0)
        self.assertLess(s, self.simulator.q)
        
        # Test k recovery
        message2 = b"Another long message for testing purposes."
        r2, s2 = self.simulator.sign(message2, k)
        
        recovered_k = self.attack.recover_k(message, message2, s, s2, self.simulator.q)
        self.assertEqual(recovered_k, k)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
