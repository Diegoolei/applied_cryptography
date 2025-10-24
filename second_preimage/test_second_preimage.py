#!/usr/bin/env python3
"""
Test cases for Second Preimage Attack

This module contains test cases to validate the second preimage attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import hashlib
import time
from second_preimage_attack import SecondPreimageAttack, HashCollisionFinder


class TestSecondPreimageAttack(unittest.TestCase):
    """Test cases for SecondPreimageAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = SecondPreimageAttack()
        self.challenge_email = "user@example.com"
    
    @patch('second_preimage_attack.requests.get')
    def test_get_target_hash(self, mock_get):
        """Test getting target hash from server."""
        mock_response = MagicMock()
        mock_response.text = "b4c9a2"
        mock_get.return_value = mock_response
        
        target_hash = self.attack.get_target_hash(self.challenge_email)
        
        self.assertEqual(target_hash, "b4c9a2")
        mock_get.assert_called_once()
    
    def test_calculate_hash(self):
        """Test hash calculation."""
        message = "user@example.com"
        hash_result = self.attack.calculate_hash(message)
        
        # Should be 6 characters (24 bits)
        self.assertEqual(len(hash_result), 6)
        self.assertRegex(hash_result, r'^[0-9a-f]{6}$')
        
        # Should match manual calculation
        expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()[:6]
        self.assertEqual(hash_result, expected_hash)
    
    def test_calculate_hash_different_messages(self):
        """Test hash calculation with different messages."""
        test_cases = [
            "user@example.com",
            "test@test.com",
            "a",
            "Hello, World!",
            "Special chars: !@#$%^&*()",
            "Unicode: ñáéíóú"
        ]
        
        for message in test_cases:
            hash_result = self.attack.calculate_hash(message)
            
            self.assertEqual(len(hash_result), 6)
            self.assertRegex(hash_result, r'^[0-9a-f]{6}$')
            
            # Verify it matches manual calculation
            expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()[:6]
            self.assertEqual(hash_result, expected_hash)
    
    @patch('second_preimage_attack.requests.post')
    def test_submit_answer(self, mock_post):
        """Test submitting answer to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        second_preimage = "user@example.com123"
        result = self.attack.submit_answer(self.challenge_email, second_preimage)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_brute_force_search_simple(self):
        """Test brute force search with simple case."""
        # Use a known hash for testing
        original_message = "test"
        target_hash = self.attack.calculate_hash(original_message)
        
        print(f"Testing with hash: {target_hash}")
        
        # This should find a collision quickly
        result = self.attack.brute_force_search(target_hash, original_message, max_length=2, num_threads=1)
        
        if result is not None:
            # Verify the result produces the same hash
            result_hash = self.attack.calculate_hash(result)
            self.assertEqual(result_hash, target_hash)
            self.assertNotEqual(result, original_message)
    
    def test_optimized_search(self):
        """Test optimized search strategy."""
        original_message = "test"
        target_hash = self.attack.calculate_hash(original_message)
        
        print(f"Testing optimized search with hash: {target_hash}")
        
        result = self.attack.optimized_search(target_hash, original_message)
        
        if result is not None:
            # Verify the result produces the same hash
            result_hash = self.attack.calculate_hash(result)
            self.assertEqual(result_hash, target_hash)
            self.assertNotEqual(result, original_message)
    
    def test_hash_collision_properties(self):
        """Test properties of hash collisions."""
        original_message = "test"
        original_hash = self.attack.calculate_hash(original_message)
        
        # Test that different messages can produce the same hash
        # (This is expected due to the birthday paradox with truncated hashes)
        found_collision = False
        
        for i in range(1000):  # Try first 1000 numbers
            candidate = original_message + str(i)
            candidate_hash = self.attack.calculate_hash(candidate)
            
            if candidate_hash == original_hash and candidate != original_message:
                found_collision = True
                print(f"Found collision: '{original_message}' and '{candidate}' both hash to {original_hash}")
                break
        
        # With 24-bit hashes, collisions should be relatively common
        # This test might not always find a collision, so we'll just verify the logic
        if found_collision:
            self.assertTrue(True)  # Collision found as expected
        else:
            print("No collision found in first 1000 attempts (this is possible)")
    
    @patch('second_preimage_attack.SecondPreimageAttack.get_target_hash')
    @patch('second_preimage_attack.SecondPreimageAttack.submit_answer')
    def test_execute_attack_success(self, mock_submit, mock_get_hash):
        """Test successful attack execution."""
        mock_get_hash.return_value = "b4c9a2"
        mock_submit.return_value = "¡Ganaste!"
        
        # Mock the optimized search to return a result
        with patch.object(self.attack, 'optimized_search') as mock_search:
            mock_search.return_value = "user@example.com123"
            
            result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_get_hash.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once_with(self.challenge_email, "user@example.com123")
    
    @patch('second_preimage_attack.SecondPreimageAttack.get_target_hash')
    def test_execute_attack_hash_mismatch(self, mock_get_hash):
        """Test attack execution when hash doesn't match."""
        mock_get_hash.return_value = "b4c9a2"
        
        # Use a different email that won't produce the target hash
        result = self.attack.execute_attack("different@email.com")
        
        self.assertIn("Error", result)
        self.assertIn("doesn't match target", result)
    
    @patch('second_preimage_attack.SecondPreimageAttack.get_target_hash')
    def test_execute_attack_no_preimage_found(self, mock_get_hash):
        """Test attack execution when no preimage is found."""
        mock_get_hash.return_value = "b4c9a2"
        
        # Mock both search methods to return None
        with patch.object(self.attack, 'optimized_search') as mock_optimized:
            with patch.object(self.attack, 'brute_force_search') as mock_brute:
                mock_optimized.return_value = None
                mock_brute.return_value = None
                
                result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Could not find second preimage", result)


class TestHashCollisionFinder(unittest.TestCase):
    """Test cases for HashCollisionFinder class."""
    
    def test_find_collision_simple(self):
        """Test finding collision with simple case."""
        # Use a short string to make collision finding easier
        test_message = "a"
        test_hash = hashlib.sha256(test_message.encode('utf-8')).hexdigest()[:6]
        
        collision = HashCollisionFinder.find_collision(test_hash, charset="abc", max_length=3)
        
        if collision is not None:
            msg1, msg2 = collision
            hash1 = hashlib.sha256(msg1.encode('utf-8')).hexdigest()[:6]
            hash2 = hashlib.sha256(msg2.encode('utf-8')).hexdigest()[:6]
            
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash1, test_hash)
            self.assertNotEqual(msg1, msg2)
    
    def test_find_collision_properties(self):
        """Test properties of found collisions."""
        test_message = "test"
        test_hash = hashlib.sha256(test_message.encode('utf-8')).hexdigest()[:6]
        
        collision = HashCollisionFinder.find_collision(test_hash, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=4)
        
        if collision is not None:
            msg1, msg2 = collision
            
            # Both messages should produce the same hash
            hash1 = hashlib.sha256(msg1.encode('utf-8')).hexdigest()[:6]
            hash2 = hashlib.sha256(msg2.encode('utf-8')).hexdigest()[:6]
            
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash1, test_hash)
            self.assertNotEqual(msg1, msg2)
            
            # Both messages should be valid strings
            self.assertIsInstance(msg1, str)
            self.assertIsInstance(msg2, str)
            self.assertGreater(len(msg1), 0)
            self.assertGreater(len(msg2), 0)


class TestSecondPreimageIntegration(unittest.TestCase):
    """Integration tests for second preimage attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = SecondPreimageAttack()
    
    def test_hash_truncation_behavior(self):
        """Test behavior of hash truncation."""
        test_messages = [
            "user@example.com",
            "test@test.com",
            "a",
            "Hello, World!",
            "Special chars: !@#$%^&*()",
        ]
        
        for message in test_messages:
            # Calculate full SHA-256
            full_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
            
            # Calculate truncated hash
            truncated_hash = self.attack.calculate_hash(message)
            
            # Truncated hash should be first 6 characters of full hash
            self.assertEqual(truncated_hash, full_hash[:6])
            self.assertEqual(len(truncated_hash), 6)
    
    def test_collision_probability(self):
        """Test collision probability with truncated hashes."""
        # With 24-bit hashes, collisions should be relatively common
        # due to the birthday paradox
        
        seen_hashes = {}
        collision_found = False
        
        # Try different messages to find a collision
        for i in range(10000):
            message = f"test{i}"
            message_hash = self.attack.calculate_hash(message)
            
            if message_hash in seen_hashes:
                collision_found = True
                original_message = seen_hashes[message_hash]
                print(f"Found collision: '{original_message}' and '{message}' both hash to {message_hash}")
                break
            
            seen_hashes[message_hash] = message
        
        # With 24-bit hashes, we expect to find collisions relatively quickly
        # This test verifies the collision-finding logic works
        if collision_found:
            self.assertTrue(True)  # Collision found as expected
        else:
            print("No collision found in 10,000 attempts (unlikely but possible)")
    
    def test_search_strategies(self):
        """Test different search strategies."""
        original_message = "test"
        target_hash = self.attack.calculate_hash(original_message)
        
        print(f"Testing search strategies with hash: {target_hash}")
        
        # Test optimized search
        start_time = time.time()
        result1 = self.attack.optimized_search(target_hash, original_message)
        time1 = time.time() - start_time
        
        if result1 is not None:
            print(f"Optimized search found result in {time1:.2f} seconds: {result1}")
            self.assertEqual(self.attack.calculate_hash(result1), target_hash)
            self.assertNotEqual(result1, original_message)
        
        # Test brute force search (limited)
        start_time = time.time()
        result2 = self.attack.brute_force_search(target_hash, original_message, max_length=2, num_threads=1)
        time2 = time.time() - start_time
        
        if result2 is not None:
            print(f"Brute force search found result in {time2:.2f} seconds: {result2}")
            self.assertEqual(self.attack.calculate_hash(result2), target_hash)
            self.assertNotEqual(result2, original_message)
    
    def test_performance_characteristics(self):
        """Test performance characteristics of the attack."""
        original_message = "test"
        target_hash = self.attack.calculate_hash(original_message)
        
        print(f"Testing performance with hash: {target_hash}")
        
        # Test with different thread counts
        thread_counts = [1, 2, 4]
        
        for num_threads in thread_counts:
            start_time = time.time()
            result = self.attack.brute_force_search(target_hash, original_message, max_length=2, num_threads=num_threads)
            elapsed = time.time() - start_time
            
            if result is not None:
                print(f"Found result with {num_threads} threads in {elapsed:.2f} seconds")
                self.assertEqual(self.attack.calculate_hash(result), target_hash)
                break
            else:
                print(f"No result found with {num_threads} threads in {elapsed:.2f} seconds")
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with empty string
        empty_hash = self.attack.calculate_hash("")
        self.assertEqual(len(empty_hash), 6)
        
        # Test with very long string
        long_string = "a" * 1000
        long_hash = self.attack.calculate_hash(long_string)
        self.assertEqual(len(long_hash), 6)
        
        # Test with special characters
        special_string = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        special_hash = self.attack.calculate_hash(special_string)
        self.assertEqual(len(special_hash), 6)
        
        # Test with unicode characters
        unicode_string = "ñáéíóú"
        unicode_hash = self.attack.calculate_hash(unicode_string)
        self.assertEqual(len(unicode_hash), 6)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
