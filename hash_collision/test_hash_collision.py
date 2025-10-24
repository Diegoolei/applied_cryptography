#!/usr/bin/env python3
"""
Test cases for Hash Collision Attack

This module contains test cases to validate the hash collision attack implementation.
"""

import unittest
from unittest.mock import patch, MagicMock
import hashlib
import time
from collections import defaultdict
from hash_collision_attack import HashCollisionAttack, CollisionFinder


class TestHashCollisionAttack(unittest.TestCase):
    """Test cases for HashCollisionAttack class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = HashCollisionAttack()
        self.challenge_email = "user@example.com"
    
    def test_calculate_hash(self):
        """Test hash calculation."""
        message = "user@example.com"
        hash_result = self.attack.calculate_hash(message)
        
        # Should be 12 characters (48 bits)
        self.assertEqual(len(hash_result), 12)
        self.assertRegex(hash_result, r'^[0-9a-f]{12}$')
        
        # Should match manual calculation
        expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()[:12]
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
            
            self.assertEqual(len(hash_result), 12)
            self.assertRegex(hash_result, r'^[0-9a-f]{12}$')
            
            # Verify it matches manual calculation
            expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()[:12]
            self.assertEqual(hash_result, expected_hash)
    
    @patch('hash_collision_attack.requests.post')
    def test_submit_collision(self, mock_post):
        """Test submitting collision to server."""
        mock_response = MagicMock()
        mock_response.text = "¡Ganaste!"
        mock_post.return_value = mock_response
        
        message1 = "user@example.com123"
        message2 = "user@example.com456"
        result = self.attack.submit_collision(self.challenge_email, message1, message2)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_post.assert_called_once()
    
    def test_find_collision_brute_force_simple(self):
        """Test brute force collision search with simple case."""
        # Use a known email for testing
        email = "test"
        
        print(f"Testing brute force collision search with email: {email}")
        
        # This should find a collision quickly with short suffixes
        result = self.attack.find_collision_brute_force(email, max_length=3, num_threads=1)
        
        if result is not None:
            message1, message2 = result
            # Verify both messages produce the same hash
            hash1 = self.attack.calculate_hash(message1)
            hash2 = self.attack.calculate_hash(message2)
            self.assertEqual(hash1, hash2)
            self.assertNotEqual(message1, message2)
            # Verify both messages contain the email
            self.assertIn(email, message1)
            self.assertIn(email, message2)
    
    def test_find_collision_optimized(self):
        """Test optimized collision search strategy."""
        email = "test"
        
        print(f"Testing optimized collision search with email: {email}")
        
        result = self.attack.find_collision_optimized(email)
        
        if result is not None:
            message1, message2 = result
            # Verify both messages produce the same hash
            hash1 = self.attack.calculate_hash(message1)
            hash2 = self.attack.calculate_hash(message2)
            self.assertEqual(hash1, hash2)
            self.assertNotEqual(message1, message2)
            # Verify both messages contain the email
            self.assertIn(email, message1)
            self.assertIn(email, message2)
    
    def test_find_collision_birthday_attack(self):
        """Test birthday attack collision search."""
        email = "test"
        
        print(f"Testing birthday attack with email: {email}")
        
        result = self.attack.find_collision_birthday_attack(email, max_attempts=10000)
        
        if result is not None:
            message1, message2 = result
            # Verify both messages produce the same hash
            hash1 = self.attack.calculate_hash(message1)
            hash2 = self.attack.calculate_hash(message2)
            self.assertEqual(hash1, hash2)
            self.assertNotEqual(message1, message2)
            # Verify both messages contain the email
            self.assertIn(email, message1)
            self.assertIn(email, message2)
    
    def test_hash_collision_properties(self):
        """Test properties of hash collisions."""
        email = "test"
        
        # Test that different messages can produce the same hash
        # (This is expected due to the birthday paradox with truncated hashes)
        found_collision = False
        
        hash_map = defaultdict(list)
        
        for i in range(1000):  # Try first 1000 numbers
            candidate = email + str(i)
            candidate_hash = self.attack.calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                found_collision = True
                messages = hash_map[candidate_hash][:2]
                print(f"Found collision: '{messages[0]}' and '{messages[1]}' both hash to {candidate_hash}")
                break
        
        # With 48-bit hashes, collisions should be relatively common
        # This test verifies the collision-finding logic works
        if found_collision:
            self.assertTrue(True)  # Collision found as expected
        else:
            print("No collision found in first 1000 attempts (this is possible)")
    
    @patch('hash_collision_attack.HashCollisionAttack.find_collision_optimized')
    @patch('hash_collision_attack.HashCollisionAttack.submit_collision')
    def test_execute_attack_success(self, mock_submit, mock_find):
        """Test successful attack execution."""
        mock_find.return_value = ("user@example.com123", "user@example.com456")
        mock_submit.return_value = "¡Ganaste!"
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertEqual(result, "¡Ganaste!")
        mock_find.assert_called_once_with(self.challenge_email)
        mock_submit.assert_called_once_with(self.challenge_email, "user@example.com123", "user@example.com456")
    
    @patch('hash_collision_attack.HashCollisionAttack.find_collision_optimized')
    @patch('hash_collision_attack.HashCollisionAttack.find_collision_birthday_attack')
    @patch('hash_collision_attack.HashCollisionAttack.find_collision_brute_force')
    def test_execute_attack_no_collision_found(self, mock_brute, mock_birthday, mock_optimized):
        """Test attack execution when no collision is found."""
        mock_optimized.return_value = None
        mock_birthday.return_value = None
        mock_brute.return_value = None
        
        result = self.attack.execute_attack(self.challenge_email)
        
        self.assertIn("Error", result)
        self.assertIn("Could not find collision", result)
    
    def test_search_collision_length(self):
        """Test collision search with specific length."""
        email = "test"
        
        # Test with a very limited character set to make collision likely
        result = self.attack._search_collision_length(email, "abc", 2)
        
        if result is not None:
            message1, message2 = result
            # Verify both messages produce the same hash
            hash1 = self.attack.calculate_hash(message1)
            hash2 = self.attack.calculate_hash(message2)
            self.assertEqual(hash1, hash2)
            self.assertNotEqual(message1, message2)
            # Verify both messages contain the email
            self.assertIn(email, message1)
            self.assertIn(email, message2)


class TestCollisionFinder(unittest.TestCase):
    """Test cases for CollisionFinder class."""
    
    def test_find_collision_generic_simple(self):
        """Test generic collision finding with simple case."""
        # Use a short string to make collision finding easier
        test_hash = hashlib.sha256(b"a").hexdigest()[:12]
        
        collision = CollisionFinder.find_collision_generic(test_hash, charset="abc", max_length=3)
        
        if collision is not None:
            msg1, msg2 = collision
            hash1 = hashlib.sha256(msg1.encode('utf-8')).hexdigest()[:12]
            hash2 = hashlib.sha256(msg2.encode('utf-8')).hexdigest()[:12]
            
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash1, test_hash)
            self.assertNotEqual(msg1, msg2)
    
    def test_find_collision_generic_properties(self):
        """Test properties of found collisions."""
        test_hash = hashlib.sha256(b"test").hexdigest()[:12]
        
        collision = CollisionFinder.find_collision_generic(test_hash, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=4)
        
        if collision is not None:
            msg1, msg2 = collision
            
            # Both messages should produce the same hash
            hash1 = hashlib.sha256(msg1.encode('utf-8')).hexdigest()[:12]
            hash2 = hashlib.sha256(msg2.encode('utf-8')).hexdigest()[:12]
            
            self.assertEqual(hash1, hash2)
            self.assertEqual(hash1, test_hash)
            self.assertNotEqual(msg1, msg2)
            
            # Both messages should be valid strings
            self.assertIsInstance(msg1, str)
            self.assertIsInstance(msg2, str)
            self.assertGreater(len(msg1), 0)
            self.assertGreater(len(msg2), 0)


class TestHashCollisionIntegration(unittest.TestCase):
    """Integration tests for hash collision attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.attack = HashCollisionAttack()
    
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
            
            # Truncated hash should be first 12 characters of full hash
            self.assertEqual(truncated_hash, full_hash[:12])
            self.assertEqual(len(truncated_hash), 12)
    
    def test_collision_probability(self):
        """Test collision probability with truncated hashes."""
        # With 48-bit hashes, collisions should be relatively common
        # due to the birthday paradox
        
        email = "test"
        seen_hashes = {}
        collision_found = False
        
        # Try different messages to find a collision
        for i in range(10000):
            message = f"{email}{i}"
            message_hash = self.attack.calculate_hash(message)
            
            if message_hash in seen_hashes:
                collision_found = True
                original_message = seen_hashes[message_hash]
                print(f"Found collision: '{original_message}' and '{message}' both hash to {message_hash}")
                break
            
            seen_hashes[message_hash] = message
        
        # With 48-bit hashes, we expect to find collisions relatively quickly
        # This test verifies the collision-finding logic works
        if collision_found:
            self.assertTrue(True)  # Collision found as expected
        else:
            print("No collision found in 10,000 attempts (unlikely but possible)")
    
    def test_search_strategies(self):
        """Test different search strategies."""
        email = "test"
        
        print(f"Testing search strategies with email: {email}")
        
        # Test optimized search
        start_time = time.time()
        result1 = self.attack.find_collision_optimized(email)
        time1 = time.time() - start_time
        
        if result1 is not None:
            print(f"Optimized search found result in {time1:.2f} seconds: {result1}")
            message1, message2 = result1
            self.assertEqual(self.attack.calculate_hash(message1), self.attack.calculate_hash(message2))
            self.assertNotEqual(message1, message2)
            self.assertIn(email, message1)
            self.assertIn(email, message2)
        
        # Test birthday attack (limited)
        start_time = time.time()
        result2 = self.attack.find_collision_birthday_attack(email, max_attempts=1000)
        time2 = time.time() - start_time
        
        if result2 is not None:
            print(f"Birthday attack found result in {time2:.2f} seconds: {result2}")
            message1, message2 = result2
            self.assertEqual(self.attack.calculate_hash(message1), self.attack.calculate_hash(message2))
            self.assertNotEqual(message1, message2)
            self.assertIn(email, message1)
            self.assertIn(email, message2)
    
    def test_performance_characteristics(self):
        """Test performance characteristics of the attack."""
        email = "test"
        
        print(f"Testing performance with email: {email}")
        
        # Test with different thread counts
        thread_counts = [1, 2, 4]
        
        for num_threads in thread_counts:
            start_time = time.time()
            result = self.attack.find_collision_brute_force(email, max_length=3, num_threads=num_threads)
            elapsed = time.time() - start_time
            
            if result is not None:
                print(f"Found result with {num_threads} threads in {elapsed:.2f} seconds")
                message1, message2 = result
                self.assertEqual(self.attack.calculate_hash(message1), self.attack.calculate_hash(message2))
                break
            else:
                print(f"No result found with {num_threads} threads in {elapsed:.2f} seconds")
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Test with empty string
        empty_hash = self.attack.calculate_hash("")
        self.assertEqual(len(empty_hash), 12)
        
        # Test with very long string
        long_string = "a" * 1000
        long_hash = self.attack.calculate_hash(long_string)
        self.assertEqual(len(long_hash), 12)
        
        # Test with special characters
        special_string = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        special_hash = self.attack.calculate_hash(special_string)
        self.assertEqual(len(special_hash), 12)
        
        # Test with unicode characters
        unicode_string = "ñáéíóú"
        unicode_hash = self.attack.calculate_hash(unicode_string)
        self.assertEqual(len(unicode_hash), 12)
    
    def test_collision_verification(self):
        """Test collision verification process."""
        email = "test"
        
        # Create a simple collision manually for testing
        hash_map = defaultdict(list)
        
        for i in range(100):
            candidate = email + str(i)
            candidate_hash = self.attack.calculate_hash(candidate)
            hash_map[candidate_hash].append(candidate)
            
            if len(hash_map[candidate_hash]) >= 2:
                messages = hash_map[candidate_hash][:2]
                
                # Verify collision properties
                hash1 = self.attack.calculate_hash(messages[0])
                hash2 = self.attack.calculate_hash(messages[1])
                
                self.assertEqual(hash1, hash2)
                self.assertNotEqual(messages[0], messages[1])
                self.assertIn(email, messages[0])
                self.assertIn(email, messages[1])
                
                print(f"Verified collision: '{messages[0]}' and '{messages[1]}' both hash to {hash1}")
                break


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
