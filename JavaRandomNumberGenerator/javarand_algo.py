"""
Java Random Number Generator Implementation
Implements the Linear Congruential Generator (LCG) used by Java's Random class.

Constants:
- Multiplier: 25214903917 (0x5DEECE66DL)
- Increment: 11 (0xBL)
- Modulus: 2^48 (1L << 48)

The generator uses 48-bit arithmetic but returns 32-bit integers by taking
the upper 32 bits of the 48-bit state.
"""

class JavaRandom:
    def __init__(self, seed=None):
        """
        Initialize the Java random number generator.
        
        Args:
            seed: Initial seed value. If None, uses current time.
        """
        if seed is None:
            import time
            seed = int(time.time() * 1000) & 0xFFFFFFFF
        
        self.seed = self._set_seed(seed)
    
    def _set_seed(self, seed):
        """
        Set the seed using Java's exact algorithm.
        
        Args:
            seed: The seed value to set
            
        Returns:
            The processed seed value (48 bits)
        """
        # Java: this.seed = (seed ^ 0x5DEECE66DL) & ((1L << 48) - 1)
        return (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
    
    def next_int(self):
        """
        Generate the next 32-bit integer using Java's algorithm.
        
        Returns:
            A 32-bit integer (signed)
        """
        # Java: this.seed = (this.seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1)
        self.seed = (self.seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        
        # Java: return (int)(this.seed >>> 16)
        # Extract upper 32 bits and convert to signed 32-bit integer
        result = self.seed >> 16
        
        # Convert to signed 32-bit integer if needed
        if result >= (1 << 31):
            result -= (1 << 32)
        
        return result
    
    def _unsigned_right_shift(self, value, shift):
        """
        Perform unsigned right shift (Java's >>> operator).
        
        Args:
            value: The value to shift
            shift: Number of bits to shift right
            
        Returns:
            The result of unsigned right shift
        """
        # Ensure we're working with 48-bit values
        value = value & ((1 << 48) - 1)
        return value >> shift
    
    def next_long(self):
        """
        Generate the next 64-bit long using Java's algorithm.
        
        Returns:
            A 64-bit long (signed)
        """
        # Java generates two 32-bit values and combines them
        high = self.next_int()
        low = self.next_int()
        
        # Combine into 64-bit value
        return (high << 32) + (low & 0xFFFFFFFF)
    
    def next_double(self):
        """
        Generate the next double using Java's algorithm.
        
        Returns:
            A double between 0.0 and 1.0
        """
        # Java uses 26 bits for the high part and 27 bits for the low part
        high = self.next_int() >> 6  # Take upper 26 bits
        low = self.next_int() >> 5   # Take upper 27 bits
        
        # Combine and normalize
        return (high * (1 << 27) + low) / (1 << 53)
    
    def get_state(self):
        """
        Get the current state of the generator.
        
        Returns:
            The current 48-bit seed value
        """
        return self.seed
    
    def set_state(self, state):
        """
        Set the state of the generator.
        
        Args:
            state: The 48-bit state value to set
        """
        self.seed = state & ((1 << 48) - 1)


def test_java_random():
    """
    Test the Java random implementation to verify it works correctly.
    """
    print("Testing Java Random Implementation")
    print("=" * 40)
    
    # Test with a known seed
    rng = JavaRandom(12345)
    
    print(f"Initial seed: {rng.get_state():012x}")
    print()
    
    # Generate some numbers
    print("First 10 integers:")
    for i in range(10):
        val = rng.next_int()
        print(f"  {i+1:2d}: {val:10d} (0x{val:08x})")
    
    print()
    print("First 5 doubles:")
    for i in range(5):
        val = rng.next_double()
        print(f"  {i+1}: {val:.10f}")
    
    print()
    print("First 3 longs:")
    for i in range(3):
        val = rng.next_long()
        print(f"  {i+1}: {val:20d} (0x{val:016x})")


if __name__ == "__main__":
    test_java_random()
