"""
Simplified Java Random Prediction Algorithm
Shows the core vulnerability: predicting future outputs from just 2 consecutive values.

Key insight: Java only returns the upper 32 bits of its 48-bit internal state,
leaving 16 bits unknown. We can brute force these 16 bits to find the complete state.
"""

def predict_third_output(first_generated, second_generated):
    """
    Predict the third output of Java Random given two consecutive outputs.
    
    Algorithm:
    1. First output gives us upper 32 bits of state after Linear Congruential Generator (LCG)
    2. Try all 2^16 = 65,536 possible values for missing 16 bits
    3. For each candidate, work backwards to find the original seed
    4. Verify the seed produces both given outputs
    5. Use the seed to generate the third output using the LCG
    """
    # Java Random constants
    MULTIPLIER = 0x5DEECE66D  # 25214903917
    INCREMENT = 0xB           # 11
    MASK = (1 << 48) - 1      # 2^48 - 1
    
    # Step 1: Extract upper 32 bits from first output
    first_unsigned = first_generated & 0xFFFFFFFF
    upper_bits = first_unsigned << 16
    
    print(f"First output: {first_generated}")
    print(f"Upper 32 bits of state: 0x{upper_bits:012x}")
    print("Brute forcing missing 16 bits...")
    
    # Step 2: Try all possible values for missing 16 bits
    for lower_bits in range(1 << 16):  # 0 to 65535
        # Complete state after LCG that produced first output
        state_after_lcg = upper_bits | lower_bits
        
        # Step 3: Work backwards to find original seed
        # Solve: (seed * MULTIPLIER + INCREMENT) & MASK = state_after_lcg
        inverse = pow(MULTIPLIER, -1, 1 << 48)  # Modular inverse
        seed = ((state_after_lcg - INCREMENT) * inverse) & MASK
        
        # Step 4: Verify this seed produces both outputs
        if _verify_seed(seed, first_generated, second_generated):
            print(f"Found seed: 0x{seed:012x}")
            
            # Step 5: Generate third output
            state1 = _lcg(seed)      # After 1st LCG → 1st output
            state2 = _lcg(state1)    # After 2nd LCG → 2nd output  
            state3 = _lcg(state2)    # After 3rd LCG → 3rd output
            
            return _extract_output(state3)
    
    return None


def _lcg(seed):
    """Apply one LCG step: (seed * 0x5DEECE66D + 0xB) & (2^48 - 1)"""
    return (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)


def _extract_output(state):
    """Extract 32-bit signed integer from 48-bit state (Java's nextInt())"""
    result = state >> 16
    return result - (1 << 32) if result >= (1 << 31) else result


def _verify_seed(seed, expected_first_generated, expected_second_generated):
    """Check if seed produces the expected two outputs"""
    state1 = _lcg(seed)
    first = _extract_output(state1)
    if first != expected_first_generated:
        return False
    
    state2 = _lcg(state1)
    second = _extract_output(state2)
    return second == expected_second_generated


def main():
    """Demonstrate the vulnerability"""
    print("Java Random Vulnerability Demo")
    print("=" * 40)
    print("Given just 2 consecutive outputs, we can predict ALL future outputs!")
    print()
    
    # The given outputs
    first_generated = -1262723701
    second_generated = 1395360408
    
    print(f"Given outputs:")
    print(f"  1st: {first_generated:10d}")
    print(f"  2nd: {second_generated:10d}")
    print()
    
    # Predict the third output
    third = predict_third_output(first_generated, second_generated)
    
    if third is not None:
        print(f"🎯 Predicted 3rd output: {third:10d}")
        print()
        print("This demonstrates why Java Random is NOT cryptographically secure!")
        print("For security, use java.security.SecureRandom instead.")
    else:
        print("❌ Prediction failed")


if __name__ == "__main__":
    main()
