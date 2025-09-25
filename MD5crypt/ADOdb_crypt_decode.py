import base64


def eliminate_internal_key(encrypted_text: str):
    """
    Eliminate the internal key by XORing even and odd characters
    This reduces the problem to a simple Vigenère cipher with 16-character key
    """
    print("=== Eliminating Internal Key ===")

    try:
        # Decode base64
        decoded = base64.b64decode(encrypted_text)
        print(f"Base64 decoded length: {len(decoded)} bytes")

        # The structure is: [md5_char, encrypted_char, md5_char, encrypted_char, ...]
        # We need to XOR even and odd characters to eliminate the internal key
        new_ciphertext = bytearray()

        for i in range(0, len(decoded), 2):
            if i + 1 < len(decoded):
                # XOR the MD5 char with the encrypted char
                new_char = decoded[i] ^ decoded[i + 1]
                new_ciphertext.append(new_char)

        print(f"New ciphertext length: {len(new_ciphertext)} bytes")
        print(f"First 20 bytes: {list(new_ciphertext[:20])}")

        return bytes(new_ciphertext)

    except Exception as e:
        print(f"Error eliminating internal key: {e}")
        return None


def vigenere_decrypt_with_known_text(ciphertext: bytes, known_text: str):
    """
    Decrypt using Vigenère with known text attack
    """
    print("\n=== Vigenère Decrypt with Known Text ===")
    print("Known text: '{known_text}'")

    known_bytes = known_text.encode("utf-8")
    print(f"Known text length: {len(known_bytes)} characters")

    # Try different positions for the known text
    for start_pos in range(len(ciphertext) - len(known_bytes) + 1):
        # Extract the ciphertext portion that might contain the known text
        ciphertext_portion = ciphertext[
            start_pos : start_pos + len(known_bytes)
        ]

        # Calculate what the key should be at this position
        # For Vigenère: ciphertext = plaintext ^ key
        # So: key = plaintext ^ ciphertext
        potential_key = bytearray()
        for i in range(len(known_bytes)):
            key_char = known_bytes[i] ^ ciphertext_portion[i]
            potential_key.append(key_char)

        # The key should be 16 characters (repeated)
        # Check if this looks like a valid key pattern
        key_16 = (
            potential_key[:16] if len(potential_key) >= 16 else potential_key
        )

        print(f"\nPosition {start_pos}:")
        print(f"  Ciphertext portion: {list(ciphertext_portion)}")
        print(f"  Potential key (first 16): {list(key_16)}")

        # Try to decrypt the entire message with this key
        decrypted = bytearray()
        for i in range(len(ciphertext)):
            key_char = key_16[i % len(key_16)]
            decrypted_char = ciphertext[i] ^ key_char
            decrypted.append(decrypted_char)

        try:
            decrypted_text = decrypted.decode("utf-8", errors="ignore")

            # Check if this looks like a valid email
            if known_text in decrypted_text:
                print("  🎉 SUCCESS!")
                print(f"  Key (16 chars): {key_16.hex()}")
                print(f"  Decrypted text: {decrypted_text}")
                return decrypted_text, key_16.hex()
            else:
                # Show partial results for analysis
                if len(decrypted_text) > 0 and any(
                    char.isalnum() for char in decrypted_text
                ):
                    print(f"  Partial result: {decrypted_text[:100]}...")

        except Exception as e:
            print(f"  Error decoding: {e}")

    return None, None


def brute_force_16_char_key(ciphertext: bytes, known_text: str):
    """
    Brute force attack on the 16-character key
    """
    print(f"\n=== Brute Force 16-Character Key ===")

    # Generate all possible 16-character keys from hex digits
    hex_chars = "0123456789abcdef"

    # Try common patterns first
    common_patterns = [
        "0000000000000000",
        "1111111111111111",
        "2222222222222222",
        "0123456789abcdef",
        "fedcba9876543210",
        "abcdef0123456789",
        "1234567890abcdef",
        "abcdef1234567890",
        "0000000000000001",
        "ffffffffffffffff",
        "aaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbb",
        "cccccccccccccccc",
        "dddddddddddddddd",
        "eeeeeeeeeeeeeeee",
        "ffffffffffffffff",
    ]

    print("Trying common patterns...")
    for pattern in common_patterns:
        if len(pattern) == 16:
            key_bytes = bytes.fromhex(pattern)
            decrypted = bytearray()

            for i in range(len(ciphertext)):
                key_char = key_bytes[i % len(key_bytes)]
                decrypted_char = ciphertext[i] ^ key_char
                decrypted.append(decrypted_char)

            try:
                decrypted_text = decrypted.decode("utf-8", errors="ignore")
                if known_text in decrypted_text:
                    print(f"🎉 SUCCESS with pattern: {pattern}")
                    print(f"Decrypted text: {decrypted_text}")
                    return decrypted_text, pattern
            except:
                continue

    print("Common patterns didn't work. Trying systematic approach...")

    # Try systematic approach (this will take a while)
    # For now, let's try a limited search
    for i in range(256):  # Try first 256 combinations
        key_hex = f"{i:016x}"
        key_bytes = bytes.fromhex(key_hex)

        decrypted = bytearray()
        for j in range(len(ciphertext)):
            key_char = key_bytes[j % len(key_bytes)]
            decrypted_char = ciphertext[j] ^ key_char
            decrypted.append(decrypted_char)

        try:
            decrypted_text = decrypted.decode("utf-8", errors="ignore")
            if known_text in decrypted_text:
                print(f"🎉 SUCCESS with key: {key_hex}")
                print(f"Decrypted text: {decrypted_text}")
                return decrypted_text, key_hex
        except:
            continue

        if i % 50 == 0:
            print(f"Progress: {i}/256 keys tried")

    return None, None


def solve_md5crypt_challenge(encrypted_text: str):
    """
    Solve the md5crypt challenge using the analysis from the problem statement
    """
    print("=== Solving MD5Crypt Challenge ===")
    print("Using the analysis from the problem statement...")

    # Step 1: Eliminate the internal key
    new_ciphertext = eliminate_internal_key(encrypted_text)

    known_text = "diegooleiarz@hotmail.com"

    if new_ciphertext is None:
        print("Failed to eliminate internal key")
        return None, None

    # Step 2: Try known text attack
    result, key = vigenere_decrypt_with_known_text(new_ciphertext, known_text)

    if result:
        return result, key

    # Step 3: Try brute force on 16-character key
    result, key = brute_force_16_char_key(new_ciphertext, known_text)

    if result:
        return result, key

    return None, None


if __name__ == "__main__":
    # The encrypted text from the challenge
    encrypted_text = "INSERT_ENCRYPTED_TEXT_HERE"

    print("=== MD5Crypt Challenge Solver ===")
    print("Solving using the analysis from the problem statement...")

    # Solve the challenge
    result, key = solve_md5crypt_challenge(encrypted_text)

    if result:
        print("\n🎉 CHALLENGE SOLVED!")
        print(f"Key: {key}")
        print(f"Decrypted message:\n{result}")

        # Save to file for submission
        with open("message.txt", "w", encoding="utf-8") as f:
            f.write(result)
        print("\nMessage saved to message.txt")
        print("You can now submit it using:")
    else:
        print("\n❌ Could not solve the challenge.")
        print(
            "The analysis might need refinement or the known text might not be present."
        )
