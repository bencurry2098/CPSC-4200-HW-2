#!/usr/bin/python3

# Run me like this:
# $ python padding_oracle.py "http://cpsc4200.mpese.com/username/paddingoracle/verify" "d3da3b324226f1434748d8d8eec900fe79710b7696c1d7ff90e22d073a267c96196d0fe7c017efa900351a8773c9010a5e8a5e599948f09887c0847a143f6b4c1440146556b695ba69b17d56e0df41260291ff94b325f1547bf1ea94e576c91a584e0beb4601d006d5f0fbd61776cf5569349c346ffe37899ca79ec208376797"
# Hex values:
#"eb07e5a61971583ed77d7b478202b3e0654209fc1aba8fa3c2476d55d97ea2dfc821ef121a9fe5d9dee2f36f0ea837c66c7aeb6bd8df8634c6e1ce39338951dad1dc23383407e3d77c188d6c1ee1aadf73510aaabd2f0d5a598a3d5f5247dfd3f446ccbe91b68be7e00e700d658c22ccc6500e4247b6b79fdf51ed0d5dc11e78"
#"d3da3b324226f1434748d8d8eec900fe79710b7696c1d7ff90e22d073a267c96196d0fe7c017efa900351a8773c9010a5e8a5e599948f09887c0847a143f6b4c1440146556b695ba69b17d56e0df41260291ff94b325f1547bf1ea94e576c91a584e0beb4601d006d5f0fbd61776cf5569349c346ffe37899ca79ec208376797"

# Learning resource:
# https://learning.oreilly.com/library/view/hands-on-cryptography-with/9781789534443/4ebe8259-cb99-4a19-baf1-a40b5e1b026a.xhtml

import json
import sys
import time
from typing import Union, Dict, List

import requests

# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()

# Block size in bytes
block_size = 16

def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue

# Split data into blocks of 16 bytes
def split_blocks(data):
    data_len = len(data)
    # Check if data length is a multiple of block size for CBC
    if data_len % block_size != 0:
        raise ValueError("Data length must be a multiple of the block size")
    # Split data into blocks
    return [data[i:i + block_size] for i in range(0, data_len, block_size)]

# Remove PKCS#7 padding
def pkcs7_unpad(data):
    # Check if data is empty
    if not data:
        return data
    # Get the number of padding bytes appended
    pad = data[-1]
    # Validate padding
    if (pad < 1 or pad > block_size):
        raise ValueError("Invalid padding")
    # Check if the padding follows the PKCS#7 scheme (4 bytes of \x04 for example)
    if (data[-pad:] != bytes([pad]) * pad):
        raise ValueError("Invalid padding bytes")
    # Remove padding and return unpadded data
    return data[:-pad]

    
def decrypt_with_oracle(ciphertext, oracle_url):
    # Split ciphertext into blocks
    blocks = split_blocks(ciphertext)
    # Buffer for recovered plaintext
    plaintext = bytearray()
    
    # iterate over ciphertext blocks, using previous block (or IV) to recover plaintext
    for block_index in range(1, len(blocks)):
        # Previous ciphertext block (or IV for first block)
        previous_block = bytearray(blocks[block_index - 1])
        # Current ciphertext block
        current_block = blocks[block_index]
        # Buffer for intermediate and recovered plaintext bytes
        intermediate_bytes = bytearray(block_size)
        plaintext_block = bytearray(block_size)
        # Decrypt byte by byte from last to first in the block
        for byte_position in reversed(range(block_size)):
            # The number of bytes we want to set to this value
            pad_val = block_size - byte_position
            # Copy of previous block for this iteration
            modified_block = bytearray(previous_block)
            # Set what we already know to the correct padding value
            for known_index in range(byte_position + 1, block_size):
                modified_block[known_index] = intermediate_bytes[known_index] ^ pad_val
            # Build 256 candidates changing only byte_position
            messages = []
            candidates = []
            for guess in range(256):
                # Create modified block
                modified = bytearray(modified_block)
                # Change only the target byte
                modified[byte_position] = guess
                # Modified block || current ciphertext block
                messages.append(bytes(modified + bytearray(current_block)))
                # Keep track of guesses to map responses
                candidates.append(guess)
            
            # Send batch to oracle
            responses = oracle(oracle_url, messages)
            
            # Flag to indicate if we found a valid padding byte
            found = False
            # Iterate over responses to find a valid padding
            for response_index, response in enumerate(responses):
                # Check if response indicates valid padding
                status = response.get("status", "")
                if status != "invalid_padding":
                    # Recover what byte we guessed
                    guess = candidates[response_index]
                    # The intermediate byte = guess ^ pad_val
                    intermediate_value = guess ^ pad_val
                    # Store this byte for future iterations
                    intermediate_bytes[byte_position] = intermediate_value
                    # Recover plaintext byte: plaintext_byte = intermediate_byte ^ previous_ciphertext_byte
                    plaintext_block[byte_position] = intermediate_value ^ previous_block[byte_position]
                    found = True
                    break
            if not found:
                # Fall back to single byte guessing if batch didn't find valid padding
                for guess in range(256):
                    modified = bytearray(modified_block)
                    modified[byte_position] = guess
                    response = oracle(oracle_url, [bytes(modified + bytearray(current_block))])[0]
                    if response.get("status", "") != "invalid_padding":
                        intermediate_value = guess ^ pad_val
                        intermediate_bytes[byte_position] = intermediate_value
                        plaintext_block[byte_position] = intermediate_value ^ previous_block[byte_position]
                        found = True
                        break
            # If still not found, we couldn't decrypt this byte
            if not found:
                raise RuntimeError(f"Could not find valid padding byte for block {block_index} byte {byte_position}")
        # Append recovered block to plaintext
        plaintext.extend(plaintext_block)
    # Return full recovered plaintext (including padding and HMAC)
    return bytes(plaintext)


def main():
    # Check command line arguments
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    
    # Parse command line arguments
    oracle_url = sys.argv[1]
    ciphertext_hex = sys.argv[2]
    
    # Convert hex to bytes, error check
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except Exception:
        raise ValueError("Invalid hex input for ciphertext")
    
    # Decrypt the message using the padding oracle
    try:
        recovered = decrypt_with_oracle(ciphertext, oracle_url)
    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")

    # Attempt to unpad the recovered plaintext
    try:
        unpadded = pkcs7_unpad(recovered)
    except ValueError:
        raise ValueError("Decrypted plaintext has invalid padding")

    # Ensure there's enough data for HMAC
    if len(unpadded) < 32:
        raise ValueError("Decrypted data too short to contain HMAC")

    # Remove the last 32 bytes (HMAC-SHA256)
    payload = unpadded[:-32]

    # Print the recovered payload
    try:
        print(payload.decode('utf-8', errors='replace'))
    except Exception:
        print(payload)

if __name__ == '__main__':
    main()