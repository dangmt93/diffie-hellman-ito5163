"""
Description: 
Author: Thomas Dang
Date: 19-May-2025

Notes:
    - 
"""
import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import math

def generate_dh_private(p: int) -> int:
    """
    Generate a Diffie-Hellman private key between 2 and p-2, inclusive.

    Args:
        p (int): A prime number used in the Diffie-Hellman key exchange.
        
    Returns:
        int: A private key in the range [2, p-2].
    """
    return secrets.randbelow(p - 3) + 2 
    # randbelow(p - 3) produces an integer in [0, p - 4], adding 2 shifts it to [2, p - 2].
    # used secrets.randbelow() for better security (cryptographic randomness) than random.randint
    #? random.randint vs secrets.randbelow: https://www.reddit.com/r/learnpython/comments/7w8w6y/what_is_the_different_between_the_random_module/

def compute_dh_public(p: int, g: int, private: int) -> int:
    """
    Compute the Diffie-Hellman public key: g^private mod p (A = g^a mod p).

    Args:
        p (int): A prime number used in the Diffie-Hellman key exchange.
        g (int): A primitive root modulo p.
        private (int): A private key of the user.

    Returns:
        int: The public key of the user.
    """
    return pow(g, private, p)

def compute_shared_secret(p: int, peer_public: int, private: int) -> int:
    """
    Compute the shared secret: peer_public^private mod p (K = B^a mod p).

    Args:
        p (int): A prime number used in the Diffie-Hellman key exchange.
        peer_public (int): The public key of the peer.
        private (int): The private key of this user.

    Returns:
        int: The shared secret key.
    """
    return pow(peer_public, private, p)


def derive_symmetric_key(shared_secret: int, 
                        length: int = 32, 
                        salt: bytes | None = None, 
                        info: bytes | None = None
    ) -> bytes:
    """
    Derive a symmetric key from DH shared secret using HKDF-SHA256.

    Args:
        shared_secret (int): The shared secret key derived from the Diffie-Hellman key exchange.
        length (int, optional): The desired length of the derived key in bytes. Defaults to 32 bytes.
        salt (bytes, optional): The HKDF salt. Defaults to None. 
                                    **Note**: If added, this must be sent to the peer.
        info (bytes, optional): The HKDF info. Defaults to None. 
                                    This is a application-specific context string. Use it to 
                                    bind the derived key to a protocol version or purpose,
                                    preventing accidental key reuse across contexts.
                                    **Note**: If added, peer must use the same info string.
    Returns:
        bytes: A `length`-byte key suitable for AEAD ciphers (AES-GCM, ChaCha20-Poly1305).
    """
    # Convert shared secret to bytes
    #? If bit length is not a multiple of 8, need to round up to nearest whole byte (1 byte = 8 bits)
    secret_bytes_ceil: int = math.ceil(shared_secret.bit_length() / 8)
    secret_bytes = shared_secret.to_bytes(length=secret_bytes_ceil, byteorder='big')
    
    # Set up HKDF-SHA256
    hkdf: HKDF = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    # Derive and return symmetric key
    return hkdf.derive(secret_bytes)


if __name__ == "__main__":
    # Example parameters
    p = 41  # A prime number
    g = 49  # A primitive root modulo p

    # Generate private keys
    private_a = 29364845492453128999703544227716908011430739688176880770541541021043088653776
    private_b = 52310969057422642239996398424873765537874701074077817731179068188790798857374

    # Compute public keys
    public_a = compute_dh_public(p, g, private_a)
    public_b = compute_dh_public(p, g, private_b)

    # Compute shared secrets
    shared_secret_a = compute_shared_secret(p, public_b, private_a)
    shared_secret_b = compute_shared_secret(p, public_a, private_b)

    print(f"Private A: {private_a}, Public A: {public_a}, Shared Secret A: {shared_secret_a}")
    print(f"Private B: {private_b}, Public B: {public_b}, Shared Secret B: {shared_secret_b}")