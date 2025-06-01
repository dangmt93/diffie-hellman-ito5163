"""
Description: 
Author: Thomas Dang
Date: 19-May-2025

Notes:
    - 
"""

import secrets

def generate_dh_private(p) -> int:
    """
    Generate a Diffie-Hellman private key between 2 and p-2, inclusive.

    Args:
        p (int): A prime number used in the Diffie-Hellman key exchange.
        
    Returns:
        int: A private key in the range [2, p-2].
    """
    return secrets.randbelow(p - 3) + 2 
    # randbelow(p - 3) produces an integer in [0, p - 4], adding 2 shifts it to [2, p - 2].
    #? random.randint vs secrets.randbelow: https://www.reddit.com/r/learnpython/comments/7w8w6y/what_is_the_different_between_the_random_module/

def compute_dh_public(p, g, private) -> int:
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

def compute_shared_secret(p, peer_public, private) -> int:
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


if __name__ == "__main__":
    # Example parameters
    p = 41  # A prime number
    g = 49  # A primitive root modulo p

    # Generate private keys
    private_a = 29364845492453128999703544227716908011430739688176880770541541021043088653776
    private_b = 52310969057422642239996398424873765537874701074077817731179068188790798857374

    # Compute public keys
    public_a = compute_dh_public(g, private_a, p)
    public_b = compute_dh_public(g, private_b, p)

    # Compute shared secrets
    shared_secret_a = compute_shared_secret(public_b, private_a, p)
    shared_secret_b = compute_shared_secret(public_a, private_b, p)

    print(f"Private A: {private_a}, Public A: {public_a}, Shared Secret A: {shared_secret_a}")
    print(f"Private B: {private_b}, Public B: {public_b}, Shared Secret B: {shared_secret_b}")