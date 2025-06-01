"""
Description: 
Author: Thomas Dang
Date: 19-May-2025

Notes:
    - 
"""

import random

def miller_rabin_is_probable_prime(n, n_rounds=20) -> bool:
    """
    Perform the Miller-Rabin primality test on n to determine if it is a (probable) prime.
    
    NOTE: Miller-Rabin test is probabilistic, 
    meaning it can return false positives (composite numbers that pass the test).
    The higher the number of rounds, the lower the probability of a false positive.
    
    Args:
        n (int): The number to be tested for primality.
        n_rounds (int, optional): Number of test rounds (higher = lower error rate but longer). Default is 20.

    Returns:
        bool: True if the number is a probable prime, False otherwise (possibly composite).
    """
    # Handle base cases
    if n < 2: 
        return False
    if n in (2, 3): 
        return True
    if n % 2 == 0: 
        return False

    '''
    Miller-Rabin test is based on 2 properties of prime numbers:
        1. If n is prime, then for any integer a such that 1 < a < n-1, it holds that a^(n-1) ≡ 1 (mod n).
        2. If n is prime, then for any integer a such that 1 < a < n-1, it holds that a^((n-1)/d) ≢ 1 (mod n) for all prime factors d of n-1.
    
    The Miller-Rabin test is a probabilistic test that uses these properties to determine if n is likely prime.
    The test is based on the fact that if n is prime, then for any integer a such that 1 < a < n-1, it holds that:
    a^(n-1) ≡ 1 (mod n).
    If n is not prime, then for any integer a such that 1 < a < n-1, it holds that:
    a^((n-1)/d) ≢ 1 (mod n) for all prime factors d of n-1.
    '''

    # Write n-1 as 2^k * q with q odd (by factoring out all 2s from n-1)
    k: int = 0
    q: int = n - 1
    while q % 2 == 0:
        q //= 2 # Divide q by 2 until it is odd
        k += 1 # Keep track of the number of divisions
    # Now n-1 = 2^k * q, where q is odd and k > 0
    # print(f"With n = {n}, n-1 = 2^{k} * {q}") #!--- For testing

    # Run n_rounds rounds of testing
    for _ in range(n_rounds):
        # Select a random integer a in the range [2, n-2] (1 < a < n-1)
        a: int = random.randint(2, n - 2)
        # Compute x = a^q mod n
        x: int = pow(a, q, n)
        
        # If a^(n-1) mod n = 1 or = n-1, return "inconclusive" (this round passes)
        #? According to https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/, it also checks if x == n-1
        if x == 1 or x == n-1:
            continue # This round passes (inconclusive), continue to next round
        
        # Loop for k-1 iterations to check if for any j in [0, k-1], a^(2^j * q) mod n = n-1
        # If we find such j, n is probably prime
        for _ in range(k-1):
            x: int = pow(x, 2, n) # Keep squaring x (i.e., compute a^(2^(j+1) * q) mod n instead of recomputing a^(2^j * q) mod n)
            if x == n - 1:
                break # This round passes (inconclusive), continue to next round
        
        else:
            # None of the conditions were met, n is composite
            return False
        
    # If passed all rounds, n is probably prime
    return True

def get_random_odd_number(bits) -> int:
    """
    Generate a random odd number with the given number of bits.
        1. Top bit is set -> number is of full length (i.e., it has the specified number of bits)
        2. Bottom bit is set -> number is odd

    Args:
        bits (int): Number of bits in the generated random number.

    Returns:
        int: Random odd integer of the specified bit length.
            
    """
    n: int = random.getrandbits(bits)
    n |= (1 << (bits - 1)) | 1 # Ensure top and bottom bits set: full length, odd
    return n

def generate_large_prime(bits, n_rounds=20) -> int:
    """
    Generate a large prime number with the given number of bits.

    Args:
        bits (int): The number of bits in the generated prime number.
        n_rounds (int, optional): Number of rounds of the Miller-Rabin test to run. Defaults to 20.

    Returns:
        int: A large prime number with the given number of bits.
    """
    while True:
        candidate: int = get_random_odd_number(bits)
        # print(f"Testing candidate: {candidate}") #!--- For testing
        
        # Run Miller-Rabin test n_rounds times to check if the candidate is a probable prime
        # if probable prime, return it, otherwise continue to next candidate
        if miller_rabin_is_probable_prime(candidate, n_rounds):
            return candidate


if __name__ == "__main__":
    bits: int = 2048
    prime: int = generate_large_prime(bits)
    print(f"Generated {bits}-bit prime:\n{prime}")
