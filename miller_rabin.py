"""
Description: 
Author: Thomas Dang
Date: 19-May-2025

Notes:
    - 
"""
import random
import secrets

def miller_rabin_is_probable_prime(n: int, n_rounds: int = 20) -> bool:
    """
    Perform the Miller-Rabin primality test on n to determine if it is a (probable) prime.
    
    NOTE: Miller-Rabin test is probabilistic. The algorithm applies multiple rounds to the candidate number n. 
    In each round, a random base `a` (1 < a < n-1) is selected, and n is tested for compositeness. 
    If n passes a round, it is a "probable prime". 
    However, in each round, there is a 1/4 chance of false positive (i.e., a composite number passing the test).
    Thus, the higher the number of rounds, the lower the probability of a false positive (i.e., higher confidence degree that the number is prime). 
    False positive rate = 1/4^rounds.

    Args:
        n (int): The number to be tested for primality.
        n_rounds (int, optional): Number of test rounds (higher = lower false positive rate but longer runtime). Default is 20.

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

    # Write n-1 as 2^k * q with q odd (by factoring out all 2s from n-1)
    k: int = 0
    q: int = n - 1
    while q % 2 == 0:
        q //= 2 # Divide q by 2 until it is odd
        k += 1  # Keep track of the number of divisions
    # Now, we have n-1 = 2^k * q, where q is odd and k > 0
    # print(f"With n = {n}, n-1 = 2^{k} * {q}") #!--- For testing

    def _miller_rabin_single_round(a: int) -> bool:
        """
        Perform a single round of the Miller-Rabin test with base `a`.

        Args:
            a (int): The base to test against.

        Returns:
            bool: True if n passes this round, False if it fails.
        """
        # Compute x = a^q mod n
        x: int = pow(a, q, n)
        
        # 1st check: if a^q mod n = 1 or n-1, this round passes
        #? According to https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/, it also checks if x == n-1
        if x == 1 or x == n - 1:
            return True # This round passes (i.e., n is probably prime)
        
        # 2nd check: if 1st check is not met, check if x can be squared k times to reach n-1
        # Loop for j in [0, k-1] (k times), check if (a^q)^(2^j) mod n = x^(2^j) mod n = n-1. If we find such j, n is probably prime
        for _ in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True # This round passes (i.e., n is probably prime)
            
        # If both checks are not met, n is composite (i.e., guaranteed not prime)
        return False

    # Run n_rounds rounds of Miller-Rabin test (false positive rate = 1/4^n_rounds)
    for _ in range(n_rounds):
        # Select a random base `a` in the range [2, n-2] (1 < a < n-1)
        a: int = secrets.randbelow(n - 3) + 2
        # randbelow(n - 3) produces an integer in [0, p - 4], adding 2 shifts it to [2, p - 2].
        # used secrets.randbelow() for better security (cryptographic randomness), instead of a: int = random.randint(2, n - 2)
        #? random.randint vs secrets.randbelow: https://www.reddit.com/r/learnpython/comments/7w8w6y/what_is_the_different_between_the_random_module/
        
        if not _miller_rabin_single_round(a):
            return False
        
    # If passed all rounds, n has high probability of being prime (more rounds = lower false positive rate)
    return True

def get_random_odd_number(bits: int) -> int:
    """
    Generate a random odd number with the given number of bits.
        1. Top bit is set -> number is of full length (i.e., it has the specified number of bits)
        2. Bottom bit is set -> number is odd

    Args:
        bits (int): Number of bits in the generated random number.

    Returns:
        int: Random odd integer of the specified bit length.
    """
    n: int = random.getrandbits(bits) # Generate a random number with the specified number of bits, in range [0, 2^bits - 1], inclusive.
    # Perform bitwise OR with masks to set top and bottom bits:
    n |= (
        (1 << (bits - 1)) # Set top bit: full length (mask 100...0)
        | 1  # Set bottom bit: odd (mask 000...1)
    )
    
    print(f"Generated random odd number of length: {n.bit_length()}")  #!--- For testing
    return n

def generate_large_prime(bits: int, n_rounds: int = 20) -> int:
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
    import time
    
    bits: int = 2048
    
    start_time: float = time.time()
    prime: int = generate_large_prime(bits)
    print(f"Generated {bits}-bit prime:\n{prime}")
    print("--- %s seconds ---" % (time.time() - start_time))
