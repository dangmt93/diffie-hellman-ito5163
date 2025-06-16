"""
Description: 
Author: Thomas Dang
Date: 2-June-2025

Notes:
    - 
"""
import random
import secrets
import multiprocessing
from multiprocessing.synchronize import Event as ProcessEvent

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


def generate_safe_prime_pair(safe_prime_bits: int) -> tuple[int, int]:
    """
    Generate a pair of safe prime p (with the given bit length) and its Sophie Germain prime q.

    **Note**: A safe prime is a prime number of the form p = 2q + 1, where q is also prime, also known as a Sophie Germain prime.

    The algorithm repeatedly:
        1) Samples a random odd number q in the range [2^(bits-2), 2^(bits-1) - 1] (ensuring p has exactly `safe_prime_bits` bits), checks if it is prime.
        2) Once a prime q is found, computes p = 2*q + 1 and checks if it is prime.
        3) If p is prime, returns (p, q). Otherwise, goes back to (1).
    
    Rationale for the q-bounds so that p has exactly `safe_prime_bits` bits:
        - By definition, an integer p has bit-length bits if: 2^(bits-1) <= p < 2^bits
        - Since p is odd, p has: 
            - Lower bound: 2^(bits-1) + 1 (the smallest odd number with `bits` bits)
            - Upper bound: 2^bits - 1 (the largest odd number with `bits` bits)
            
        - Since q = (p - 1)/2, we can derive bounds for q:
            - Lower bound:
                - q = (p - 1) / 2 = (2^(bits-1) + 1 - 1) / 2 = 2^(bits-1) / 2 = 2^(bits-2)
            - Upper bound:
                - q = (p - 1) / 2 = (2^bits - 1 - 1) / 2 = (2^bits - 2) / 2 = 2^(bits-1) - 1
        - Therefore, q must be in the range [2^(bits-2), 2^(bits-1) - 1] to ensure p has exactly `safe_prime_bits` bits. 
    
    Args:
        safe_prime_bits (int): The number of bits in the generated safe prime.

    Returns:
        tuple[int, int]: A tuple (p, q) where:
            - p is the safe prime of the specified bit length
            - q is the corresponding Sophie Germain prime

    Raises:
        ValueError: If the bit length is less than 3.
    """
    if safe_prime_bits < 3:
        raise ValueError("Bit length must be at least 3 for a safe prime.")
    
    # Inclusive bounds for q, so that p = 2q + 1 has the correct bit length (exactly `safe_prime_bits` bits)
    min_q: int = 1 << (safe_prime_bits - 2)         # 2^(bits-2)
    max_q: int = (1 << (safe_prime_bits - 1)) - 1   # 2^(bits-1) - 1
    
    while True:
        # 1) Sample q in bounds [min_q, max_q]
        q: int = random.randrange(min_q, max_q + 1) # +1 because randrange is exclusive on the upper bound
        q |= 1  # ensure q is odd
        
        if not miller_rabin_is_probable_prime(q): 
            continue
        
        # 2) Generate safe prime p = 2q + 1
        p: int = 2 * q + 1
        
        if miller_rabin_is_probable_prime(p):
            return p, q


def worker_generate_safe_prime_pair(safe_prime_bits: int, stop_event: ProcessEvent, result_queue: multiprocessing.Queue) -> None:
    """
    Worker process function to generate a safe prime pair (p, q) generation.

    This function is intended to be run in a separate process that attempts to generate a safe prime pair (p, q) given a bit length. 
        - Before starting, it checks if the stop_event is already set, indicating that another worker has already succeeded, in which case it exits.
        - If it succeeds and no other worker has already succeeded (stop_event is not set),
            it puts the result into the shared result_queue and set stop_event to signal other workers to stop.

    If any other error occurs, just exit. This can happen if the queue is full or another worker has already put a result in the queue.

    Args:
        safe_prime_bits (int): The number of bits in the generated safe prime.
        stop_event (multiprocessing.synchronize.Event): Event to signal workers to stop.
        result_queue (multiprocessing.Queue): Queue to put the result (p, q) into.

    Returns:
        None
    """
    # Check if stop_event is already set before starting work 
    # to avoid unnecessary computation if another worker has already won (i.e., found p and q).
    if stop_event.is_set():
        return

    # Call pure generator: Generate a safe prime pair (p, q)
    # This will keep trying until:
    # - it finds a valid pair (i.e., first worker to succeed -> push result into queue and set stop_event to signal others to stop)
    # - or the stop_event is set (i.e., another worker has won, so this worker should exit)
    p, q = generate_safe_prime_pair(safe_prime_bits)

    # If stop_event is still not set (i.e., this worker is the first to succeed), 
    # push result into queue and set stop_event to signal others to stop
    if not stop_event.is_set():
        try:
            result_queue.put((p, q))
            stop_event.set()
        except Exception:
            # If any other error occurs, just exit
            print(f"Worker {multiprocessing.current_process().name} failed to put result in queue (queue may be full or already has a result).")
            return
    # Then exit (any remaining work is handled by the main process)



def generate_safe_prime_pair_parallel(safe_prime_bits: int, num_workers: int | None = None) -> tuple[int, int]:
    """
    Generate a safe prime pair (p, q) using parallel processing.

    This function launches multiple worker processes to concurrently generate a safe prime pair (p, q) of the specified bit length. 
    
    The first worker to succeed puts its result into a shared queue and sets a stop event, and the main process:
        1) Retrieves the result from the queue.
        2) Sets stop_event to signal any remaining workers to stop (make sure all workers see the stop signal, in case the succeeded worker fails to set).
        3) Forcefully terminates any remaining alive workers.
        4) Waits for all workers to finish before returning the result.

    Args:
        safe_prime_bits (int): The number of bits in the generated safe prime.
        num_workers (int | None, optional): The number of worker processes to use. If None,
            the number of CPU cores is used by default.

    Returns:
        tuple[int, int]: A tuple (p, q) where:
            - p is the safe prime of the specified bit length
            - q is the corresponding Sophie Germain prime
    """
    # If num_workers is not specified, use the number of CPU cores
    if num_workers is None:
        num_workers = multiprocessing.cpu_count()

    # Shared primitives
    stop_event: ProcessEvent = multiprocessing.Event()
    result_queue: multiprocessing.Queue = multiprocessing.Queue()
    workers: list[multiprocessing.Process] = []

    # Spawn worker processes to run the safe prime generator
    for i in range(num_workers):
        worker_process = multiprocessing.Process(
            target=worker_generate_safe_prime_pair,
            args=(safe_prime_bits, stop_event, result_queue),
            name=f"SafePrimeWorker-{i}"
        )
        worker_process.start()
        workers.append(worker_process) # Keep track of all worker processes

    # Block until (wait for) the first worker finishes and put its result into the queue
    #? result_queue.get() blocks until the queue is not empty
    p_val, q_val = result_queue.get()

    # Now we have a winner (i.e., have result in queue)
    # set stop_event to signal the other workers to stop (in case the succeeded worker fails to set it)
    stop_event.set()
    
    # Forcefully terminate all worker processes that are still alive
    for worker_process in workers:
        if worker_process.is_alive():
            worker_process.terminate()  # force‐kill immediately

    # Wait for all worker processes to finish (for clean exit)
    #? join() blocks until all worker processes have finished
    for worker_process in workers:
        worker_process.join()

    # Return the found safe prime pair (p, q)
    return p_val, q_val


def find_primitive_root_from_safe_prime(p: int, q: int, smallest_primitive_root: bool = True) -> int:
    """
    Find a primitive root modulo a safe prime p of the form 2q + 1.
    
    It can either find the smallest primitive root (in sequential order) or any primitive root (chosen randomly) 
    depending on the parameter `smallest_primitive_root`.

    Args:
        p (int): A safe prime number.
        q (int): The corresponding Sophie Germain prime.
        smallest_primitive_root (bool, optional): Flag to indicate if the smallest
            primitive root should be found. Defaults to True.

    Returns:
        int: A primitive root modulo p.

    Raises:
        ValueError: If no primitive root is found, although this should not happen for safe primes.
    """

    prime_factors: list[int] = [2, q]  # The only prime factors of p-1 are 2 and q (since p = 2q + 1, so p-1 = 2q)
    
    if smallest_primitive_root:
        # Search sequentially for smallest primitive root modulo p
        for g in range(2, p-1): # search in [2, p-2] (since g = p-1 or 1 are not primitive roots)
            #? g is a primitive root mod p if g^((p-1)/r) != 1 (mod p) for each prime divisor r of p-1
            if all(pow(g, (p-1)//factor, p) != 1 for factor in prime_factors):
                return g
    else:
        # Search randomly for a primitive root modulo p
        while True:
            g: int = random.randrange(2, p-1)
            if all(pow(g, (p-1)//factor, p) != 1 for factor in prime_factors):
                return g
    
    raise ValueError("No primitive root found")  # Shouldn't happen for safe primes

if __name__ == "__main__":
    import time
    
    time_start: float = time.time()
    BITS = 512
    print(f"Starting parallel safe-prime search ({multiprocessing.cpu_count()} workers)…")
    p, q = generate_safe_prime_pair_parallel(BITS)
    print(f"\n→ Found safe prime p (bit-length {p.bit_length()}):\n{p}\n")
    print(f"→ Corresponding q (bit-length {q.bit_length()}):\n{q}")
    
    print(f"\nTime taken: {time.time() - time_start} seconds")
    
    primitive_root: int = find_primitive_root_from_safe_prime(p, q)
    print(f"\n→ Found primitive root g (bit-length {primitive_root.bit_length()}):\n{primitive_root}")