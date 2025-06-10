"""
Description: 
Author: Thomas Dang
Date: 2-June-2025

Notes:
    - 
"""
import random
import multiprocessing
from multiprocessing.synchronize import Event as ProcessEvent
from miller_rabin import miller_rabin_is_probable_prime, get_random_odd_number


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


if __name__ == "__main__":
    import time
    
    time_start: float = time.time()
    BITS = 512
    print(f"Starting parallel safe-prime search ({multiprocessing.cpu_count()} workers)…")
    p, q = generate_safe_prime_pair_parallel(BITS)
    print(f"\n→ Found safe prime p (bit-length {p.bit_length()}):\n{p}\n")
    print(f"→ Corresponding q (bit-length {q.bit_length()}):\n{q}")
    
    print(f"\nTime taken: {time.time() - time_start} seconds")