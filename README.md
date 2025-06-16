# Diffie-Hellman Implementation


## Prerequisites
- Python 3.10 or newer  
- (Optional) [Poetry](https://python-poetry.org/) for dependency management  
  - Install dependencies with Poetry: `poetry install`

## How to run code

### Generating ECDSA Keys
- You need a long-term ECDSA key pair for each user. Either:
  - Use setup_ecdsa_keypair() function in signature_utils

### Setup
**Prepare each system** (host and VM):
   - The user’s respective **private ECDSA key** (e.g. `alice_priv.pem` in Alice's system)
   - A **public key store directory** containing both parties’ public keys (e.g. `key_store/`). You can either use shared folder between systems, or separate folders containing both public keys.
   - The **Diffie–Hellman project folder** (with `user.py`, helper modules, etc.)


### Running the Demo
From inside the project directory, run:
```bash
python3 main.py <listen_port> <hostname> <path_to_your_private_key> <path_to_public_key_store>
```
where:
- <listen_port>: UDP port to bind (e.g. 5000)
- <hostname>: Logical hostname matching your key filenames (e.g. Alice)
- <path_to_your_private_key>: Path to your private PEM (e.g. ./alice_priv.pem)
- <path_to_public_key_store>: Path to the directory holding **both** public keys

Note: Make sure relative paths are correct.

For example:
```bash
python3 main.py 5000 Alice ../ALice/alice_priv.pem "C:\Users\username\VirtualBox VMs\Shared" 

```

Within each user session, you can use the following commands:
- **init dh** – begin a new Diffie–Hellman handshake (prompts for peer IP, port)
- **send data** – encrypt and send a message to a connected peer
- **remove peer** – drop a connected peer and clear its session state
- **exit** – quit the program


## Known limitations
- Initiator must know the peer’s UDP port ahead of time.
- Assumes ECDSA public keys are pre-shared in key_store/ with filenames matching the lowercase hostname (e.g., alice_pub.pem, bob_pub.pem).