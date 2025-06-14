import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes, PrivateKeyTypes
from cryptography.exceptions import UnsupportedAlgorithm

class KeyLoadingError(Exception):
    """
    Exception raised when loading an ECDSA key fails.
    """
    pass

def setup_ecdsa_keypair(identity: str, priv_path: str, pub_path: str) -> None:
    
    """
    Generate a pair of ECDSA keypair and save them to files as PEM-serialised bytes.

    The private key is saved to `priv_path` in PKCS#8 format with no encryption.
    The public key is derived from the private key and saved to `pub_path` in
    SubjectPublicKeyInfo format.

    Args:
        identity (str): Identifier for the key owner (for logging).
        priv_path (str): Path to write the private key PEM (chmod 600).
        pub_path (str): Path to write the public key PEM (chmod 644).
    
    Returns:
        None
    """
    # Generate, serialise private key, and save to file
    private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
    priv_bytes: bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(priv_path, 'wb') as f:
        f.write(priv_bytes)
    os.chmod(priv_path, 0o600)  # Set permissions to 600 (read/write for owner only)
        
    # Generate, serialise public key and save to file
    #? Note: Public key is derived from private key, so no need to generate it separately
    public_key: ec.EllipticCurvePublicKey = private_key.public_key()
    pub_bytes: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(pub_path, 'wb') as f:
        f.write(pub_bytes)
    os.chmod(pub_path, 0o644)  # Set permissions to 644 (read for all, write for owner only)
    #? Note: In real scenarios, public keys are available and accessible from a public directory or key authority
    
    print(f"[INFO] {identity} ECDSA keys generated: {priv_path}, {pub_path}")


def sign_data(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Sign the given data using the provided private key.

    Args:
        private_key (ec.EllipticCurvePrivateKey): The private key to use for signing.
        data (bytes): The data to sign.

    Returns:
        bytes: The ECDSA signature of the data.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def verify_signature(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify the ECDSA signature of the given data using the provided public key.

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key to use for verification.
        data (bytes): The data that was signed.
        signature (bytes): The ECDSA signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """

    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def load_ecdsa_private_key(priv_path: str) -> ec.EllipticCurvePrivateKey:
    """
    Load an ECDSA private key from a PEM file (PKCS#8, unencrypted).

    Args:
        priv_path (str): Path to the private key PEM file.

    Returns:
        An instance of EllipticCurvePrivateKey for ECDSA. 
            The type depends on the specific key algorithm used.

    Raises:
        KeyLoadingError: If the file can't be read or isn't a valid private key.
    """
    try:
        with open(priv_path, "rb") as f:
            key_data: bytes = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise KeyLoadingError(f"Cannot find or open private key file '{priv_path}': {e}")

    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=None,
        )
    except (ValueError, UnsupportedAlgorithm) as e:
        raise KeyLoadingError(f"Invalid private key in '{priv_path}': {e}")

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise KeyLoadingError(f"Loaded key is not an EllipticCurvePrivateKey in '{priv_path}'")

    return private_key


def load_ecdsa_public_key(pub_path: str) -> ec.EllipticCurvePublicKey:
    """
    Load an ECDSA public key from a PEM file (SubjectPublicKeyInfo).

    Args:
        pub_path (str): Path to the public key PEM file.

    Returns:
        An instance of EllipticCurvePublicKey for ECDSA. 
            The type depends on the specific key algorithm used.

    Raises:
        KeyLoadingError: If the file can't be read or isn't a valid public key.
    """
    try:
        with open(pub_path, "rb") as f:
            key_data: bytes = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise KeyLoadingError(f"Cannot find or open public key file '{pub_path}': {e}")

    try:
        public_key: PublicKeyTypes = serialization.load_pem_public_key(
            key_data,
        )
    except (ValueError, UnsupportedAlgorithm) as e:
        raise KeyLoadingError(f"Invalid public key in '{pub_path}': {e}")

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise KeyLoadingError(f"Loaded key is not an EllipticCurvePublicKey in '{pub_path}'")
    
    return public_key


if __name__ == "__main__":
    # priv_key, pub_key = generate_keypair()
    name = "bob"
    priv_key = load_ecdsa_private_key(f"{name}_priv.pem")
    pub_key = load_ecdsa_public_key(f"{name}_pub.pem")
    
    data = b"Hello, world!"
    
    signature = sign_data(priv_key, data)
    print("Signature:", signature.hex())
    
    is_valid = verify_signature(pub_key, data, signature)
    print("Signature valid:", is_valid)
    
    # serialised_pub = serialize_public_key(pub_key)
    # print("Serialised Public Key:", serialised_pub.decode())
    
    # loaded_pub = load_public_key(serialised_pub)
    # print("Loaded Public Key:", loaded_pub)  # Should match original pub_key
    