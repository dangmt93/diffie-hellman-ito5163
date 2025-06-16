import socket, threading, json, uuid
from enum import Enum
from dataclasses import dataclass
from typing import Any
from datetime import datetime, timezone
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from signature_utils import (
    sign_data,
    verify_signature,
    load_ecdsa_private_key,
    load_ecdsa_public_key,
)

from diffie_hellman import generate_dh_private, compute_dh_public, compute_shared_secret, derive_symmetric_key
from safe_prime_primitive_root import generate_safe_prime_pair_parallel, find_primitive_root_from_safe_prime

@dataclass
class PeerInfo:
    """ 
    Dataclass to store information about a connected peer, after successful DH key exchange. 
    A peer has a hostname, IP address, port, and a derived symmetric key.
    """
    hostname: str       # e.g. "Bob"
    ip:       str       # e.g. "192.168.1.2"
    port:     int       # e.g. 5002
    key:      bytes     # the derived symmetric key

class MsgType(Enum):
    DH_INIT   = "DH_INIT"
    DH_PUBLIC = "DH_PUBLIC"
    DATA      = "DATA"

class User:
    def __init__(
        self,
        listen_port: int,
        hostname: str,
        local_priv_key_path: str,
        public_key_store_path: str
    ) -> None:
        """       
        Initialise a User instance for secure communication using ECDSA and Diffie-Hellman.
        
        This constructor:
        - sets up the user's hostname, ip, public ECDSA key store path, and loads the private ECDSA key
        - prepares Diffie-Hellman and peer state variables
        - sets up a UDP socket for network communication
        - starts a listener thread to handle incoming messages
        
        Args:
            listen_port (int): The local port that this user will listen on for incoming messages.
            hostname (str): The hostname of the user.
            local_priv_key_path (str): Path to the user's private ECDSA key file (PEM format).
            public_key_store_path (str): Path to the file where the users' public ECDSA keys will be stored.

        Returns:
            None
        """
        # Set up hostname, ip, and public key store
        self.hostname: str = hostname
        self.ip: str = self.get_local_ip()
        self.public_key_store_path: str = public_key_store_path
        
        # Load private ECDSA key
        self.ecdsa_priv: ec.EllipticCurvePrivateKey = load_ecdsa_private_key(local_priv_key_path)

        # DH state (filled in during the protocol)
        self.dh_p: int | None = None
        self.dh_g: int | None = None
        self.dh_private: int | None = None
        self.dh_public: int | None = None
        
        # Peer connection states
        self.connected_peers: dict[str, PeerInfo] = {}
        
        # Networking
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", listen_port))
        print(f"[INFO] {hostname} listening on port {listen_port}")

        # Start listener thread
        self.listen()

    def listen(self) -> None:
        """
        Start a background thread to continuously listen for UDP packets from the socket and handle incoming JSON messages.

        When a message is received, it is deserialised and passed to handle_json_message for further processing. 
        If the message cannot be parsed or handled, a warning is logged. 
        The listening thread runs in the background and does not block the main thread.
        """
        def handle_msg() -> None:
            while True:
                data, source_addr = self.sock.recvfrom(8192)
                try:
                    msg: dict = json.loads(data.decode())
                    print(f"\n[RECV from {source_addr}]: {json.dumps(msg, indent=2)}\n")
                    self.handle_json_message(msg, source_addr)
                except Exception as e:
                    print(f"[WARN] Failed to parse/handle message: {e}")

        # Start the message handler in a separate thread
        print("[INFO] Starting message listener thread...")
        threading.Thread(target=handle_msg, daemon=True).start()

    def make_message(self, 
                    dest_hostname: str, msg_type: MsgType, payload: dict[str, Any], attach_signature: bool = True
    ) -> dict:
        """
        Create a new JSON message with the given recipient, message type, and payload.

        The message is structured as a dictionary containing the following fields:
        - message_id: A unique UUID for replay protection.
        - timestamp: A timestamp in ISO-8601 UTC format for freshness.
        - source: The source of the message, in format "hostname".
        - dest: The intended destination of the message, in format "hostname".
        - type: The type of the message (e.g. DH_INIT, DH_PUBLIC, DATA).
        - payload: The payload of the message, represented as a dictionary in JSON format.
        - signature: The ECDSA signature of the message, signed with the user's ECDSA private key 
                        using the canonical serialisation of the message fields. 
                        (Only included if attach_signature is True.)

        Args:
            dest_hostname (str): The hostname of the intended recipient of the message.
            msg_type (MsgType): The type of the message (e.g. DH_INIT, DH_PUBLIC, DATA).
            payload (dict[str, Any]): The payload of the message, represented as a dictionary in JSON format.
            attach_signature (bool, optional): Whether to attach the ECDSA signature to the message. Defaults to True.

        Returns:
            dict: The constructed message dictionary.
        """
        msg_id: str = str(uuid.uuid4())
        timestamp: str = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        msg: dict[str, str | dict[str, Any]] = {
            "message_id":   msg_id,
            "timestamp" :   timestamp,
            "source"    :   self.hostname,
            "dest"      :   dest_hostname,
            "type"      :   msg_type.value,
            "payload"   :   payload,
        }
        
        if not attach_signature:
            return msg
        
        # Canonical serialisation for signing
        canonical_json: bytes = self.canonical_json_for_signing(msg)
        
        # Sign the message with the user's ECDSA private key
        if not self.ecdsa_priv:
            raise ValueError("ECDSA private key not loaded.")
        msg["signature"] = sign_data(self.ecdsa_priv, canonical_json).hex()
        
        return msg

    def send_json(self, dest_ip: str, dest_port: int, msg: dict) -> None:
        """
        Send a JSON message to a specified destination over UDP.

        Args:
            dest_ip (str): The IP address of the destination host.
            dest_port (int): The port number of the destination host.
            msg (dict): The message to be sent, represented as a dictionary in JSON format.

        Returns:
            None
        """
        data: bytes = json.dumps(msg).encode()
        self.sock.sendto(data, (dest_ip, dest_port))
        print(f"[SENT to {dest_ip}:{dest_port}]\n")
        # print(f"{json.dumps(msg, indent=2)}\n") #! For testing

    def init_dh(self, prime_bit_len: int = 512) -> None:
        """
        Initialise the Diffie-Hellman key exchange by generating a safe prime pair and primitive root,
        then sending the DH parameters to a peer.

        This method generates a safe prime pair (p, q) and a primitive root g, constructs a message
        containing these parameters, and sends it to the specified peer.
        """ 
        dest_ip: str = input('Peer host IP: ').strip(); 
        port: int = int(input('Peer port: ').strip())
        
        # Generate safe prime pair and primitive root
        p, q = generate_safe_prime_pair_parallel(prime_bit_len)
        g    = find_primitive_root_from_safe_prime(p, q)
        
        # Store own DH parameters
        self.dh_p, self.dh_g = p, g
        self.dh_private = generate_dh_private(p)
        self.dh_public  = compute_dh_public(p, g, self.dh_private)
        
        # Build message
        payload: dict[str, int] = { "p": p, "g": g, "dh_public": self.dh_public }
        msg: dict[str, str | dict[str, Any]] = self.make_message(dest_ip, MsgType.DH_INIT, payload) # Use IP as temporary dest hostname
        
        # Send message
        self.send_json(dest_ip, port, msg)
        
    def send_encrypted_data(self) -> None:
        """
        Send encrypted data to a connected peer.

        Prompt the user to select a connected peer to send data to, and then ask for plaintext input.
        The plaintext is encrypted using AES-GCM with the shared symmetric key between the user and the peer.
        The IV and ciphertext are sent to the peer as a JSON message with type 'DATA'.
        """
        
        if not self.connected_peers:
            print("[ERROR] No connected peers. Please run `init dh` to connect to a peer first.")
            return
        
        # Peer selection
        print("Select a peer to send data to:")
        peer_list: list[PeerInfo] = list(self.connected_peers.values())
        for i, peer in enumerate(peer_list, start=1):
            print(f"{i}: {peer.hostname} ({peer.ip}:{peer.port})")
        try:
            choice: int = int(input("Enter the number of the peer: ")) - 1
            peer: PeerInfo = peer_list[choice]
        except (IndexError, ValueError):
            print("[ERROR] Invalid choice.")
            return
        
        # Send data with payload {iv, ciphertext} (without signature)
        plaintext: bytes = input('Plaintext: ').encode()
        iv: bytes = secrets.token_bytes(12)
        ciphertext: bytes = AESGCM(peer.key).encrypt(iv, plaintext, None)
        payload: dict[str, str] = {'iv': iv.hex(), 'ciphertext': ciphertext.hex()}
        msg: dict[str, str | dict[str, Any]] = self.make_message(peer.hostname, MsgType.DATA, payload, attach_signature=False)
        self.send_json(peer.ip, peer.port, msg)
        
    def remove_peer(self) -> None:
        """
        Remove a peer from the list of connected peers.

        Prompt the user to select one of the connected peers to remove.
        Note: this (currently) does not send any message to the peer; it simply removes the peer from the local list of connected peers. 
        """
        if not self.connected_peers:
            print("[ERROR] No connected peers. Please run `init dh` to connect to a peer first.")
            return
        
        # Peer selection
        print("Select a peer to end connection with:")
        peer_list: list[PeerInfo] = list(self.connected_peers.values())
        for i, peer in enumerate(peer_list, start=1):
            print(f"{i}: {peer.hostname} ({peer.ip}:{peer.port})")
        try:
            choice: int = int(input("Enter the number of the peer: ")) - 1
            peer: PeerInfo = peer_list[choice]
        except (IndexError, ValueError):
            print("[ERROR] Invalid choice.")
            return
        
        # TODO: Consider sending a DISCONNECT message to politely notify the peer
        
        # (Locally) Remove peer from list of connected peers
        try:
            del self.connected_peers[f"{peer.hostname}@{peer.ip}"]
        except KeyError:
            print("[ERROR] Peer not found in list of connected peers.")
        print(f"[DISCONNECTED from {peer.ip}:{peer.port}]\n")

    def handle_json_message(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        Handle a received JSON message from a peer.

        Depending on the message type, this calls the appropriate handler function.

        Args:
            msg (dict[str, str | dict[str, Any]): The received message, represented as a dictionary in JSON format.
            source_addr (tuple): The address of the source (host, port).

        Returns:
            None
        """
        msg_type: str | None = type_val if isinstance(type_val := msg.get("type"), str) else None
        if not msg_type:
            print("[WARN] Received message without type field.")
            return
        
        if msg_type == MsgType.DH_INIT.value:
            self.handle_dh_init(msg, source_addr)
        elif msg_type == MsgType.DH_PUBLIC.value:
            self.handle_dh_public(msg, source_addr)
        elif msg_type == MsgType.DATA.value:
            self.handle_encrypted_data(msg, source_addr)
        else:
            print(f"[WARN] Unknown message type: {msg_type}")
            
        # print(f"[INFO] Handled message of type {msg_type} from {msg['source']} to {msg['dest']}") #! For testing

    def handle_dh_init(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        Handle a received DH_INIT message to establish Diffie-Hellman parameters.

        Upon receiving a DH_INIT message, this function: 
        - retrieves the peer's ECDSA public key (using the peer's hostname) and verifies the message signature on (p,g,A)
        - stores DH parameters
        - generates the user's own ephemeral DH parameters (b,B)
        - constructs and sends a DH_PUBLIC response message back with the user's DH public (B) to the source address
        - computes DH shared secret (K) and derives/stores the symmetric secret key
        - stores connected peer's address

        Args:
            msg (dict[str, str | dict[str, Any]): The received message containing the DH_INIT parameters.
            source_addr (tuple): The address (IP, port) from which the message was sent.

        Returns:
            None
        """
        # Retrieve peer's ECDSA public key
        peer_hostname: str = str(msg["source"])
        peer_public_key_path: str = f"{self.public_key_store_path}/{peer_hostname.lower()}_pub.pem"
        peer_pub_ecdsa_pub: ec.EllipticCurvePublicKey = load_ecdsa_public_key(peer_public_key_path)
        
        # Verify received signature
        canonical_json: bytes = self.canonical_json_for_signing(msg)
        if not isinstance(signature := msg.get("signature"), str):
            print("[ERROR] Signature missing or not a string.")
            return
        if not verify_signature(peer_pub_ecdsa_pub, canonical_json, bytes.fromhex(signature)):
            print("[ERROR] DH_INIT signature invalid—possible MITM")
            return

        # Accept parameters
        if not isinstance(received_payload := msg.get("payload"), dict):
            print("[ERROR] Payload is not a dictionary.")
            return
        self.dh_p = int(received_payload["p"])
        self.dh_g = int(received_payload["g"])
        print(f"[INFO] Set DH params p={self.dh_p}, g={self.dh_g}")

        # Generate own ephemeral DH parameters
        self.dh_private = generate_dh_private(self.dh_p)
        self.dh_public  = compute_dh_public(self.dh_p, self.dh_g, self.dh_private)

        # Build response message
        res_payload: dict[str, int] = { "dh_public": self.dh_public }
        res_msg: dict[str, str | dict[str, Any]] = self.make_message(peer_hostname, MsgType.DH_PUBLIC, res_payload)

        # Send response message, back to source address
        self.send_json(source_addr[0], source_addr[1], res_msg)
        
        # Compute shared secret and derive symmetric key
        peer_dh_pub: int = int(received_payload["dh_public"])
        if self.dh_p is None or self.dh_private is None:
            print("[ERROR] DH parameters not set.")
            return
        dh_shared_secret = compute_shared_secret(self.dh_p, peer_dh_pub, self.dh_private)
        dh_symmetric_key = derive_symmetric_key(dh_shared_secret)
        print(f"[INFO] Set DH shared secret: {dh_shared_secret}")
        print(f"[INFO] Set DH symmetric key: {dh_symmetric_key}")
        
        # Store connected peer's address
        peer_info: PeerInfo = PeerInfo(peer_hostname, source_addr[0], source_addr[1], dh_symmetric_key)
        self.connected_peers[peer_info.hostname + "@" + peer_info.ip] = peer_info
        print(f"[INFO] Set connected peer info: {peer_hostname}@{source_addr[0]}:{source_addr[1]}\n")

        # Reset DH parameters
        self.dh_p = self.dh_g = self.dh_private = self.dh_public = None

    def handle_dh_public(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        Handle a received DH_PUBLIC message from a peer.

        Upon receiving a DH_PUBLIC message, this function:
        - retrieves the peer's ECDSA public key (using the peer's hostname) and verifies the message signature on (B)
        - computes DH shared secret (K) and derives/stores the symmetric secret key
        - stores connected peer's address

        Args:
            msg (dict[str, str | dict[str, Any]): The received message, represented as a dictionary in JSON format.
            source_addr (tuple): The address of the source (host, port).

        Returns:
            None
        """
        # Retrieve peer's ECDSA public key
        peer_hostname: str = str(msg["source"])
        peer_public_key_path: str = f"{self.public_key_store_path}/{peer_hostname.lower()}_pub.pem"
        peer_pub_ecdsa_pub: ec.EllipticCurvePublicKey = load_ecdsa_public_key(peer_public_key_path)
        
        # Verify received signature
        canonical_json: bytes = self.canonical_json_for_signing(msg)
        if not isinstance(signature := msg.get("signature"), str):
            print("[ERROR] Signature missing or not a string.")
            return
        if not verify_signature(peer_pub_ecdsa_pub, canonical_json, bytes.fromhex(signature)):
            print("[ERROR] DH_PUBLIC signature invalid—possible MITM")
            return
        
        # Compute shared secret and derive symmetric key
        if not isinstance(received_payload := msg.get("payload"), dict):
            print("[ERROR] Payload is not a dictionary.")
            return
        peer_dh_pub: int = int(received_payload["dh_public"])
        if self.dh_p is None or self.dh_private is None:
            print("[ERROR] DH parameters not set.")
            return
        dh_shared_secret = compute_shared_secret(self.dh_p, peer_dh_pub, self.dh_private)
        dh_symmetric_key = derive_symmetric_key(dh_shared_secret)
        print(f"[INFO] Set DH shared secret: {dh_shared_secret}")
        print(f"[INFO] Set DH symmetric key: {dh_symmetric_key}")
        
        # Store connected peer's address
        peer_info: PeerInfo = PeerInfo(peer_hostname, source_addr[0], source_addr[1], dh_symmetric_key)
        self.connected_peers[peer_info.hostname + "@" + peer_info.ip] = peer_info
        print(f"[INFO] Set connected peer info: {peer_hostname}@{source_addr[0]}:{source_addr[1]}\n")
        
        # Reset DH parameters
        self.dh_p = self.dh_g = self.dh_private = self.dh_public = None
        

    def handle_encrypted_data(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        Handle a received encrypted data message.

        Checks if the peer is connected, then decrypts the message using AES-GCM and prints the plaintext.

        Args:
            msg (dict[str, str | dict[str, Any]]): The received message containing the encrypted payload.
            source_addr (tuple[str, int]): The address (IP, port) from which the message was sent.

        Returns:
            None
        """
        peer_hostname: str = str(msg["source"])
        peer_ip: str = source_addr[0]
        
        if (peer := self.connected_peers.get(peer_hostname + "@" + peer_ip)) is None:
            print(f"[ERROR] Peer {peer_hostname}@{peer_ip} not connected. Cannot handle encrypted data.")
            return
        
        # Decrypt ciphertext with AES-GCM
        if not isinstance(payload := msg.get("payload"), dict):
            print("[ERROR] Payload is not a dictionary.")
            return
        # print(f"[INFO] Received encrypted data: {msg['payload']}") #! For testing
        iv: bytes = bytes.fromhex(payload['iv'])
        ciphertext: bytes = bytes.fromhex(payload['ciphertext'])
        plaintext: bytes = AESGCM(peer.key).decrypt(iv, ciphertext, None)
        print(f"[DECRYPTED from {peer_hostname}@{peer_ip}]: {plaintext.decode()}\n")


    def command_loop(self) -> None:
        """Simple CLI to send DH_PARAMS, DATA, or exit."""
        while True:
            cmd = input("\nCommand (init dh / send data / remove peer / exit): ").strip().lower()
            match cmd:
                case "init dh":
                    self.init_dh()
                case "send data":
                    self.send_encrypted_data()
                case "remove peer":
                    self.remove_peer()
                case "exit":
                    print("[INFO] Exiting.")
                    break
                case _:
                    print("Unknown command. Use 'init dh', 'send data', 'remove peer', or 'exit'.")
                    

    # ============================================================================ #
    #                                Static Methods                                #
    # ============================================================================ #
    @staticmethod
    def get_local_ip() -> str:
        """
        Discover the host's primary IP address by creating a temporary UDP socket.
        """
        s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # connect to public DNS server to determine outbound IP
            s.connect(("8.8.8.8", 80))
            ip: str = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1' # Fallback to `localhost` if connection fails
        finally:
            s.close()
        return ip
    
    @staticmethod
    def canonical_json_for_signing(msg: dict[str, str | dict[str, Any]]) -> bytes:
        """
        Convert a message to a canonical JSON form suitable for signing.
        
        This removes the 'signature' field and re-serialises the remaining fields with sorted keys and no extra whitespace.
        The returned byte sequence is to be fed to sign() or verify() call.
        
        Args:
            msg (dict[str, str | dict[str, Any]]): The message to convert.
        
        Returns:
            bytes: The canonical JSON form suitable for signing or verification.
        """
        # Copy all fields except 'signature'
        msg_to_serialise: dict[str, str | dict[str, Any]] = {key: msg[key] for key in msg.keys() if key != "signature"}
        
        # Return canonical JSON dump with sorted keys and no extra whitespace
        canonical_json: bytes = json.dumps(msg_to_serialise, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return canonical_json