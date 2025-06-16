import socket, threading, json, uuid
from enum import Enum
from typing import Any
from datetime import datetime, timezone
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
        self.dh_shared_secret: int | None = None
        
        # Peer connection states
        self.derived_key: bytes | None = None
        self.peer_addr: tuple[str, int] | None = None
        
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
                data, addr = self.sock.recvfrom(8192)
                try:
                    msg: dict = json.loads(data.decode())
                    print(f"\n[RECV from {addr}]: {json.dumps(msg, indent=2)}\n")
                    self.handle_json_message(msg, addr)
                except Exception as e:
                    print(f"[WARN] Failed to parse/handle message: {e}")

        # Start the message handler in a separate thread
        print("[INFO] Starting message listener thread...")
        threading.Thread(target=handle_msg, daemon=True).start()

    def make_message(self, 
                    dest_hostname: str, msg_type: str, payload: dict[str, Any], attach_signature: bool = True
    ) -> dict:
        """
        Create a new JSON message with the given recipient, message type, and payload.

        The message is structured as a dictionary containing the following fields:
        - message_id: A unique UUID for replay protection.
        - timestamp: A timestamp in ISO-8601 UTC format for freshness.
        - source: The source of the message, in format "hostname".
        - dest: The intended destination of the message, in format "hostname".
        - type: The type of the message (e.g. DH_INIT, DH_REPLY, DATA).
        - payload: The payload of the message, represented as a dictionary in JSON format.
        - signature: The ECDSA signature of the message, signed with the user's ECDSA private key 
                        using the canonical serialisation of the message fields. 
                        (Only included if attach_signature is True.)

        Args:
            recipient_identity (str): The identity of the recipient.
            recipient_ip (str): The IP address of the recipient.
            msg_type (str): The type of the message (e.g. DH_PARAMS, DH_PUBLIC, DATA).
            payload (dict): The payload of the message, represented as a dictionary in JSON format.
            attach_signature (bool): Whether to attach a signature to the message. Defaults to True.

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
            "type"      :   msg_type,
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
        payload: dict[str, int] = { "p": p, "g": g, "A": self.dh_public }
        msg: dict[str, str | dict[str, Any]] = self.make_message("_", "DH_INIT", payload) # unknown dest hostname for now
        
        # Send message
        self.send_json(dest_ip, port, msg)
        

    def handle_json_message(self, msg: dict[str, str | dict[str, Any]], addr: tuple[str, int]) -> None:
        """
        Handle a received JSON message from a peer.

        Depending on the message type, this calls the appropriate handler function.

        Args:
            msg (dict): The received message, represented as a dictionary in JSON format.
            addr (tuple): The address of the source (host, port).

        Returns:
            None
        """
        msg_type: str | None = type_val if isinstance(type_val := msg.get("type"), str) else None
        if not msg_type:
            print("[WARN] Received message without type field.")
            return
        
        if msg_type == MsgType.DH_INIT.value:
            self.handle_dh_init(msg, addr)
        elif msg_type == MsgType.DH_PUBLIC.value:
            self.handle_dh_public(msg, addr)
        elif msg_type == MsgType.DATA.value:
            self.handle_data(msg)
        else:
            print(f"[WARN] Unknown message type: {msg_type}")
            
        # print(f"[INFO] Handled message of type {msg_type} from {msg['source']} to {msg['dest']}") #! For testing

    def handle_dh_init(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        Handle an incoming DH_INIT message to establish Diffie-Hellman parameters.

        Upon receiving a DH_INIT message, this function: 
        - retrieves the peer's ECDSA public key (using the peer's hostname) and verifies the message signature on (p,g,A)
        - stores DH parameters
        - generates the user's own ephemeral DH parameters (b,B)
        - constructs and sends a DH_PUBLIC response message back with the user's DH public (B) to the source address
        - computes DH shared secret (K) and derives/stores the symmetric secret key

        Args:
            msg (dict): The received message containing the DH_INIT parameters.
            source_addr (tuple): The address (IP, port) from which the message was received.

        Returns:
            None
        """
        # Retrieve peer's ECDSA public key
        peer_hostname = str(msg["source"])
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
        if not isinstance(payload := msg.get("payload"), dict):
            print("[ERROR] Payload is not a dictionary.")
            return
        self.dh_p = int(payload["p"])
        self.dh_g = int(payload["g"])
        print(f"[INFO] Set DH params p={self.dh_p}, g={self.dh_g}")

        # Generate own ephemeral DH parameters
        self.dh_private = generate_dh_private(self.dh_p)
        self.dh_public  = compute_dh_public(self.dh_p, self.dh_g, self.dh_private)

        # Build response message
        res_payload: dict[str, int] = { "B": self.dh_public }
        res_msg: dict[str, str | dict[str, Any]] = self.make_message(peer_hostname, "DH_PUBLIC", res_payload)

        # Send response message, back to source address
        self.send_json(source_addr[0], source_addr[1], res_msg)
        
        # Compute shared secret and derive symmetric key
        peer_dh_pub = int(payload["A"])
        self.dh_shared_secret = compute_shared_secret(self.dh_p, peer_dh_pub, self.dh_private)
        self.dh_symmetric_key = derive_symmetric_key(self.dh_shared_secret)
        print(f"[INFO] Set DH shared secret: {self.dh_shared_secret}")
        print(f"[INFO] Set DH symmetric key: {self.dh_symmetric_key}")
        
        # Store connected peer's address
        self.peer_addr = source_addr
        print(f"[INFO] Set peer address: {self.peer_addr}\n")


    def handle_dh_public(self, msg: dict[str, str | dict[str, Any]], source_addr: tuple[str, int]) -> None:
        """
        1. Verify signature on B (or A)
        2. Compute shared secret and derive symmetric key
        """
        pass
        # sender    = msg["sender"]
        # recipient = msg["recipient"]
        # payload   = msg["payload"]
        # sign_input = (
        #     f"{msg['message_id']}|{msg['timestamp']}|{sender}|"
        #     f"{recipient}|DH_PUBLIC|{json.dumps(payload, sort_keys=True)}"
        # ).encode()
        # if not verify_signature(self.peer_ecdsa_pub, sign_input, bytes.fromhex(msg["signature"])):
        #     print("[ERROR] DH_PUBLIC signature invalid—possible MITM")
        #     return

        # peer_pub = int(payload["dh_public"])
        # print(f"[INFO] Received peer DH public: {peer_pub}")

        # # Compute shared secret
        # self.dh_shared_secret = compute_shared_secret(self.dh_p, peer_pub, self.dh_private)
        # # Derive a 256-bit key via SHA-256
        # self.derived_key = hashlib.sha256(str(self.dh_shared_secret).encode()).digest()
        # print(f"[INFO] Shared secret computed and key derived.")

    def send_encrypted_data(self) -> None:
        if not self.derived_key:
            print('[ERROR] No shared key—run initdh first')
            return
        # host = input('Peer host: ').strip(); port = int(input('Peer port: ').strip())
        # recipient = input('Recipient identity: ').strip()
        # pt = input('Plaintext: ').encode()
        # iv = secrets.token_bytes(12)
        # ct = AESGCM(self.derived_key).encrypt(iv, pt, None)
        # payload = {'iv': iv.hex(), 'ciphertext': ct.hex()}
        # msg = self.make_message(recipient, 'DATA', payload)
        # self.send_json(host, port, msg)

    def end_dh(self) -> None:
        self.p = self.g = self.dh_private = self.dh_public = None
        self.shared_secret = self.derived_key = None
        print('[INFO] DH state reset.')

    def handle_data(self, msg: dict) -> None:
        """
        1. Verify signature
        2. Decrypt ciphertext with AES-GCM
        """
        pass
        # sender    = msg["sender"]
        # recipient = msg["recipient"]
        # payload   = msg["payload"]
        # sign_input = (
        #     f"{msg['message_id']}|{msg['timestamp']}|{sender}|"
        #     f"{recipient}|DATA|{json.dumps(payload, sort_keys=True)}"
        # ).encode()
        # if not verify_signature(self.peer_ecdsa_pub, sign_input, bytes.fromhex(msg["signature"])):
        #     print("[ERROR] DATA signature invalid—possible MITM")
        #     return

        # iv  = bytes.fromhex(payload["iv"])
        # ct  = bytes.fromhex(payload["ciphertext"])
        # aes = AESGCM(self.derived_key)
        # pt  = aes.decrypt(iv, ct, None)
        # print(f"[DECRYPTED from {sender}]: {pt.decode()}")



    def command_loop(self) -> None:
        """Simple CLI to send DH_PARAMS, DATA, or exit."""
        while True:
            cmd = input("\nCommand (initdh / senddata / enddh / exit): ").strip().lower()
            match cmd:
                case "initdh":
                    self.init_dh()
                case "senddata":
                    self.send_encrypted_data()
                case "enddh":
                    self.end_dh()
                case "exit":
                    print("[INFO] Exiting.")
                    break
                case _:
                    print("Unknown command. Use initdh / senddata / enddh / exit.")
                    

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