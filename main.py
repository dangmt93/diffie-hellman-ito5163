import sys

from user import User

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python main.py <listen_port> <hostname> <local_priv.pem> <public_key_store_path>")
        sys.exit(1)

    port, hostname, priv_key_path, public_key_store_path = sys.argv[1:]
    user = User(int(port), hostname, priv_key_path, public_key_store_path)
    user.command_loop()