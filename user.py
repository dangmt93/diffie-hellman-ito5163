import socket
import threading
import json
import sys

def listen_for_messages(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        # print(f'\n[Message from {addr}]: {data.decode()}')
        try:
            message = json.loads(data.decode())
            print(f'\n[JSON Message from {addr}]: {json.dumps(message, indent=2)}')
            print(f"signature: {message.get('signature')}")
        except json.JSONDecodeError:
            print(f'\n[Message from {addr}]: {data.decode()}')

def main():
    local_host = '0.0.0.0'
    # local_port = int(input("Enter your listening port: "))
    local_port = int(sys.argv[1])

    # remote_host = input("Enter remote host IP: ")
    # remote_port = int(input("Enter remote host port: "))
    remote_host = sys.argv[2]
    remote_port = int(sys.argv[3])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local_host, local_port))

    threading.Thread(target=listen_for_messages, args=(sock,), daemon=True).start()

    while True:
        # message = input('Enter message: ')
        command = input('Enter command (sendjson / sendtext): ').strip()
        if command == 'sendjson':
            message = {
                "sender": "UserA",
                "receiver": "UserB",
                "prime_p": "<large_prime>",
                "primitive_root_g": "<primitive_root>",
                "public_key": "<public_key>",
                "signature": "<digital_signature>"
            }

            sock.sendto(json.dumps(message).encode(), (remote_host, remote_port))

        elif command == 'sendtext':
            message = input('Enter message: ')
            sock.sendto(message.encode(), (remote_host, remote_port))
        else:
            print("Invalid command! Use 'sendjson' or 'sendtext'.")


if __name__ == '__main__':
    main()