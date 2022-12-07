import socket
import ipaddress
import sys

TOR_host = "127.0.0.1"
TOR_port = 4000


def init_node_as_relay():
    """
    Handshake between node and TOR server to decide on the relay IP address

    :return:
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 6420))
        sock.connect((TOR_host, TOR_port))
        message = "Bonjour".encode()
        sock.send(message)
        address = sock.recv(1024)
        address = address.decode()
        print(f"Received address : {address}")

        return address


if __name__ == '__main__':
    ip_address = init_node_as_relay()


