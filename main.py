import time

import rsa
import socket
import client

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = client.Node(starting_nodes[0], True)
    west_node.start()

    east_node = client.Node(starting_nodes[2], False)
    east_node.start()

    south_node = client.Node(starting_nodes[3], False)
    south_node.start()

    north_node = client.Node(starting_nodes[1], False)
    north_node.start()


if __name__ == '__main__':
    # start_network()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.bind(("127.0.0.1", 4000))
    sock.connect(("127.0.0.1", 5000))
    time = time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime())
    sock.send(f"Return : {time}".encode())
