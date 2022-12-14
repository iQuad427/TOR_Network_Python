import rsa
import socket
import client

tor_network_address = ("127.0.0.1", 4000)


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = client.Node("127.0.0.1", 4001, tor_network_address)
    west_node.init_node_as_relay()

    north_node = client.Node("127.0.0.1", 4002, tor_network_address)
    north_node.init_node_as_relay()

    east_node = client.Node("127.0.0.1", 4003, tor_network_address)
    east_node.init_node_as_relay()

    south_node = client.Node("127.0.0.1", 4004, tor_network_address)
    south_node.init_node_as_relay()


if __name__ == '__main__':
    start_network()
