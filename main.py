import rsa
import socket
import client

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = client.Node(starting_nodes[0])
    west_node.init_node_as_relay()

    east_node = client.Node(starting_nodes[2])
    east_node.init_node_as_relay()

    south_node = client.Node(starting_nodes[3])
    south_node.init_node_as_relay()

    north_node = client.Node(starting_nodes[1])
    north_node.init_node_as_relay()
    north_node.init_phonebook_public_keys()
    north_node.send_encrypted_packet(
        "We assume that the packet already contains the IP address of the receiver outside the network"
        + "Encrypts packet with the public keys of the nodes contained in the list")


if __name__ == '__main__':
    start_network()
