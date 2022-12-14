import rsa
import socket
import client

tor_network_address = ("127.0.0.1", 4000)
starting_nodes = [("127.0.0.1", 4001), ("127.0.0.1", 4002), ("127.0.0.1", 4003), ("127.0.0.1", 4004)]


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = client.Node(starting_nodes[0], tor_network_address)
    west_node.start_listener()
    print("lol")
    west_node.init_node_as_relay()

    # north_node = client.Node(starting_nodes[1], starting_nodes[0])
    # north_node.init_node_as_relay()
    #
    # east_node = client.Node(starting_nodes[2], tor_network_address)
    # east_node.init_node_as_relay()
    #
    # south_node = client.Node(starting_nodes[3], tor_network_address)
    # south_node.init_node_as_relay()


if __name__ == '__main__':
    start_network()
