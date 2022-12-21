import node

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]

TIME_OUT = 10


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = node.Node(starting_nodes[0], True)
    west_node.start()

    north_node = node.Node(starting_nodes[1], False)
    north_node.start()

    east_node = node.Node(starting_nodes[2], False)
    east_node.start()

    south_node = node.Node(starting_nodes[3], False)
    south_node.start()

    print("server started")


if __name__ == '__main__':
    start_network()
