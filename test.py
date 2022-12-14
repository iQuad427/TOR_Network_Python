import client

starting_nodes = [("127.0.0.1", 4001), ("127.0.0.1", 4002), ("127.0.0.1", 4003), ("127.0.0.1", 4004)]


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    node0 = client.Node(("127.0.0.1", 4503))
    node0.init_node_as_relay()

    node0 = client.Node(("127.0.0.1", 4504))
    node0.init_node_as_relay()

    node0 = client.Node(("127.0.0.1", 4505))
    node0.init_node_as_relay()

    node0 = client.Node(("127.0.0.1", 4506))
    node0.init_node_as_relay()

    west_node = client.Node(starting_nodes[0])
    west_node.init_node_as_relay()

    north_node = client.Node(starting_nodes[1])
    north_node.init_node_as_relay()

    east_node = client.Node(starting_nodes[2])
    east_node.init_node_as_relay()

    south_node = client.Node(starting_nodes[3])
    south_node.init_node_as_relay()


if __name__ == '__main__':
    start_network()

    node = client.Node(("127.0.0.1", 4005))
    node.phonebook[("127.0.0.1", 4503)] = ["new node", False]
    node.phonebook[("127.0.0.1", 4504)] = ["new node", False]
    node.phonebook[("127.0.0.1", 4505)] = ["new node", False]
    node.phonebook[("127.0.0.1", 4506)] = ["new node", False]
    node.init_node_as_relay()

    node1 = client.Node(("127.0.0.1", 4006))
    # node1.init_node_as_relay()
    node1.phonebook[("127.0.0.1", 4005)] = ["known node from before", False]

    node1.update_phonebook(("127.0.0.1", 4005))
    node1.complete_entries_key(starting_nodes)
    # node1.define_path()

    print(node1.phonebook)
