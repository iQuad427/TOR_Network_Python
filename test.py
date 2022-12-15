import client
import message_tool

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]


def start_network():
    """
    Deploy the four kernel nodes of the TOR network
    """
    west_node = client.Node(starting_nodes[0])
    west_node.init_node_as_relay()

    north_node = client.Node(starting_nodes[1])
    north_node.init_node_as_relay()

    east_node = client.Node(starting_nodes[2])
    east_node.init_node_as_relay()

    south_node = client.Node(starting_nodes[3])
    south_node.init_node_as_relay()


def test_phonebook():
    client.Node(("127.0.0.5", 4000)).init_node_as_relay()
    client.Node(("127.0.0.5", 4010)).init_node_as_relay()
    client.Node(("127.0.0.5", 4020)).init_node_as_relay()
    client.Node(("127.0.0.5", 4030)).init_node_as_relay()

    node0 = client.Node(("127.0.0.5", 4040))
    node0.phonebook[("127.0.0.5", 4000)] = ["new node", False]
    node0.phonebook[("127.0.0.5", 4010)] = ["new node", False]
    node0.phonebook[("127.0.0.5", 4020)] = ["new node", False]
    node0.phonebook[("127.0.0.5", 4030)] = ["new node", False]
    node0.init_node_as_relay()

    node1 = client.Node(("127.0.0.5", 4050))
    node1.init_node_as_relay()
    node1.phonebook[("127.0.0.5", 4040)] = ["known node from before", False]

    node1.update_phonebook(("127.0.0.5", 4040))
    node1.complete_entries_key(starting_nodes)
    print(node1.phonebook)


if __name__ == '__main__':
    start_network()
    # test_phonebook()

    node = client.Node(("127.0.0.5", 4000))
    node.send("oui")
