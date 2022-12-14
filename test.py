import client

tor_network_address = ("127.0.0.1", 4000)


if __name__ == '__main__':
    node0 = client.Node(("127.0.0.1", 4005), tor_network_address)
    # node.init_node_as_relay()
    node0.phonebook[("127.0.0.1", 5420)] = ("new node added", False)
    node0.phonebook[("127.0.0.1", 4001)] = ("suppressed node", False)
    node0.phonebook[("127.0.0.1", 5420)] = ("new node added", False)
    node0.listen()
