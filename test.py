import client

tor_network_address = ("127.0.0.1", 4000)


if __name__ == '__main__':
    node = client.Node(("127.0.0.1", 4001), tor_network_address)
    node.init_node_as_relay()