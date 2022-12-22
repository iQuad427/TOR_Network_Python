import time

from auth_node import AuthenticationNode


if __name__ == '__main__':
    auth_node = AuthenticationNode(("127.0.0.5", 4500), False)
    auth_node.start()
    auth_node.sign_up("Quentin", "azerty")
    auth_node.sign_in("Quentin", "azerty")

    # malicious = AuthenticationNode(("127.0.0.6", 4500), False)
    # malicious.start()
    # malicious.disconnect("Quentin")
    # malicious.stop()

    auth_node.sign_in("Quentin", "azerty")
    auth_node.disconnect("Quentin")

    auth_node.stop()
