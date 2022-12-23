from auth_node import AuthenticationNode

PORT = 60000


if __name__ == '__main__':
    auth_node = AuthenticationNode(("127.0.0.5", PORT), False)
    print("Starting the node")
    auth_node.start()
    print("Signing up")
    auth_node.sign_up("Quentin", "azerty")
    print("Logging in")
    auth_node.sign_in("Quentin", "azerty")

    print("Malicious attack")
    malicious = AuthenticationNode(("127.0.0.6", PORT), False)
    malicious.start()
    malicious.disconnect("Quentin")
    malicious.stop()

    print("Logging in bis")
    auth_node.sign_in("Quentin", "azerty")
    print("Disconnecting")
    auth_node.disconnect("Quentin")

    print("User start its second computer")
    second_node = AuthenticationNode(("127.0.0.5", PORT + 1000), False)
    second_node.start()

    print("Previous computer still logged in")
    auth_node.sign_in("Quentin", "azerty")
    print("Log in with new computer")
    second_node.sign_in("Quentin", "azerty")

    print("Outdated session try to disconnect, should fail")
    auth_node.disconnect("Quentin")

    auth_node.stop()
    second_node.stop()
