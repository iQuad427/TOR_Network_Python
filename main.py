from Crypto.Cipher import AES
import pickle
import tools
import node

starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]
authentication_server = ("127.0.0.5", 10000)

TIME_OUT = 10


class AuthenticationNode(node.Node):
    def __init__(self, address, is_exit_node):
        node.Node.__init__(self, address, is_exit_node)
        self.server_public_key = 0

    def start(self):
        node.Node.start(self)
        self.server_public_key = self.ask_for_server_public_key()
        print("server public_key :", self.server_public_key)

    def ask_for_server_public_key(self):
        print("request public key")
        formatted = tools.format_message("random", "public_key", "void")
        self.send(tools.format_send_to(authentication_server, formatted))
        response = self.recv(TIME_OUT)

        return pickle.loads(response) if response is not None else None

    def sign_up(self, username, password):
        print("sign up")

        password_hash = tools.hash_password_to_aes_key(password)
        formatted = tools.format_message(username, "sign_up", password_hash, to_decode=False)
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(TIME_OUT)
        print(server_response)

        if server_response is None:
            print("failed")
            return

        user, request, content = tools.parsing(server_response)

        if request == "log":
            print("Sign up status :", content)

    def sign_in(self, username, password):
        print("sign in")

        formatted = tools.format_message(username, "sign_in", "void")
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        message = self.recv(TIME_OUT)

        if message is None:
            print("failed")
            return

        user, request, challenge = tools.parsing(message)

        if request != "challenge":
            print("Sign in failed")
            return

        print("responding to challenge")

        password_hash = tools.hash_password_to_aes_key(password)
        cipher = AES.new(password_hash, AES.MODE_CTR, nonce=b'1')
        actual = cipher.encrypt(challenge.encode('utf-8'))

        formatted = tools.format_message(username, "challenge", actual, to_decode=False)
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(TIME_OUT)
        print(server_response)

        if server_response is None:
            print("failed")
            return

        user, query, content = tools.parsing(server_response)

        if query == "log":
            print("Sign in status :", content)

    def disconnect(self, username):
        print("disconnecting")

        formatted = tools.format_message(username, "disconnect", "void")
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(2048)

        user, query, content = tools.parsing(server_response)

        if query == "log":
            print("Connection status :", content)


if __name__ == '__main__':
    auth_node = AuthenticationNode(("127.0.0.5", 4000), False)
    auth_node.start()
    auth_node.sign_up("Quentin", "azerty")
    auth_node.sign_in("Quentin", "azerty")
    auth_node.disconnect("Quentin")
