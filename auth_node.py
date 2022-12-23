import rsa
from Crypto.Cipher import AES
import pickle
import tools
import node

# List of starting nodes
starting_nodes = [("127.0.0.1", 4000), ("127.0.0.2", 4000), ("127.0.0.3", 4000), ("127.0.0.4", 4000)]
# Address of the authentication server
authentication_server = ("127.0.0.5", 10000)

# Timeout for receiving messages
TIME_OUT = 5


class AuthenticationNode(node.Node):
    def __init__(self, address, is_exit_node):
        """
        Initializes an instance of the AuthenticationNode class which inherits Node class
        :param address: The IP address and port of the node.
        :param is_exit_node: Indicating whether the node is an exit node.
        """
        node.Node.__init__(self, address, is_exit_node)
        self.server_public_key = None
        self.client_public_key, self.client_private_key = rsa.newkeys(1024)

    def start(self):
        """
        Starts the node and retrieves the server's public key.
        """
        node.Node.start(self)
        while self.server_public_key is None:
            self.server_public_key = self.ask_for_server_public_key()

    def ask_for_server_public_key(self):
        """
        Requests the server's public key
        :return: The server's public key, if it was received successfully. Otherwise, returns None.
        """
        formatted = tools.format_message("random", "public_key", "void")
        self.send(tools.format_send_to(authentication_server, formatted))
        response = self.recv(TIME_OUT)

        if response is None:
            return None

        _, _, response, _, _ = tools.parsing(response)

        return response

    def sign_up(self, username, password):
        """
        Attempts to sign up the user with the given username and password.
        :param username: Username of the user.
        :param password: Password of the user.
        """
        password_hash = tools.hash_password(password)
        formatted = tools.format_message(username, "sign_up", password_hash, encoding=0)
        # Send the hashed password the authentication server
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(TIME_OUT)

        if server_response is None:
            return

        user, request, content, tag, _ = tools.parsing(server_response)

        if request == "log":
            print(content)

    def sign_in(self, username, password):
        """
        Attempts to sign in the user with the given username and password.
        :param username: Username of the user.
        :param password: Password of the user.
        :return:
        """

        formatted = tools.format_message(username, "sign_in", self.client_public_key, encoding=2)
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        message = self.recv(TIME_OUT)

        if message is None:
            return

        user, request, challenge, _, _ = tools.parsing(message)

        if request != "challenge":
            return

        password_hash = tools.hash_password(password)
        # Encrypt the challenge using AES256 and hashed password as key
        cipher = AES.new(password_hash, AES.MODE_CTR, nonce=b'1')
        actual = cipher.encrypt(challenge.encode('utf-8'))

        formatted = tools.format_message(username, "challenge", actual, encoding=0)
        # Send the encrypted challenge to the authentication server
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(TIME_OUT)
        server_response = tools.decrypt(server_response, self.client_private_key)

        if server_response is None:
            return

        user, query, content, _, _ = tools.parsing(server_response)

        if query == "log":
            print(content)

    def disconnect(self, username):
        """
        Disconnects the user with the given username.
        :param username: Username of the user.
        """
        formatted = tools.format_message(username, "disconnect", "void", private_key=self.client_private_key, encoding=2)
        self.send(tools.format_send_to(authentication_server, tools.encrypt(formatted, self.server_public_key)))

        server_response = self.recv(2048)

        user, query, content, _, _ = tools.parsing(server_response)

        if query == "log":
            print(content)
