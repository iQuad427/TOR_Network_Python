import pickle
import random
import socket
import ipaddress
import sys
import threading

import rsa


starting_phonebook = {
    ("127.0.0.1", 4000): ("tor_server", False),
    ("127.0.0.1", 4001): ("west_node", False),
    ("127.0.0.1", 4002): ("north_node", False),
    ("127.0.0.1", 4003): ("east_node", False),
    ("127.0.0.1", 4004): ("south_node", False),
}


class Node:
    def __init__(self, own_address, server_address):
        self.tor_host = server_address[0]
        self.tor_port = server_address[1]
        self.my_address = own_address[0]
        self.my_port = own_address[1]
        self.phonebook = starting_phonebook
        self.path = []
        self.public_key = 0
        self.private_key = 0

    def init_keys(self):
        # TODO : Check if keys are already set, else do whatever bro, idk
        (self.public_key, self.private_key) = rsa.newkeys(1024)

    def update_phonebook(self, address):
        if address not in self.phonebook:
            raise PermissionError("Node not in phonebook")

        print(f"Previous phonebook : {self.phonebook}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.my_address, self.my_port))
            sock.connect((address[0], address[1]))

            sock.send(pickle.dumps("phonebook"))
            new_phonebook = sock.recv(2048)
            new_phonebook = pickle.loads(new_phonebook)

            for entry in new_phonebook:
                # add new address only if it was not already in our phonebook,
                # no modification of the previous addresses
                if entry not in self.phonebook:
                    self.phonebook[entry] = new_phonebook[entry]

            print(f"New phonebook : {self.phonebook}")

    def reset_phonebook(self):
        self.phonebook = starting_phonebook

    def define_path(self):
        list_of_node = [self.phonebook[entry] for entry in self.phonebook]
        random.shuffle(list_of_node)
        while len(list_of_node) > 3:
            index = random.randrange(0, len(list_of_node), 1)
            list_of_node.pop(index)

        self.path = list_of_node

    def send_encrypted_packet(self):
        """
        Add the path composed of IP addresses of at least 3 nodes and encrypt them with
        the corresponding public keys and sends it to the first node.
        :return:
        """

    def encrypt_public_packet(self, packet, keys_list):  # Probablement la même fonction qu'en dessous
        """
        Encrypts packet with the public keys of the nodes contained in the list
        :return:
        """

    def decrypt_public_packet(self, packet, keys_list):
        """
        Decrypts received packet with the public keys of the nodes contained in the list
        :return:
        """

    def decrypt_private_packet(self, packet):  # Probablement la même fonction qu'en dessous
        """
        Decrypts received packet with the private key
        :return:
        """

    def encrypt_private_packet(self):
        """
        Encrypts packet with the private key
        :return:
        """

    def forward_packet(self, packet, ip_address):
        """
        Send the packet to the corresponding IP address
        :return:
        """

    def connect_to_network(self):
        """
        Request a subset of IP addresses to a node already in the network
        :return:
        """

    def start_listener(self):
        listener = threading.Thread(target=self.listener)
        listener.start()

    def listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.my_address, self.my_port))
            sock.listen()
            while True:
                connection, address = sock.accept()
                with connection:
                    message = connection.recv(2048)
                    message = pickle.loads(message)
                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook))
                    elif type(message) is rsa.PublicKey:
                        msg_to_node = pickle.dumps(self.phonebook)
                        connection.send(msg_to_node)
                        node_address = (address[0], address[1], message, False)
                        self.phonebook[(address[0], address[1])] = (message, False)
                        print(self.phonebook)

    def init_node_as_relay(self):
        """
        Handshake between node and TOR server to decide on the relay IP address

        :return:
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.my_address, self.my_port+1))
            sock.connect((self.tor_host, self.tor_port))
            self.init_keys()
            key = pickle.dumps(self.public_key)
            message = key
            sock.send(message)
            addresses = sock.recv(2048)
            addresses = pickle.loads(addresses)
            print(f"Received address : {addresses}")

            self.list_addresses = addresses
