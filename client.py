import copy
import pickle
import random
import socket
import ipaddress
import sys
import threading
import rsa

PATH_LENGTH = 3

starting_phonebook = {
    ("127.0.0.1", 4001): ["west_node", False],
    ("127.0.0.1", 4002): ["north_node", False],
    ("127.0.0.1", 4003): ["east_node", False],
    ("127.0.0.1", 4004): ["south_node", False],
}


def exchange_key(address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(address)

            sock.send(pickle.dumps("public_key"))
            new_public_key = sock.recv(2048)
            new_public_key = pickle.loads(new_public_key)
    except socket.error:
        return 1

    return new_public_key


class Node:
    def __init__(self, own_address):
        self.public_key = 0
        self.private_key = 0
        self.init_keys()
        self.address = (own_address[0], own_address[1])
        self.phonebook = copy.deepcopy(starting_phonebook)
        self.path = []

    def init_keys(self):
        # TODO : Check if keys are already set, else do whatever bro, idk
        (self.public_key, self.private_key) = rsa.newkeys(1024)

    def reset_phonebook(self):
        self.phonebook = starting_phonebook

    def update_phonebook(self, address):
        if address not in self.phonebook:
            raise PermissionError("Node not in phonebook")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(self.address)
            sock.connect(address)

            sock.send(pickle.dumps("phonebook"))
            new_phonebook = sock.recv(2048)
            new_phonebook = pickle.loads(new_phonebook)

            new_entries = []
            for entry in new_phonebook:
                # add new address only if it was not already in our phonebook,
                # no modification of the previous addresses
                if entry not in self.phonebook:
                    self.phonebook[entry] = new_phonebook[entry]
                    new_entries.append(entry)

            self.complete_entries_key(new_entries)

    def complete_entries_key(self, addresses):
        for entry in addresses:
            if type(self.phonebook[entry][0]) is not rsa.PublicKey:
                public_key = exchange_key(entry)
                if type(public_key) is rsa.PublicKey:
                    self.phonebook[entry][0] = public_key
                else:
                    # Communication failed, suppose that node is offline, remove from phonebook
                    del self.phonebook[entry]

    def define_path(self):
        list_of_node = [self.phonebook[entry] for entry in self.phonebook]
        random.shuffle(list_of_node)
        while len(list_of_node) > PATH_LENGTH:
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
            sock.bind(self.address)
            sock.listen()

            while True:
                connection, address = sock.accept()
                print(f"{self.address} accepted connection with: {address}")
                with connection:
                    message = connection.recv(2048)
                    message = pickle.loads(message)
                    print(f"received: {message}")
                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook))
                    elif message == "public_key":
                        if type(self.public_key) is not rsa.PublicKey:
                            self.init_keys()
                        connection.send(pickle.dumps(self.public_key))
                    elif type(message) is rsa.PublicKey:
                        self.phonebook[(address[0], address[1])] = [message, False]

    def init_node_as_relay(self):
        self.start_listener()
        print(self.address)
