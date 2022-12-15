import copy
import pickle
import random
import socket
import threading
import time
import rsa

import message_tool

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


def peel_address(message, key):
    return ("", 0), ""


def peel_layer(message, key):
    return ""


def add_layer(message, key):
    return ""


class Node:
    def __init__(self, own_address):
        self.public_key = 0
        self.private_key = 0
        self.init_keys()
        self.address = (own_address[0], own_address[1])
        self.phonebook = copy.deepcopy(starting_phonebook)
        self.path = []

    def init_node_as_relay(self):
        self.start()
        print(f"{self.address} is online")

    def init_keys(self):
        # TODO : Check if keys are already set, else do whatever bro, idk
        (self.public_key, self.private_key) = rsa.newkeys(1024)

    def reset_phonebook(self):
        self.phonebook = starting_phonebook

    def update_phonebook(self, address):
        if address not in self.phonebook:
            raise PermissionError("Node not in phonebook")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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
        list_of_node = list(self.phonebook.keys())
        random.shuffle(list_of_node)
        while len(list_of_node) > PATH_LENGTH:
            index = random.randrange(0, len(list_of_node), 1)
            list_of_node.pop(index)

        self.path = list_of_node

    def send(self, message):
        self.define_path()

        onion = message_tool.generate_onion(message, self.path)
        print(onion)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            print(self.path)
            sock.connect(self.path[0])
            sock.send(pickle.dumps("forward"))
            time.sleep(0.5)
            sock.send(pickle.dumps(onion[1:]))

    def start(self):
        listener = threading.Thread(target=self.listener)
        listener.start()

    def listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(self.address)
            sock.listen()

            while True:
                connection, address = sock.accept()
                print(f"{self.address} accepted connection with: {address}")
                need_to_close = True

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
                elif message == "forward":
                    threading.Thread(target=self.start_forwarding, args=(connection,)).start()
                    print(f"{self.address} forwarded a packet from {address}")
                    need_to_close = False

                if need_to_close:
                    print("closing connection")
                    connection.close()

    def start_forwarding(self, previous_node):
        # Connection information on next node
        while True:
            message = previous_node.recv(2048)

            if message != b'':
                onion = pickle.loads(message)

                if len(onion) == 1:
                    print(f"Message received at {self.address} : {onion[0]}")
                    return

                next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                next_node.connect(onion[0])

                next_node.send(pickle.dumps("forward"))
                time.sleep(0.5)
                next_node.send(pickle.dumps(onion[1:]))
                return
