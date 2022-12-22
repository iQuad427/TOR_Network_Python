import copy
import pickle
import socket
import select
import threading
import time
import rsa

import tools
from phonebook import Phonebook

PATH_LENGTH = 3     # The maximum number of nodes in the communication path

# The range of free ports that can be assigned to sockets
STARTING_FREE_PORT = 8000
ENDING_FREE_PORT = 64000

# Initial dictionary containing initial addresses as keys and (public_key, is_exit_node) as values
starting_phonebook = {
    ("127.0.0.1", 4000): ["west_node", True],
    ("127.0.0.2", 4000): ["north_node", False],
    ("127.0.0.3", 4000): ["east_node", False],
    ("127.0.0.4", 4000): ["south_node", False],
}

# Specific indexes to assign different ports for different purposes
port_dictionary = {
    "listening":    0,
    "peering":      1,
}


class Node:
    def __init__(self, own_address, is_exit_node):
        self.address = (own_address[0], own_address[1])
        self.public_key, self.private_key = rsa.newkeys(1024)
        self.phonebook = Phonebook()
        self.init_phonebook()
        self.is_exit_node = is_exit_node
        self.exit = set()
        self.path = list()
        self.free_port = STARTING_FREE_PORT
        self.backwarding_sockets = list()
        self.dict_address_to_portsocket = dict()  # {(own_address[0], 4999): [4999]}
        self.sockets = list()
        self.dict_socket_to_address = dict()  # {4999: (own_address[0], 4999)}
        self.to_backward = list()
        self.recv_buffer = list()
        self.thread_locked = False
        self.listening_socket = None
        self.forwarding_socket = None

    def start(self):
        """
        Starts listening to incoming requests
        Starts the forwarding loop to forward incoming messages from a previous node
        Starts the backwarding loop to backward incoming messages from a next node
        """
        self.thread_locked = False
        threading.Thread(target=self.start_forwarding).start()
        threading.Thread(target=self.start_backwarding).start()
        threading.Thread(target=self.start_listening).start()

    def stop(self):
        self.thread_locked = True

        self.sockets.clear()
        self.dict_address_to_portsocket.clear()
        self.dict_socket_to_address.clear()

    def become_exit_node(self):
        """
        Turn the node into an exit node
        """
        self.is_exit_node = True

    def become_normal_node(self):
        """
        Turn the node into a non exit node
        """
        self.is_exit_node = False

    def init_phonebook(self):
        """
        Init the phonebook with correct addresses and corresponding (public_key, is_exit_node) by
        sending requests to the addresses in the starting_phonebook
        :return:
        """
        list_of_contact = copy.deepcopy(starting_phonebook)
        self.phonebook.update_contact_list(list_of_contact)
        self.phonebook.complete_contacts([contact for contact in list_of_contact])

    def update_phonebook(self, address):
        """
        Update the phonebook with a peer's phonebook
        :param address: tuple containing the IP address and port of the peer whose phonebook we want
        """
        if address not in self.phonebook.get_contacts():
            raise PermissionError("Node not in phonebook")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(address)

            sock.send(pickle.dumps("phonebook"))
            new_phonebook = sock.recv(2048)
            new_phonebook = pickle.loads(new_phonebook)

            self.phonebook.update_contact_list(new_phonebook)

    def increment_port(self):
        """
        Increment the node's current free port by 1 and return the new value
        If the new port exceeds the ending free port, reset the free port to the starting free port
        :return:
        """
        new_port = self.free_port + 1
        if new_port > ENDING_FREE_PORT:
            self.free_port = STARTING_FREE_PORT
        else:
            self.free_port = new_port

        return self.free_port

    def set_path(self):
        """
        If the path has not been set yet, add the first node in the exit set to the path
        :return:
        """
        if not self.path:
            if len(self.phonebook.get_contact_list()) < PATH_LENGTH:
                for node in self.phonebook.contact_list:
                    self.update_phonebook(node)
            self.path = self.phonebook.define_path(PATH_LENGTH)

    def update_address_socket_mapping(self, address):
        """
        Update the mapping of addresses to sockets and sockets to addresses for the node.
        This function creates a socket that listens on a specific port and adds it to the list of sockets
        that the node listens to for incoming messages.
        :param address: tuple containing the IP address and port of the node we want to update the mapping for
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.address[0], self.free_port))
        server.listen(1)
        self.sockets.append(server)
        # Saving the port from which we send the onion
        self.dict_address_to_portsocket[address] = [self.free_port]
        # Creating a socket and add it to listening_backward loop
        self.dict_address_to_portsocket[address].append(server)
        # Adding the address to which the socket will backward the received onions
        self.dict_socket_to_address[server] = address

    def send(self, message):
        """
        Send a packet after onioning it
        """
        self.set_path()

        onion = tools.encrypt_path(message, self.path)
        next_address, onion = tools.peel_address(onion, private_key=None)

        # Sending to the next node the onion
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.address[0], self.free_port))
        try:
            sock.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
            sock.send(onion)
        except ConnectionRefusedError:
            # Means that the first node in the path, should be removed from the phonebook
            self.connection_error_handler(next_address)
        sock.close()

        self.update_address_socket_mapping(self.address)
        self.increment_port()

    def recv(self, timeout, delay=0.1):
        elapsed = 0

        response = None
        while response is None and elapsed < timeout:
            time.sleep(delay)
            response = self.recv_buffer.pop(0) if len(self.recv_buffer) > 0 else None
            elapsed += delay

        return response

    def get_listening_socket(self):
        if self.listening_socket is not None:
            return self.listening_socket
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self.address)
            sock.settimeout(1)
            self.listening_socket = sock

        return sock

    def start_listening(self):
        sock = self.get_listening_socket()
        sock.listen()

        while not self.thread_locked:
            try:
                connection, address = sock.accept()
                with connection:
                    message = connection.recv(2048)
                    message = pickle.loads(message)
                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook.get_contact_list()))
                    elif message == "public_key":
                        connection.send(pickle.dumps(self.public_key))
            except socket.timeout:
                pass

    def get_forwarding_socket(self):
        if self.forwarding_socket is not None:
            return self.forwarding_socket
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.address[0], self.address[1] + port_dictionary["peering"]))
            sock.settimeout(1)
            self.forwarding_socket = sock

        return sock

    def start_forwarding(self):
        sock = self.get_forwarding_socket()
        sock.listen()
        while not self.thread_locked:
            try:
                connection, address = sock.accept()
                threading.Thread(target=self.forwarding, args=(connection, address)).start()
            except socket.timeout:
                pass

    def forwarding(self, previous_node, address):
        """
        Forward a message received from a previous node in the onion routing path
        :param previous_node: socket connected to the previous node in the path
        :param address: tuple containing the IP address and port of the previous node
        """
        while not self.thread_locked:
            # Receive a message (could be longer than 2048, need to concat)
            message = b''
            while True:
                packet = previous_node.recv(2048)
                if not packet:
                    break
                message += packet

            # If we did not receive the onion
            if message == b'':
                return

            # Get the address of the next node by removing one layer of encryption
            next_address, onion = tools.peel_address(message, self.private_key)

            if next_address is None:    # Means That this node is the recipient of the message
                break

            # Create a socket to send the message to the next node
            next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            next_node.bind((self.address[0], self.free_port))

            if onion[:5] == b'send:':
                if not self.is_exit_node:
                    return

                # Send the message to host outside the TOR network
                try:
                    next_node.connect(next_address)
                    next_node.send(onion[5:])
                except ConnectionRefusedError:
                    # Means that the previous node disconnected, should be removed from the phonebook
                    self.connection_error_handler(address)

                message = b''
                while True:
                    packet = next_node.recv(2048)   # Receiving a possible answer from the host
                    if not packet:
                        break
                    message += packet

                # Create a socket to send back the answer to the previous node in the path
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.connect(address)
                    sock.send(message)
                except ConnectionRefusedError:
                    # Means that the previous node disconnected, should be removed from the phonebook
                    self.connection_error_handler(address)

                sock.close()

            else:
                # Sending the onion the next node
                try:
                    next_node.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
                    next_node.send(onion)
                except ConnectionRefusedError:
                    # Means that the next node disconnected, should be removed from the phonebook
                    self.connection_error_handler(next_address)

            next_node.close()
            # Create a listening socket to listen for possible responses from the next node
            if address not in self.dict_address_to_portsocket.keys():
                self.update_address_socket_mapping(address)
                self.increment_port()
            return

    def start_backwarding(self):
        """
        Launching two threads to listen from responses for the onions that we sent and send them back
        """
        threading.Thread(target=self.listen_backward).start()
        threading.Thread(target=self.start_sending_backward).start()

    def start_sending_backward(self):
        """
        Loop to send back the responses received for the forwarded onions
        """
        while not self.thread_locked:
            to_remove = []
            for message in self.to_backward:
                next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    next_node.connect((message[0][0], message[0][1]))
                    next_node.send(tools.sign(message[1], self.private_key))
                except ConnectionRefusedError:
                    # Means that a previous node disconnected, should be removed from the phonebook
                    self.connection_error_handler((message[0][0], message[0][1]))
                next_node.close()
                to_remove.append(message)
            for message in to_remove:
                self.to_backward.remove(message)

    def listen_backward(self):
        """
        Loop listening on all the ports that were used to forward onions.
        Adds received messages and the address to which send back to the list to_backward
        """
        while not self.thread_locked:
            if self.sockets:
                readable, _, _ = select.select(self.sockets, [], [], 0.2)

                if readable:
                    ready_server = readable[0]
                    connection, address = ready_server.accept()
                    with connection:
                        message = connection.recv(2048)
                        if self.dict_socket_to_address[ready_server] == self.address:
                            self.recv_buffer.append(tools.verify_sign_path(message, self.path))
                        else:
                            self.to_backward.append((self.dict_socket_to_address[ready_server], message))

    def connection_error_handler(self, address):
        """
        Removes a non responding node from the phonebook
        :param address: Address of the non responding node
        :return:
        """
        if address in self.phonebook.get_contacts():
            self.phonebook.remove_address(address)

