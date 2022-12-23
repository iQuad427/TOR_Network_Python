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
DEL_PATH_ON_BACKWARD = True

# The range of free ports that can be assigned to sockets
STARTING_FREE_PORT = 8000
ENDING_FREE_PORT = 64000

PORT = 4100

# Initial dictionary containing initial addresses as keys and (public_key, is_exit_node) as values
starting_phonebook = {
    ("127.0.0.1", PORT): ["west_node", True],
    ("127.0.0.2", PORT): ["north_node", False],
    ("127.0.0.3", PORT): ["east_node", False],
    ("127.0.0.4", PORT): ["south_node", False],
}

# Specific indexes to assign different ports for different purposes
port_dictionary = {
    "peering": 1,
}


class Node:
    def __init__(self, own_address, is_exit_node):
        self.address = (own_address[0], own_address[1])
        self.public_key, self.private_key = rsa.newkeys(1024)
        self.is_exit_node = is_exit_node
        self.phonebook = Phonebook()
        self.exit = set()
        self.path = list()
        self.free_port = STARTING_FREE_PORT
        self.backwarding_sockets = list()
        self.dict_address_to_socket = dict()  # {(own_address[0], 4999): [4999]}
        self.dict_socket_to_address = dict()  # {4999: (own_address[0], 4999)}
        self.sockets = list()
        self.to_backward = list()
        self.recv_buffer = list()
        self.thread_locked = False
        self.forwarding_socket = None
        self.listening_socket = None

    def start(self):
        """
        Starts listening to incoming requests
        Starts the forwarding loop to forward incoming messages from a previous node
        Starts the backwarding loop to backward incoming messages from a next node
        """
        self.thread_locked = False
        threading.Thread(target=self.start_listening).start()
        threading.Thread(target=self.start_forwarding).start()
        threading.Thread(target=self.start_backwarding).start()
        self.init_phonebook()

    def stop(self):
        self.thread_locked = True

        self.sockets.clear()
        self.dict_address_to_socket.clear()
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
        """
        self.phonebook = Phonebook(copy.deepcopy(starting_phonebook))
        self.phonebook.complete_contacts()

    def update_phonebook(self, address):
        """
        Update the phonebook with a peer's phonebook
        :param address: tuple containing the IP address and port of the peer whose phonebook we want
        """
        if address not in self.phonebook.get_contacts():
            raise PermissionError("Node not in phonebook")

        new_phonebook = tools.request_from_node(address, "phonebook")
        if new_phonebook is not None:
            self.phonebook.update_contact_list(new_phonebook)

    def set_path(self):
        """
        If the path has not been set yet, add the first node in the exit set to the path
        """
        if not self.path:
            if len(self.phonebook.get_contact_list()) < PATH_LENGTH:
                for node in self.phonebook.contact_list:
                    self.update_phonebook(node)
            self.path = self.phonebook.define_path(PATH_LENGTH)

    def update_address_socket_mapping(self, previous_address, self_address):
        """
        Update the mapping of addresses to sockets and sockets to addresses for the node.
        This function creates a socket that listens on a specific port and adds it to the list of sockets
        that the node listens to for incoming messages.
        :param previous_address:
        :param self_address:
        """
        socket_to_previous_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_to_previous_node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socket_to_previous_node.bind(self_address)
        socket_to_previous_node.listen(1)

        self.sockets.append(socket_to_previous_node)
        # Saving the port from which we sent the onion + creating a socket and add it to listening_backward loop
        self.dict_address_to_socket[previous_address] = [self_address, socket_to_previous_node]
        # Adding the address to which the socket will backward the received onions
        self.dict_socket_to_address[socket_to_previous_node] = previous_address

    def send(self, message):
        """
        Send a packet after onioning it
        """
        self.set_path()

        onion = tools.encrypt_path(message, self.path)
        next_address, onion = tools.peel_address(onion, private_key=None)

        # Sending to the next node the onion
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
            sock.send(onion)
        except ConnectionRefusedError:
            # Means that the first node in the path, should be removed from the phonebook
            self.connection_error_handler(next_address)

        address_used_to_forward = sock.getsockname()
        sock.close()

        # Give self.address as previous node to stop the sender forwarding loop when receiving its packet back
        self.update_address_socket_mapping(self.address, address_used_to_forward)

    def recv(self, timeout, delay=0.1):
        elapsed = 0

        response = None
        while response is None and elapsed < timeout:
            time.sleep(delay)
            response = self.recv_buffer.pop(0) if len(self.recv_buffer) > 0 else None
            elapsed += delay

        return response

    def get_listening_socket(self):
        if self.listening_socket is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(self.address)
            sock.settimeout(1)
            self.listening_socket = sock
        else:
            return self.listening_socket

        return sock

    def start_listening(self):
        sock = self.get_listening_socket()
        sock.listen()

        while not self.thread_locked:
            try:
                connection, address = sock.accept()
                with connection:
                    message = connection.recv(2048)

                    try:
                        message = pickle.loads(message)
                    except EOFError:
                        message = ""

                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook.get_contact_list()))
                    elif message == "public_key":
                        connection.send(pickle.dumps(self.public_key))
                    elif type(message) == rsa.PublicKey:
                        self.phonebook.add_address(address, message)
                        connection.send(pickle.dumps("added to network"))
                    elif message == "exit_node":
                        self.phonebook.remove_address(address)
                        self.phonebook.add_address(address, message, is_exit_node=True)
                        connection.send(pickle.dumps("became an exit node"))
            except socket.timeout:
                pass

    def get_forwarding_socket(self):
        if self.forwarding_socket is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.address[0], self.address[1] + port_dictionary["peering"]))
            sock.settimeout(1)
            self.forwarding_socket = sock
        else:
            return self.forwarding_socket

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

    def forwarding(self, previous_node, previous_node_address):
        """
        Forward a message received from a previous node in the onion routing path
        :param previous_node_address: tuple containing the IP address and port of the previous node
        :param previous_node: socket connected to the previous node in the path
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

            if onion[:5] == b'send:':
                if not self.is_exit_node:
                    return

                # Send the message to host outside the TOR network
                try:
                    next_node.connect(next_address)
                    next_node.send(onion[5:])
                except ConnectionRefusedError:
                    # Means that the previous node disconnected, should be removed from the phonebook
                    self.connection_error_handler(previous_node_address)

                message = b''
                while True:
                    packet = next_node.recv(2048)   # Receiving a possible answer from the host
                    if not packet:
                        break
                    message += packet

                # Create a socket to send back the answer to the previous node in the path
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.connect(previous_node_address)
                    sock.send(message)
                except ConnectionRefusedError:
                    # Means that the previous node disconnected, should be removed from the phonebook
                    self.connection_error_handler(previous_node_address)

                sock.close()
            else:
                # Sending the onion the next node
                try:
                    next_node.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
                    next_node.send(onion)
                except ConnectionRefusedError:
                    # Means that the next node disconnected, should be removed from the phonebook
                    self.connection_error_handler(next_address)

            address_used_to_forward = next_node.getsockname()
            next_node.close()
            # Create a listening socket to listen for possible responses from the next node
            if previous_node_address not in self.dict_address_to_socket.keys():
                self.update_address_socket_mapping(previous_node_address, address_used_to_forward)
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

                    if DEL_PATH_ON_BACKWARD:
                        self.dict_address_to_socket.pop(self.dict_socket_to_address[ready_server])
                        self.dict_socket_to_address.pop(ready_server)

    def connection_error_handler(self, address):
        """
        Removes a non responding node from the phonebook
        :param address: Address of the non responding node
        :return:
        """
        if address in self.phonebook.get_contacts():
            self.phonebook.remove_address(address)

