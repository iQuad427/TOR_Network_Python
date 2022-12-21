import copy
import pickle
import socket
import threading
import time
import rsa
import select

import tools
from phonebook import Phonebook

PATH_LENGTH = 3
STARTING_FREE_PORT = 5000
ENDING_FREE_PORT = 64000

starting_phonebook = {
    ("127.0.0.1", 4000): ["west_node", True],
    ("127.0.0.2", 4000): ["north_node", False],
    ("127.0.0.3", 4000): ["east_node", False],
    ("127.0.0.4", 4000): ["south_node", False],
}

port_dictionary = {
    "listening":    0,
    "peering":      1,
    "forwarding":   2,
    "backwarding":  3,
    "sending":      4,
    "phonebook":    5,
    "auth":         6,
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
        self.dict_address_to_portsocket = {(own_address[0], 4999): [4999]}
        self.sockets = list()
        self.dict_socket_to_address = {4999: (own_address[0], 4999)}
        self.to_backward = list()
        self.recv_buffer = list()

    def start(self):
        print(f"{self.address} is online")
        threading.Thread(target=self.start_listening).start()
        threading.Thread(target=self.start_forwarding).start()
        threading.Thread(target=self.start_backwarding).start()

    def init_phonebook(self):
        list_of_contact = copy.deepcopy(starting_phonebook)
        self.phonebook.update_contact_list(list_of_contact)
        self.phonebook.complete_contacts([contact for contact in list_of_contact])

    def update_phonebook(self, address):
        """
        Update the phonebook through a peer phonebook
        :param address: address of the peer we want the phonebook of
        """
        if address not in self.phonebook.get_contacts():
            raise PermissionError("Node not in phonebook")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["phonebook"]))
            sock.connect(address)

            sock.send(pickle.dumps("phonebook"))
            new_phonebook = sock.recv(2048)
            new_phonebook = pickle.loads(new_phonebook)

            self.phonebook.update_contact_list(new_phonebook)

    def increment_port(self):
        new_port = self.free_port + 1
        if new_port > ENDING_FREE_PORT:
            self.free_port = STARTING_FREE_PORT
        else:
            self.free_port = new_port

        return self.free_port

    def set_path(self):
        if not self.path:
            self.path = self.phonebook.define_path(PATH_LENGTH)

    def send(self, message):
        """
        Send a packet after onioning it
        """
        self.set_path()
        print(f"Path : {[self.path[i][0] for i in range(len(self.path))]}")

        onion = tools.encrypt_path(message, self.path)
        # print(f"Onion to send : {onion}")

        next_address, onion = tools.peel_address(onion, private_key=None)

        # Sending to the next node the onion
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.address[0], self.free_port))
        sock.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
        sock.send(onion)
        sock.close()

        # Saving the port from which we send the onion
        self.dict_address_to_portsocket[self.address] = [self.free_port]
        # Creating a socket that will listen on the same port from which we
        # sent the onion to be able to get responses
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.address[0], self.free_port))
        server.listen(1)
        self.sockets.append(server)
        # Creating a socket and add it to listening_backward loop
        self.dict_address_to_portsocket[self.address].append(server)
        # Adding the address to which the socket will backward the received onions
        # The address of the client because it's the original sender, and he will not backward it
        self.dict_socket_to_address[server] = self.address

        self.increment_port()

    def recv(self, timeout, delay=0.1):
        elapsed = 0

        response = None
        while response is None and elapsed < timeout:
            # print("blocking everyone")
            time.sleep(delay)
            response = self.recv_buffer.pop(0) if len(self.recv_buffer) > 0 else None
            elapsed += delay

        return response

    def start_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(self.address)
            sock.listen()

            while True:
                connection, address = sock.accept()
                # print(f"{self.address} accepted connection with: {address}")

                with connection:
                    message = connection.recv(2048)
                    message = pickle.loads(message)
                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook.get_contact_list()))
                    elif message == "public_key":
                        connection.send(pickle.dumps(self.public_key))

    def start_forwarding(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["peering"]))
            sock.listen()

            while True:
                connection, address = sock.accept()
                threading.Thread(target=self.forwarding, args=(connection, address)).start()
                # print(f"{self.address} forwarded a packet from {address}")

    def forwarding(self, previous_node, address):
        while True:
            # Receive message (could be longer than 2048, need to concat)
            message = b''
            while True:
                packet = previous_node.recv(2048)
                if not packet:
                    break
                message += packet

            # If we did receive the onion
            if message == b'':
                return

            next_address, onion = tools.peel_address(message, self.private_key)
            # print("Next address : " + str(next_address))
            # print("Next message : " + str(onion))

            if next_address is None:
                print(f"Message received at {self.address} : {onion.decode('utf-8')}")
                break

            next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_node.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if address in self.dict_address_to_portsocket.keys():
                next_node.bind((self.address[0], self.dict_address_to_portsocket[address][0]))
            else:
                next_node.bind((self.address[0], self.free_port))

            if onion[:5] == b'send:':
                if not self.is_exit_node:

                    return

                print(f"sending {onion[5:]} to {next_address}")

                next_node.connect(next_address)
                next_node.send(onion[5:])

                message = b''
                while True:
                    print("receiving message")
                    packet = next_node.recv(2048)
                    if not packet:
                        break
                    message += packet

                print("received message :", message)

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(address)
                sock.send(message)
                sock.close()

                print("backwarded")

            else:
                next_node.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
                next_node.send(onion)

            next_node.close()

            if address not in self.dict_address_to_portsocket.keys():
                # Saving the port from which we send the onion
                self.dict_address_to_portsocket[address] = [self.free_port]
                # Creating a socket that will listen on the same port from which we
                # sent the onion to be able to get responses
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.address[0], self.free_port))
                server.listen(1)
                self.sockets.append(server)
                # Creating a socket and add it to listening_backward loop
                self.dict_address_to_portsocket[address].append(server)
                # Adding the address to which the socket will backward the received onions
                self.dict_socket_to_address[server] = address

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
        while True:
            to_remove = []
            if len(self.to_backward) > 0:
                print("sent_to_backward :", self.to_backward)
            for address in self.to_backward:
                next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # next_node.bind((self.address[0], self.free_port))
                next_node.connect((address[0][0], address[0][1]))
                next_node.send(address[1])
                next_node.close()
                to_remove.append(address)
            for address in to_remove:
                self.to_backward.remove(address)

    def listen_backward(self):
        """
        Loop listening on all the ports that were used to forward onions.
        Adds received messages and the address to which send back to a list
        """
        while True:
            if self.sockets:
                readable, _, _ = select.select(self.sockets, [], [], 0.2)

                if readable:
                    ready_server = readable[0]
                    connection, address = ready_server.accept()
                    with connection:
                        message = connection.recv(2048)
                        # message = message.decode()
                        print(f"\nMessage received : {message}\n"
                              f"At   : {self.address}\n"
                              f"From : {address}")

                        # connection.send(message.encode())

                        print(self.dict_socket_to_address[ready_server], self.address)
                        if self.dict_socket_to_address[ready_server] == self.address:
                            print("Returned to sender")
                            self.recv_buffer.append(message)
                        else:
                            self.to_backward.append((self.dict_socket_to_address[ready_server], message))

    def sign(self, packet):
        return rsa.sign(packet, self.private_key, 'SHA-256')
