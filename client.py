import copy
import pickle
import random
import socket
import threading
import time
import rsa
import select

import tools
from phonebook import Phonebook

PATH_LENGTH = 3

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
}


class Node:

    def __init__(self, own_address):
        self.public_key = 0
        self.private_key = 0
        self.init_keys()
        self.address = (own_address[0], own_address[1])
        self.phonebook = Phonebook()
        self.init_phonebook()
        self.exit = set()
        self.path = []
        self.free_port = 5000
        self.backwarding_sockets = []
        self.dict_address_to_portsocket = {(own_address[0], 4999): [4999]
                                           }
        self.sockets = []
        self.dict_port_to_address = {4999: (own_address[0], 4999)
                                       }
        self.dict_socket_to_address = {4999: (own_address[0], 4999)
                                       }
        self.to_backward = []

    def init_node_as_relay(self):
        self.start()
        print(f"{self.address} is online")

    def init_keys(self):
        # TODO : Check if keys are already set, else do whatever bro, idk
        (self.public_key, self.private_key) = rsa.newkeys(1024)

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

    def set_path(self):
        self.path = self.phonebook.define_path(PATH_LENGTH)

    def send(self, message):
        """
        Send a packet after onioning it
        :param message:
        :return:
        """
        self.set_path()
        print(f"Path : {self.path}")

        onion = tools.encrypt_path(message, self.path)
        print(f"Onion to send : {onion}")

        next_address, onion = tools.peel_address(onion, private_key=None)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.address[0], self.address[1] + port_dictionary["sending"]))
        sock.connect((next_address[0], next_address[1] + 1))
        sock.send(onion)
        sock.close()
        self.dict_address_to_portsocket[self.address] = [self.free_port]
        self.dict_port_to_address[self.free_port] = self.address
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.address[0], self.free_port))
        server.listen(1)
        self.sockets.append(server)
        self.dict_address_to_portsocket[self.address].append(server)
        self.dict_socket_to_address[server] = self.address
        self.free_port += 1

    def start(self):
        threading.Thread(target=self.start_listening).start()
        # threading.Thread(target=self.backward).start()
        threading.Thread(target=self.start_forwarding).start()

    def start_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(self.address)
            sock.listen()

            while True:
                connection, address = sock.accept()
                #print(f"{self.address} accepted connection with: {address}")

                with connection:
                    message = connection.recv(2048)
                    message = pickle.loads(message)
                    #print(f"received: {message}")
                    if message == "phonebook":
                        connection.send(pickle.dumps(self.phonebook.get_contact_list()))
                    elif message == "public_key":
                        if type(self.public_key) is not rsa.PublicKey:
                            self.init_keys()
                        connection.send(pickle.dumps(self.public_key))
                    elif type(message) is rsa.PublicKey:
                        self.phonebook[(address[0], address[1])] = [message, False]

    def start_forwarding(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["peering"]))
            sock.listen()

            while True:
                connection, address = sock.accept()
                threading.Thread(target=self.forwarding, args=(connection, address)).start()
                print(f"{self.address} forwarded a packet from {address}")

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
            print("Next address : " + str(next_address))
            print("Next message : " + str(onion))

            if next_address is None:
                print(f"Message received at {self.address} : {onion.decode('utf-8')}")
                break

            next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_node.bind((self.address[0], self.free_port))

            next_node.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
            next_node.send(onion)
            next_node.close()

            self.dict_address_to_portsocket[address] = [self.free_port]
            self.dict_port_to_address[self.free_port] = address
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.address[0], self.free_port))
            server.listen(1)
            self.sockets.append(server)
            self.dict_address_to_portsocket[address].append(server)
            self.dict_socket_to_address[server] = address
            self.free_port += 1
            return
        # threading.Thread(target=self.backward).start()

    def start_listen_backward(self):
        #threading.Thread(target=self.update_sockets).start()
        threading.Thread(target=self.listen_backward).start()
        threading.Thread(target=self.start_sending_backward).start()

    def start_sending_backward(self):
        while True:
            to_remove = []
            for i in self.to_backward:
                print(i)
                next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # next_node.bind((self.address[0], self.free_port))
                print("là fréro", (i[0][0], i[0][1]))
                next_node.connect((i[0][0], i[0][1]))
                next_node.send(i[1])
                next_node.close()
                to_remove.append(i)
            for i in to_remove:
                self.to_backward.remove(i)


    def listen_backward(self):

        while True:
            if self.sockets:
                print(self.sockets)
                readable, _, _ = select.select(self.sockets, [], [])
                ready_server = readable[0]
                print("heeeeeeeeeeeeeeeere", ready_server)
                connection, address = ready_server.accept()
                with connection:
                    message = connection.recv(2048)
                    message = message.decode()
                    print(f"Message received : {message}\n"
                          f"From : ({address[0]}, {address[1]})")

                    connection.send(message.encode())
                    print("I received a response to my message", message)
                    print(self.dict_socket_to_address[ready_server], self.address)

                    if self.dict_socket_to_address[ready_server] == self.address:
                        print("I received a response to my message", message)
                    else:
                        self.to_backward.append((self.dict_socket_to_address[ready_server], message.encode()))

    def backwarding(self, previous_node, next_node):
        # Receive message (could be longer than 2048, need to concat)

        while True:
            packet = next_node.recv(2048)
            if not packet:
                break
            if packet:
                signature = self.sign(packet)
                message = signature + packet
                previous_node.send(message)

    def forward_loop(self, previous_node, next_node):

        while True:
            # Receive message (could be longer than 2048, need to concat)
            message = b''
            while True:
                print("xd")
                packet = previous_node.recv(2048)
                if not packet:
                    break
                message += packet

            # If we did receive the onion
            if message != b'':
                next_address, onion = tools.peel_address(message, self.private_key)

                print("Next address : " + str(next_address))
                print("Next message : " + str(onion))
                next_node.send(onion)

    def backward(self):
        i = 0
        while True:
            time.sleep(1)
            i += 1
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        #     sock.bind((self.address[0], self.address[1]+502))
        #     sock.listen()
        #
        #     while True:
        #         connection, address = sock.accept()
        #         # print(f"{self.address} accepted connection with: {address}")
        #
        #         with connection:
        #             message = connection.recv(2048)
        #             message = pickle.loads(message)
        #             # print(f"received: {message}")
        #             if message == "phonebook":
        #                 connection.send(pickle.dumps(self.phonebook))
        #             elif message == "public_key":
        #                 if type(self.public_key) is not rsa.PublicKey:
        #                     self.init_keys()
        #                 connection.send(pickle.dumps(self.public_key))
        #             elif type(message) is rsa.PublicKey:
        #                 self.phonebook[(address[0], address[1])] = [message, False]

    def sign(self, packet):
        return rsa.sign(packet, self.private_key, 'SHA-256')

    def send_back(self, address, packet):
        signature = self.sign(packet)
        new_packet = signature + packet
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["backwarding"]))
            sock.connect((address[0], address[1] + port_dictionary["backwarding"]))
            sock.send(new_packet)

    def signup_to_authentication_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.1.1.1", 4000))
            sock.send("Give me your public key".encode())
            public_key = sock.recv(2048)
            public_key = pickle.loads(public_key)
            sock.send("Signup".encode())
            if sock.recv(2048).decode() == "Username":
                sock.send(self.address[0].encode())
            else:
                print("error")
            if sock.recv(2048).decode() == "Password":
                sock.send(tools.encrypt("postgres".encode(), public_key))
            else:
                print("error")
            if sock.recv(2048).decode() == "Password":
                sock.send(tools.encrypt("postgres".encode(), public_key))
            else:
                print("error")
            print(f"Received message from server : {sock.recv(2048).decode()}")

    def signin_to_authentication_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.1.1.1", 4000))
            sock.send("Give me your public key".encode())
            public_key = sock.recv(2048)
            public_key = pickle.loads(public_key)
            sock.send("Signin".encode())
            if sock.recv(2048).decode() == "Username":
                sock.send(self.address[0].encode())
            else:
                print("error")
            if sock.recv(2048).decode() == "Password":
                sock.send(tools.encrypt("postgres".encode(), public_key))
            else:
                print("error")
            print(f"Received message from server : {sock.recv(2048).decode()}")

