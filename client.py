import copy
import pickle
import random
import socket
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import message_tool

PATH_LENGTH = 3

starting_phonebook = {
    ("127.0.0.1", 4000): ["west_node", False],
    ("127.0.0.2", 4000): ["north_node", False],
    ("127.0.0.3", 4000): ["east_node", False],
    ("127.0.0.4", 4000): ["south_node", False],
}

port_dictionary = {
    "listening":    0,
    "peering":      1,
    "forwarding":   2,
    "sending":      3,
    "phonebook":    4,
    "backwarding":  5,
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
            sock.bind((self.address[0], self.address[1] + port_dictionary["phonebook"]))
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
        list_of_node = [(entry, self.phonebook[entry]) for entry in self.phonebook]
        random.shuffle(list_of_node)
        while len(list_of_node) > PATH_LENGTH:
            index = random.randrange(0, len(list_of_node), 1)
            list_of_node.pop(index)

        self.path = list_of_node

    def send(self, message):
        """
        Send a packet after onioning it
        :param message:
        :return:
        """
        self.define_path()
        print(f"Path : {self.path}")

        onion = self.encrypt_packet_for_path(message, self.path)
        print(f"Onion to send : {onion}")
        pos = 0
        for i in range(len(onion)):
            # 58 = utf8 of :
            if onion[i] == 58:
                pos = i
                break

        print(pos)
        print(onion[:pos])
        print(onion[:pos].decode('utf-8'))
        next_address = eval(onion[:pos].decode('utf-8'))
        print(next_address)
        onion = onion[(pos + 1):]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["sending"]))
            sock.connect((next_address[0], next_address[1] + 1))
            print("yoooooooooooooooooooo", next_address[1])
            sock.send(onion)

    # def send_encrypted_packet(self, packet):
    #     """
    #     Add the path composed of IP addresses of at least 3 nodes and encrypt them with
    #     the corresponding public keys and sends it to the first node.
    #     :return:
    #     """
    #     self.define_path()
    #     packet = bytes(packet, 'utf-8')
    #     encrypted_packet = self.encrypt_public_packet(packet)
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    #         # sock.bind((self.address[0], self.address[1] + 2))
    #         sock.connect(self.path[0][0])
    #         print("before")
    #         sock.send(pickle.dumps(encrypted_packet))
    #         print("after")

    def init_phonebook_public_keys(self):
        for entry in self.phonebook :
            self.phonebook[entry][0] = exchange_key(entry)
        print(self.phonebook)

    def encrypt(self, message, public_key):
        """
        Encrypt a message destined to a certain address
        :param message:
        :param public_key:
        :return:
        """
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CTR)
        new_encrypted_packet = cipher.encrypt(message)
        nonce = cipher.nonce
        encrypted_aes_key = rsa.encrypt(key, public_key)
        encrypted_packet = encrypted_aes_key + nonce + new_encrypted_packet
        return encrypted_packet

    def encrypt_packet_for_path(self, packet, path):  # Probablement la même fonction qu'en dessous
        """
        We assume that the packet already contains the IP address of the receiver outside the network
        Encrypts packet with the public keys of the nodes contained in the list
        :return:
        """
        encrypted_packet = bytes(packet, 'utf-8')
        packaging_order = copy.deepcopy(path)
        packaging_order.reverse()
        for node in packaging_order:
            print(node[1][0])
            encrypted_packet = self.encrypt(encrypted_packet, node[1][0])
            encrypted_packet = bytes(str(node[0]), 'utf-8') + bytes(":", 'utf-8') + encrypted_packet

        return encrypted_packet
# encrypt_node0 (path node1 + msg for node1 )
# decrypt
    def decrypt(self, message):
        """
        Decrypt a message
        :param message:
        :return:
        """
        aes_key = rsa.decrypt(message[0:128], self.private_key)
        cipher2 = AES.new(aes_key, AES.MODE_CTR, nonce=message[128:136])
        decrypted_packet = cipher2.decrypt(message[136:])
        return decrypted_packet

    # def encrypt_public_packet(self, packet):  # Probablement la même fonction qu'en dessous
    #     """
    #     We assume that the packet already contains the IP address of the receiver outside the network
    #     Encrypts packet with the public keys of the nodes contained in the list
    #     :return:
    #     """
    #     encrypted_packet = packet
    #
    #     # decrypt_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    #     # plain_text = decrypt_cipher.decrypt(cipher_text)
    #     print(encrypted_packet)
    #     i = 0
    #     key = get_random_bytes(32)
    #     cipher = AES.new(key, AES.MODE_CTR)
    #     new_encrypted_packet = cipher.encrypt(encrypted_packet)
    #     nonce = cipher.nonce
    #     print(nonce)
    #     encrypted_aes_key = rsa.encrypt(key, self.phonebook[("127.0.0.1", 4000)][0])
    #     encrypted_packet = new_encrypted_packet
    #     new_encrypted_packet = encrypted_aes_key  # + nonce + encrypted_packet
    #     encrypted_packet = new_encrypted_packet
    #     print(encrypted_packet)
    #     return encrypted_packet

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

    def start(self):
        threading.Thread(target=self.start_listening).start()
        threading.Thread(target=self.start_forwarding).start()

    def start_listening(self):
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

    def start_forwarding(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["peering"]))
            sock.listen()

            while True:
                connection, address = sock.accept()
                threading.Thread(target=self.forwarding, args=(connection,)).start()
                print(f"{self.address} forwarded a packet from {address}")

    def forwarding(self, previous_node):
        while True:
            # Receive message (could be longer than 2048, need to concat)
            message = b''
            while True:
                packet = previous_node.recv(2048)
                if not packet:
                    break
                message += packet

            # If we did receive the onion
            if message != b'':

                onion = self.decrypt(message)
                pos = 0
                for i in range(len(onion)):
                    # 58 = utf8 of :
                    if onion[i] == 58:
                        pos = i
                        break

                if pos == 0:
                    print(f"Message received at {self.address} : {onion.decode('utf-8')}")
                    return

                next_address = eval(onion[:pos].decode('utf-8'))
                next_msg = onion[(pos + 1):]

                next_node = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                next_node.bind((self.address[0], self.address[1] + port_dictionary["forwarding"]))
                next_node.connect((next_address[0], next_address[1] + port_dictionary["peering"]))
                next_node.send(next_msg)

                return

    def sign(self, packet):
        return rsa.sign(packet, self.private_key, 'SHA-256')

    def send_back(self, address, packet):
        signature = self.sign(packet)
        new_packet = signature+packet
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.address[0], self.address[1] + port_dictionary["backwarding"]))
            sock.connect((address[0], address[1] + 5))
            sock.send(new_packet)


