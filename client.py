import pickle
import socket
import ipaddress
import sys
import rsa


class Node:
    list_addresses = []
    public_key = 0
    private_key = 0

    def __init__(self, my_address, my_port, server_address):
        self.tor_host = server_address[0]
        self.tor_port = server_address[1]
        self.my_address = my_address
        self.my_port = my_port

    def init_keys(self):
        (self.public_key, self.private_key) = rsa.newkeys(1024)

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

    def forward_packet(self, packet, IP_address):
        """
        Send the packet to the corresponding IP address
        :return:
        """

    def connect_to_network(self):
        """
        Request a subset of IP addresses to a node already in the network
        :return:
        """

    def init_node_as_relay(self):
        """
        Handshake between node and TOR server to decide on the relay IP address

        :return:
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.my_address, self.my_port))
            sock.connect((self.tor_host, self.tor_port))
            self.init_keys()
            key = pickle.dumps(self.public_key)
            message = key
            sock.send(message)
            addresses = sock.recv(2048)
            addresses = pickle.loads(addresses)
            print(f"Received address : {addresses}")

            self.list_addresses = addresses