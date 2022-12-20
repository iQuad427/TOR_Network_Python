import copy
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import rsa
import pickle
import socket


def format_message(username, query, content, to_decode=True):
    """
    Creates a formatted challenge from the username that is getting challenged

    :param username: the username of the user getting challenged
    :param query: the request made to the server
    :param content: the content required by the server to compute the request
    :param to_decode: should the content be decoded when receiving the message (typically a hash should not)

    :return: a formatted byte string representing the whole query made to the server
    """
    formatted = f"{1 if to_decode else 0}:{username}:{query}:".encode('utf-8')
    return formatted + (f"{content}".encode('utf-8') if to_decode else content)


def parsing(argv):
    """
    Parse the argument and retrieve the values separated by the token ":"
    Note :
        - the expected message topology is "to_decode:username:query:content"
        - none of the parts of the message should be left blank
        - the parsing only occurs for the 2 first splitting tokens, allowing for ":" in content

    :param argv: the message after preprocessing (i.e. : "username:query:content")
    :return: username, query, content
    """
    print(argv)
    if argv[1] != b':'[0]:
        return None, None, None

    to_decode = argv[0] - 48  # 48 is the value of 0 in ASCII -> returns an int corresponding to the string value
    argv = argv[2:]

    pos = [None, None]
    number = 0
    for i in range(len(argv)):
        # 58 = utf8 of :
        if argv[i] == 58:
            pos[number] = i
            number += 1
            if number == 2:
                break

    if pos[0] is None or pos[1] is None:
        return None, None, None

    return argv[:pos[0]].decode('utf-8'), argv[pos[0] + 1:pos[1]].decode('utf-8'), \
           (argv[pos[1] + 1:].decode('utf-8') if to_decode else argv[pos[1] + 1:])


def generate_onion(message, node_path):
    packaging_order = copy.deepcopy(node_path)
    packaging_order.reverse()
    onion = [message]
    for hop in packaging_order:
        onion.insert(0, hop[0])

    return onion


def encrypt(message, public_key):
    """
    Encrypt a message destined to a certain address
    :param public_key:
    :param message:
    :return:
    """
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CTR)
    new_encrypted_packet = cipher.encrypt(message)
    nonce = cipher.nonce
    encrypted_aes_key = rsa.encrypt(key, public_key)
    encrypted_packet = encrypted_aes_key + nonce + new_encrypted_packet
    return encrypted_packet


def decrypt(message, private_key):
    """
    Decrypt a message
    :param private_key:
    :param message:
    :return:
    """
    aes_key = rsa.decrypt(message[0:128], private_key)
    cipher2 = AES.new(aes_key, AES.MODE_CTR, nonce=message[128:136])
    decrypted_packet = cipher2.decrypt(message[136:])
    return decrypted_packet


def encrypt_path(packet, path):
    """
    We assume that the packet already contains the IP address of the receiver outside the network
    Encrypts packet with the public keys of the nodes contained in the list
    :return:
    """
    encrypted_packet = bytes(packet, 'utf-8')
    packaging_order = copy.deepcopy(path)
    packaging_order.reverse()
    for node in packaging_order:
        # print(node[1][0])
        encrypted_packet = encrypt(encrypted_packet, node[1][0])
        encrypted_packet = bytes(str(node[0]), 'utf-8') + bytes(":", 'utf-8') + encrypted_packet

    return encrypted_packet


def peel_address(onion, private_key=None):
    """

    :param onion: encrypted[(address, port):rest_of_onion]
    :param private_key: if None, no need to decrypt before processing, else, decrypt with private_key
    :return:
    """
    if private_key is not None:
        onion = decrypt(onion, private_key)

    pos = 0
    for i in range(len(onion)):
        # 58 = utf8 of :
        if onion[i] == 58:
            pos = i
            break

    next_address, next_onion = None, b''
    if pos != 0:
        next_address = eval(onion[:pos])
        next_onion = onion[(pos + 1):]
    else:
        next_onion = onion

    return next_address, next_onion


def request_key(address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(address)

            sock.send(pickle.dumps("public_key"))
            new_public_key = sock.recv(2048)
            new_public_key = pickle.loads(new_public_key)
    except socket.error:
        return 1

    return new_public_key


def send_encrypted_packet(self, packet, public_key):
    """
    Add the path composed of IP addresses of at least 3 nodes and encrypt them with
    the corresponding public keys and sends it to the first node.
    :return:
    """
    self.define_path()
    packet = bytes(packet, 'utf-8')
    encrypted_packet = encrypt(packet, public_key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # sock.bind((self.address[0], self.address[1] + 2))
        sock.connect(self.path[0][0])
        sock.send(pickle.dumps(encrypted_packet))
