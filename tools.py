import copy
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import rsa
import pickle
import socket


class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def format_message(username, query, content, private_key=None, encoding=1):
    """
    Creates a formatted challenge from the username that is getting challenged

    :param private_key: used to tag the message
    :param username: the username of the user getting challenged
    :param query: the request made to the server
    :param content: the content required by the server to compute the request
    :param encoding:
        0 - do nothing
        1 - encode (utf-8)
        2 - pickle.dumps

    :return: a formatted byte string representing the whole query made to the server
    """

    prefix = f"{encoding}:".encode('utf-8')
    message = f"{username}:{query}:".encode('utf-8')
    if encoding:
        if encoding == 1:
            message += content.encode('utf-8')
        elif encoding == 2:
            message += pickle.dumps(content)
    else:
        message += content

    tag = b""
    if private_key is not None:
        tag = rsa.sign(message, private_key, 'SHA-256')

    if len(tag) < 128:
        padding = (128 - len(tag)) * "0"
        tag = tag + bytes(padding, 'utf-8')

    return prefix + tag + b':' + message


def decode_message(message, delim, decoding):
    content = message[delim[1] + 1:]
    # If the content is encoded, decode the content based on the value of decoding
    if decoding:
        if decoding == 1:
            content = content.decode('utf-8')
        elif decoding == 2:
            content = pickle.loads(content)

    return message[:delim[0]].decode('utf-8'), message[delim[0] + 1:delim[1]].decode('utf-8'), content


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
    if argv[1] != b':'[0]:
        return None, None, None, None, None

    encoding = argv[0] - 48  # 48 is the value of 0 in ASCII -> returns an int corresponding to the string value
    argv = argv[2:]

    tag = argv[:128]
    argv = argv[129:]

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
        return None, None, None, None, None

    user, query, content = decode_message(argv, pos, encoding)
    return user, query, content, tag, argv


def format_send_to(address, message):
    """
    Encode the address with utf-8 and prepend it to the message, separated by ':send:'
    """
    return f"{address}:send:".encode('utf-8') + message


def hash_password(password):
    """
    Return Hashed password with SHA256
    """
    return hashlib.sha256(password.encode()).hexdigest().encode()[:32]


def generate_onion(message, node_path):
    # Create a deep copy of the node_path and reverse it
    packaging_order = copy.deepcopy(node_path)
    packaging_order.reverse()

    onion = [message]

    # Iterate through the packaging_order and add the hop to the beginning of the onion
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
    encrypted_packet = packet
    for node in path[::-1]:
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


def request_from_node(address, request):
    """
    Try to connect to the node at the given address and send the request
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(address)
            # Send the request as a pickled object
            sock.send(pickle.dumps(request))
            # Receive the response from the node and un-pickle it
            res = sock.recv(4096)
            res = pickle.loads(res)
    # If the connection is refused, return None
    except ConnectionRefusedError:
        return None

    return res


def sign(packet, private_key):
    """
    Sign using RSA private key and SHA256
    """
    return rsa.sign(packet, private_key, 'SHA-256') + packet


def verify_sign(packet, public_key):
    """
    Verify using RSA public key
    """
    return rsa.verify(packet[128:], packet[:128], public_key)


def verify_sign_path(packet, path):
    """
    Verify the signature on a packet as it travels through a path of nodes.
    If any node's signature is invalid, return None. Otherwise, return the packet
    with all the signatures stripped off.
    :param packet: the packet with the signatures to verify
    :param path: a list of tuples representing the nodes in the path.
    """
    verified_packet = packet
    for node in path[:-1]:  # last of path is the exit node (no signature)
        if verify_sign(verified_packet, node[1][0]):
            verified_packet = verified_packet[128:]
        else:
            return None
    return verified_packet
