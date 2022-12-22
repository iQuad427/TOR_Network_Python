import hashlib
import pickle
import socket
import rsa
from Crypto.Cipher import AES
import tools

# Topology of received messages : username:#request:code

STATUS_INDEX = 0
COUNTER_INDEX = 1
PASSWORD_INDEX = 2
PUBLIC_KEY_INDEX = 3

LEN_USER_INFO = 4

DISCONNECTED = 0
SIGNING_IN = 1
CONNECTED = 2

client_address = ("127.0.0.4", 4006)
authentication_server = ("127.0.0.5", 10000)

# username : log, password
user_credentials = dict()


def verif_challenge(username, user_response):
    password = user_credentials[username][PASSWORD_INDEX]
    cipher = AES.new(password, AES.MODE_CTR, nonce=b'1')
    actual = cipher.encrypt(format_challenge(username))

    return user_response == actual


def format_challenge(username, to_encode=True):
    """
    Creates a formatted challenge from the username that is getting challenged

    :param username: the username getting challenged
    :param to_encode: whether the output should be bytes or a string

    :return: return a formatted challenge for the user given as argument
    """
    formatted = f"new_challenger_{username}_{str(user_credentials[username][1])}"
    return formatted.encode('utf-8') if to_encode else formatted


if __name__ == '__main__':
    public_key, private_key = rsa.newkeys(1024)

    # Open a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(authentication_server)
    sock.listen()

    while True:
        conn, addr = sock.accept()

        message = conn.recv(2048)

        # message expected 0:username:request:content when not encrypted
        if message[1] != b':'[0]:
            # if not expected message, it has been encrypted
            message = tools.decrypt(message, private_key)

        if message[1] != b':'[0]:
            conn.close()
            break

        user, query, content, signature, raw_message = tools.parsing(message)

        verified_user = False
        if user in user_credentials and type(user_credentials[user][PUBLIC_KEY_INDEX]) is rsa.PublicKey:
            client_public_key = user_credentials[user][PUBLIC_KEY_INDEX]
            try:
                verified_user = (rsa.verify(raw_message, signature, client_public_key) == 'SHA-256')
            except rsa.VerificationError:
                verified_user = False

        if user is None:
            conn.send(tools.format_message("server", "log", "Error : Message badly formed"))

        if query == "public_key":
            conn.send(pickle.dumps(public_key))

        elif query == "sign_up":
            if user not in user_credentials:
                user_credentials[user] = [0] * LEN_USER_INFO
                user_credentials[user][PASSWORD_INDEX] = content
                conn.send(tools.format_message("server", "log", "Log : sign up succeeded"))
            else:
                conn.send(tools.format_message("server", "log", "Error : sign up failed"))

        elif query == "sign_in":
            if user in user_credentials:
                user_credentials[user][STATUS_INDEX] = SIGNING_IN
                user_credentials[user][PUBLIC_KEY_INDEX] = content
                user_credentials[user][COUNTER_INDEX] += 1
                conn.send(tools.format_message("server", "challenge", format_challenge(user, False)))
            else:
                conn.send(tools.format_message("server", "log", "Error : sign in aborted"))

        elif query == "challenge":
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == SIGNING_IN:
                if verif_challenge(user, content):
                    user_credentials[user][STATUS_INDEX] = CONNECTED
                    conn.send(tools.encrypt(
                        tools.format_message("server", "log", "Log : authentication succeeded"),
                        user_credentials[user][PUBLIC_KEY_INDEX])
                    )
                else:
                    conn.send(tools.format_message("server", "log", "Error : authentication failed"))

        elif query == "do_stuff":
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == CONNECTED and verified_user:
                conn.send(tools.encrypt(
                    tools.format_message("server", "log", "We are doing stuff together"),
                    user_credentials[user][PUBLIC_KEY_INDEX])
                )
            else:
                conn.send(tools.format_message("server", "log", "I won't do stuff with you"))

        elif query == "disconnect":
            if user_credentials[user][STATUS_INDEX] == CONNECTED and verified_user:
                user_credentials[user][STATUS_INDEX] = DISCONNECTED
                conn.send(tools.format_message("server", "log", "Log : disconnected from server"))
            else:
                if not verified_user:
                    conn.send(tools.format_message("server", "log", "Error : access denied"))

        conn.close()
