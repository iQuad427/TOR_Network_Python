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

DISCONNECTED = 0
SIGNING_IN = 1
CONNECTED = 2

client_address = ("127.0.0.4", 4006)

# username : log, password
user_credentials = dict()
public_key, private_key = rsa.newkeys(1024)


def verif_challenge(username, user_response):
    password = user_credentials[username][PASSWORD_INDEX]
    cipher = AES.new(password, AES.MODE_CTR, nonce=b'1')
    actual = cipher.encrypt(format_challenge(username))

    print("response :", user_response)
    print("actual :", actual)

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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.5", 10000))
    sock.listen()

    print("server started")

    while True:
        conn, addr = sock.accept()

        print("accepted a connection")

        message = conn.recv(2048)

        user, query, content = tools.parsing(message)

        print(user, query, content)

        if user is None:
            conn.send(tools.format_message("server", "log", "Error : Message badly formed"))

        if query == "public_key":
            print("was asked for public_key")
            conn.send(pickle.dumps(public_key))
            print("sent public_key")
        elif query == "sign_up":
            print("sign up requested")
            if user not in user_credentials:
                user_credentials[user] = [0, 0, content]
                conn.send(tools.format_message("server", "log", "Log : sign up succeeded"))
            else:
                conn.send(tools.format_message("server", "log", "Error : sign up failed"))
        elif query == "sign_in":
            print("sign in requested")
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == DISCONNECTED:
                user_credentials[user][STATUS_INDEX] = 1
                user_credentials[user][COUNTER_INDEX] += 1
                conn.send(tools.format_message("server", "challenge", format_challenge(user, False)))
                print("challenge sent")
            else:
                conn.send(tools.format_message("server", "log", "Error : sign in aborted"))
        elif query == "challenge":
            print("challenge answered")
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == SIGNING_IN:
                print("verifying challenge")
                if verif_challenge(user, content):
                    user_credentials[user][STATUS_INDEX] = CONNECTED
                    conn.send(tools.format_message("server", "log", "Log : authentication succeeded"))
                else:
                    conn.send(tools.format_message("server", "log", "Error : authentication failed"))
        elif query == "disconnect":
            print(f"disconnection requested from user : {user}")
            if user_credentials[user][STATUS_INDEX] == CONNECTED:
                user_credentials[user][STATUS_INDEX] = DISCONNECTED
                conn.send(tools.format_message("server", "log", "Log : disconnected from server"))

        conn.close()
