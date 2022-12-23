import pickle
import socket
import rsa
import time
from Crypto.Cipher import AES
import tools
from tools import BColors

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

# username : status, counter, password, public_key
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


def launch_server():
    print(f"{BColors.WARNING}{BColors.BOLD}Starting Authentication Server...{BColors.ENDC}")
    public_key, private_key = rsa.newkeys(1024)

    # Open a socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(authentication_server)
        sock.listen()
    except OSError:
        print(f"{BColors.FAIL}Failed to launch the server, wait a moment and try again{BColors.ENDC}")
        return 1

    print(f"{BColors.OKGREEN}Launch successful{BColors.ENDC}")
    print(f"{BColors.BOLD}{BColors.UNDERLINE}Server Logs{BColors.ENDC} :")
    while True:
        conn, addr = sock.accept()
        timestamp = time.strftime("%H:%M:%S", time.localtime())

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
            conn.send(tools.format_message("server", "log", "Error : Message badly formed", private_key=private_key))

        if query == "public_key":
            conn.send(
                tools.format_message("server", "public_key", public_key, encoding=2)
            )
            print(f"[{timestamp}]: Sent server public key to {user}")

        elif query == "sign_up":
            if user not in user_credentials:
                user_credentials[user] = [0] * LEN_USER_INFO
                user_credentials[user][PASSWORD_INDEX] = content
                conn.send(tools.format_message("server", "log", "Log : sign up succeeded", private_key=private_key))
                print(f"[{timestamp}]: \"{user}\" signed up")
            else:
                conn.send(tools.format_message("server", "log", "Error : sign up failed", private_key=private_key))
                print(f"[{timestamp}]: \"{user}\" failed to sign up")

        elif query == "sign_in":
            if user in user_credentials:
                user_credentials[user][STATUS_INDEX] = SIGNING_IN
                user_credentials[user][PUBLIC_KEY_INDEX] = content
                user_credentials[user][COUNTER_INDEX] += 1
                conn.send(
                    tools.format_message("server", "challenge", format_challenge(user, False), private_key=private_key)
                )
                print(f"[{timestamp}]: sent a challenge to \"{user}\"")
            else:
                conn.send(tools.format_message("server", "log", "Error : sign in aborted", private_key=private_key))
                print(f"[{timestamp}]: log in of \"{user}\" was aborted")

        elif query == "challenge":
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == SIGNING_IN:
                if verif_challenge(user, content):
                    user_credentials[user][STATUS_INDEX] = CONNECTED
                    conn.send(tools.encrypt(
                        tools.format_message("server", "log", "Log : authentication succeeded", private_key=private_key),
                        user_credentials[user][PUBLIC_KEY_INDEX])
                    )
                    print(f"[{timestamp}]: \"{user}\" as logged in successfully")
                else:
                    conn.send(
                        tools.format_message("server", "log", "Error : authentication failed", private_key=private_key)
                    )
                    print(f"[{timestamp}]: \"{user}\" failed to log in")

        elif query == "do_stuff":
            if user in user_credentials and user_credentials[user][STATUS_INDEX] == CONNECTED and verified_user:
                conn.send(tools.encrypt(
                    tools.format_message("server", "log", "We are doing stuff together", private_key=private_key),
                    user_credentials[user][PUBLIC_KEY_INDEX])
                )
                print(f"[{timestamp}]: \"{user}\" is playing with the server")
            else:
                conn.send(tools.format_message("server", "log", "I won't do stuff with you", private_key=private_key))
                print(f"[{timestamp}]: server refused to play with \"{user}\"")

        elif query == "disconnect":
            if user_credentials[user][STATUS_INDEX] == CONNECTED and verified_user:
                user_credentials[user][STATUS_INDEX] = DISCONNECTED
                conn.send(
                    tools.format_message("server", "log", "Log : disconnected from server", private_key=private_key)
                )
                print(f"[{timestamp}]: \"{user}\" disconnected from server")
            else:
                if not verified_user:
                    conn.send(tools.format_message("server", "log", "Error : access denied", private_key=private_key))
                    print(f"[{timestamp}]: access was denied to \"{user}\"")

        conn.close()


if __name__ == '__main__':
    launch_server()
