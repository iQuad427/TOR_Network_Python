import hashlib
import pickle
import socket
import rsa
from Crypto.Cipher import AES

import tools

# Topology of received messages : username:#request:code

# username : log, password
user_credentials = dict()
public_key, private_key = rsa.newkeys(1024)


def parsing(plaintext_message):
    pos = [None, None]
    number = 0
    for i in range(len(plaintext_message)):
        # 58 = utf8 of :
        if plaintext_message[i] == 58:
            pos[number] = i
            number += 1
            if number == 2:
                break

    if pos[0] is None or pos[1] is None:
        return None, None, None

    user = plaintext_message[:pos[0]].decode('utf-8')
    query = plaintext_message[pos[0]+1:pos[1]].decode('utf-8')
    rest = plaintext_message[pos[1]+1:]

    return user, query, rest


def verif_challenge(user, response):
    password = user_credentials[user][1]
    cipher = AES.new(password, AES.MODE_CTR, nonce=b'1')
    actual = cipher.encrypt(format_challenge(user))

    print("server password :", password)
    print("response :", response)
    print("actual :", actual)

    return response == actual


def format_challenge(user):
    return bytes("new_challenger_" + user, 'utf-8')


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.5", 10000))
    sock.listen()

    print("server started")

    while True:
        conn, addr = sock.accept()

        print("accepted a connection")

        message = conn.recv(2048)
        print(message, message[0])

        # j'ai mis un 0 en début de message quand il ne faut pas le décoder
        # par exemple, une encryption ne peut pas être décodée, ça throw une error
        if message[0] == 49 and message[1] == 58:
            if message.decode('utf-8') == "public_key":
                print("was asked for public_key")
                conn.send(pickle.dumps(public_key))
                conn.close()
        elif message[0] == 48 and message[1] == 58:
            print(message[2:])

        username, request, code = parsing(message[2:])

        print(username, request, code)

        if request == "sign_up":
            print("sign up requested")
            if username not in user_credentials:
                user_credentials[username] = [0, code]
                conn.send("Sign up succeeded".encode('utf-8'))
            else:
                conn.send("Sign up failed".encode('utf-8'))
        elif request == "sign_in":
            print("sign in requested")
            if username in user_credentials and user_credentials[username][0] == 0:
                user_credentials[username][0] = 1
                conn.send("challenge:".encode('utf-8') + format_challenge(username))
            else:
                conn.send("Sign in aborted".encode('utf-8'))
        elif request == "challenge":
            print("challenge answered")
            if username in user_credentials and user_credentials[username][0] == 1:
                print("verifying challenge")
                if verif_challenge(username, code):
                    user_credentials[username][0] = 2
                    conn.send("Authentication succeeded".encode('utf-8'))
                else:
                    conn.send("Authentication failed".encode('utf-8'))

        conn.close()
