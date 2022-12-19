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
    for i in range(len(message)):
        # 58 = utf8 of :
        if message[i] == 58:
            pos[number] = i
            number += 1
            if number == 2:
                break

    if pos[0] is None or pos[1] is None:
        return None, None, None

    user = message[:pos[0]].decode('utf-8')
    query = message[pos[0]+1:pos[1]].decode('utf-8')
    rest = message[pos[1]+1:]

    return user, query, rest


def verif_challenge(user, response):
    password = user_credentials[user][1]
    cipher = AES.new(password, AES.MODE_CTR, nonce=b'1')
    actual = cipher.encrypt(format_challenge(user))

    return response == actual


def format_challenge(user):
    return bytes("new_challenger_" + user, 'utf-8')


if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.5", 10000))

    while True:
        conn, addr = sock.accept()

        message = sock.recv(2048)
        if message.decode('utf-8') == "public_key":
            conn.send(pickle.dumps(public_key))
            conn.close()
            break

        username, request, code = parsing(tools.decrypt(message, private_key))

        if request == "sign_up":
            if username not in user_credentials:
                user_credentials[username] = [0, code]
        elif request == "sign_in":
            if username in user_credentials and user_credentials[username][0] == 0:
                user_credentials[username][0] = 1
                sock.send(format_challenge(username))
        elif request == "challenge":
            if username in user_credentials and user_credentials[username][0] == 1:
                if verif_challenge(username, code):
                    sock.send("Authentication succeeded")
                else:
                    sock.send("Authentication failed")

        conn.close()
