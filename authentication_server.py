import hashlib
import pickle
import random
import socket

import rsa


# Create a socket to listen for incoming connections
import tools

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.1.1.1", 4000))
sock.listen(1)
dict_credentials = dict()
public_key, private_key = rsa.newkeys(1024)
while True:
    # Accept an incoming connection
    conn, addr = sock.accept()
    print("Received connection from", addr)

    # Receive the response from the client
    conn.recv(2048)
    conn.send(pickle.dumps(public_key))
    response = conn.recv(2048)
    response = response.decode()
    conn.send("Username".encode())
    username = conn.recv(2048)

    conn.send("Password".encode())
    password = hashlib.sha256(tools.decrypt(conn.recv(2048), private_key)).hexdigest()
    print(response)
    print(username)
    print(password)
    if response == "Signup":
        conn.send("Password".encode())
        password_confirmation = hashlib.sha256(tools.decrypt(conn.recv(2048), private_key)).hexdigest()
        print(password_confirmation)
        if password == password_confirmation:
            dict_credentials[username] = password
            conn.send("Successfully signed up".encode())
    elif response == "Signin":
        if username not in dict_credentials.keys():
            conn.send("Login failed; Invalid user ID or password".encode())
        elif password != dict_credentials[username]:
            conn.send("Login failed; Invalid user ID or password".encode())
        else:
            conn.send("Successfully connected".encode())
    conn.close()
