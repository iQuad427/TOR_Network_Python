import socket
import sys
import pickle

import rsa

host = "127.0.0.1"
port = 4000

# Each tuple of address is compose of (IP address, port number, is_exit_node)
init_addresses = [("127.0.0.2", 4000, False), ("127.0.0.3", 4000, False), ("127.0.0.4", 4000, True)]

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
        socket.bind((host, port))
        socket.listen()
        connection, address = socket.accept()
        with connection:
            message = connection.recv(2048)
            message = pickle.loads(message)
            print(f"Message received : {message}\n"
                  f"From : ({address[0]}, {address[1]})")
            print(message)
            if type(message) is rsa.PublicKey:
                msg_to_node = pickle.dumps(init_addresses)
                connection.send(msg_to_node)
                print(message)
                node_address = (address[0], address[1], message, False)
                init_addresses.append(node_address)
                print(init_addresses)

