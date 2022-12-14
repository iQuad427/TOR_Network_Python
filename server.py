import socket
import sys
import pickle

import rsa

host = "127.0.0.1"
port = 4000

# Dictionary (ip_address, port_number): (public_key, is_exit_node)
addresses_table = {
    ("127.0.0.1", 4000): ("tor_server", False),
    ("127.0.0.1", 4001): ("west_server", False),
    ("127.0.0.1", 4002): ("north_node", False),
    ("127.0.0.1", 4003): ("east_node", False),
    ("127.0.0.1", 4004): ("south_node", False),
}

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
        socket.bind((host, port))
        socket.listen()
        while True:
            connection, address = socket.accept()
            with connection:
                message = connection.recv(2048)
                message = pickle.loads(message)
                print(f"Message received : {message}\n"
                      f"From : ({address[0]}, {address[1]})")
                print(message)
                if type(message) is rsa.PublicKey:
                    msg_to_node = pickle.dumps(addresses_table)
                    connection.send(msg_to_node)
                    node_address = (address[0], address[1], message, False)
                    addresses_table[(address[0], address[1])] = (message, False)
                    print(addresses_table)

