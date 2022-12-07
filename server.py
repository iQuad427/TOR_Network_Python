import socket
import sys

host = "127.0.0.1"
port = 4000

if __name__ == '__main__':
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket:
        socket.bind((host, port))
        socket.listen()
        connection, address = socket.accept()
        with connection:
            message = connection.recv(1024)
            message = message.decode()
            print(f"Message received : {message}\n"
                  f"From : ({address[0]}, {address[1]})")

            connection.send("127.0.0.2".encode())
