import socket
import time

host = "127.0.0.1"
port = 5000

def client_program():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # instantiate
    client_socket.bind(("127.0.0.8", 4006))
    client_socket.connect((host, port))  # connect to the server

    #message = input(" -> ")  # take input


    client_socket.send("Bonsoir".encode())  # send message
        # data = client_socket.recv(1024).decode()  # receive response
        #
        # print('Received from server: ' + data)  # show in terminal

        #message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()