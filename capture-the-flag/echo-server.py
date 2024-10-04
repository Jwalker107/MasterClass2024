# echo-server.py
# https://realpython.com/python-sockets/
import socket

#HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
HOST = "0.0.0.0"  # Standard loopback interface address (localhost)
PORT = 2080  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    # This loop allows us to accept a new connection after each client connection closes
    # Without the while loop, the script terminates after the first client completes.
    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)
                