import socket
import threading

def handle_client(client_socket, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(f"{username}> {message}")
        except:
            break

def start_server():
    # Create a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server.bind(('10.0.0.171', 5555))

    # Listen for incoming connections
    server.listen()

    print("Server is waiting for connections...")

    while True:
        # Accept the connection from a client
        client_socket, client_address = server.accept()
        print(f"Connected to {client_address}")

        # Get the username from the connected client
        username = client_socket.recv(1024).decode('utf-8')
        print(f"{username} has joined the chat.")

        # Create a separate thread to handle the client's messages
        client_thread = threading.Thread(target=handle_client, args=(client_socket, username))
        client_thread.start()

if __name__ == "__main__":
    start_server()
