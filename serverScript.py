import socket
import threading

clients = {}  # Dictionary to store connected clients

def handle_client(client_socket, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            broadcast(f"{username}> {message}", client_socket)
        except:
            break

def broadcast(message, sender_socket):
    for client_socket in clients:
        # Send the message to all clients except the sender
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except:
                # Remove the client if unable to send the message
                remove_client(client_socket)

def remove_client(client_socket):
    if client_socket in clients:
        username = clients[client_socket]
        print(f"{username} has left the chat.")
        del clients[client_socket]

def start_server():
    # Create a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server.bind(('your_server_ip', 5555))

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

        # Add the client to the dictionary
        clients[client_socket] = username

        # Create a separate thread to handle the client's messages
        client_thread = threading.Thread(target=handle_client, args=(client_socket, username))
        client_thread.start()

if __name__ == "__main__":
    start_server()
