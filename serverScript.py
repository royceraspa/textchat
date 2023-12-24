import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

clients = {}  # Dictionary to store connected clients
password = "your_password"  # Set your desired password here

def handle_client(client_socket, username, private_key):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the received message
            decrypted_message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')

            formatted_message = f"{username}> {decrypted_message}"
            print(formatted_message)
            broadcast(formatted_message, client_socket)
        except Exception as e:
            print(f"Error handling client: {e}")
            break

def broadcast(message, sender_socket):
    for client_socket in clients:
        # Send the message to all clients except the sender
        if client_socket != sender_socket:
            try:
                # Encrypt the message for each client
                client_socket.send(encrypt_message(message, clients[client_socket]))
            except:
                # Remove the client if unable to send the message
                remove_client(client_socket)

def remove_client(client_socket):
    if client_socket in clients:
        username = clients[client_socket]
        print(f"{username} has left the chat.")
        del clients[client_socket]

def generate_key_pair():
    # Generate an RSA key pair for encryption/decryption
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key for sharing with clients
    public_key = private_key.public_key()

    return private_key, public_key

def start_server():
    # Create a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server.bind(('0.0.0.0', 5555))  # Allow connections from any IP

    # Listen for incoming connections
    server.listen()

    print("Server is waiting for connections...")

    # Generate a key pair for the server
    server_private_key, server_public_key = generate_key_pair()

    while True:
        # Accept the connection from a client
        client_socket, client_address = server.accept()
        print(f"Connected to {client_address}")

        # Get the password from the connected client
        entered_password = client_socket.recv(1024).decode('utf-8')

        if entered_password == password:
            # Password is correct, proceed with user authentication

            # Send the server's public key to the client
            client_socket.send(server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            # Receive the client's public key
            client_public_key_bytes = client_socket.recv(1024)
            client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes,
                backend=default_backend()
            )

            # Get the username from the connected client
            username = client_socket.recv(1024).decode('utf-8')
            print(f"{username} has joined the chat.")

            # Add the client and its public key to the dictionary
            clients[client_socket] = client_public_key

            # Send a confirmation message to the client
            client_socket.send(encrypt_message("Welcome to the chat!", client_public_key))

            # Create a separate thread to handle the client's messages
            client_thread = threading.Thread(target=handle_client, args=(client_socket, username, server_private_key))
            client_thread.start()
        else:
            # Incorrect password, close the connection
            print("Incorrect password. Closing connection.")
            client_socket.close()

if __name__ == "__main__":
    start_server()
