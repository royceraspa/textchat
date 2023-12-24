import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def receive_messages(client_socket, private_key):
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

            print(decrypted_message)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def start_client():
    # Get user input for username and password
    username = input("Enter your username: ")
    password = input("Enter the server password: ")

    # Create a socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client.connect(('your_server_ip', 5555))

    # Send the password to the server
    client.send(password.encode('utf-8'))

    # Receive the server's public key
    server_public_key_bytes = client.recv(1024)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )

    # Generate an RSA key pair for encryption/decryption
    client_private_key, client_public_key = generate_key_pair()

    # Send the client's public key to the server
    client.send(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Receive the server's confirmation message
    confirmation_message = client.recv(1024)
    print(decrypt_message(confirmation_message, client_private_key))

    # Create a separate thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(client, client_private_key))
    receive_thread.start()

    while True:
        # Get user input and send messages
        message = input()
        if message.lower() == 'exit':
            break

        # Encrypt the message using the server's public key
        encrypted_message = server_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.S
