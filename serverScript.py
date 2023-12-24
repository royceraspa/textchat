import socket
import threading

clients = {}  # Dictionary to store connected clients
password = "royce"  # Set your desired password here

def handle_client(client_socket, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            formatted_message = f"{username}> {message}"
            print(formatted_message)
            broadcast(formatted_message, client_socket)
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
    server.bind(('10.0.0.171', 5555))  # Allow connections from any IP

    # Listen for incoming connections
    server.listen()

    print("Server is waiting for connections...")

    while True:
        # Accept the connection from a client
        client_socket, client_address = server.accept()
        print(f"Connected to {client_address}")

        # Get the password from the connected client
        entered_password = client_socket.recv(1024).decode('utf-8')

        if entered_password == password:
            # Password is correct, proceed with user authentication

            # Get the username from the connected client
            username = client_socket.recv(1024).decode('utf-8')
            print(f"{username} has joined the chat.")

            # Add the client to the dictionary
            clients[client_socket] = username

            # Send a confirmation message to the client
            client_socket.send("Welcome to the chat!".encode('utf-8'))

            # Create a separate thread to handle the client's messages
            client_thread = threading.Thread(target=handle_client, args=(client_socket, username))
            client_thread.start()
        else:
            # Incorrect password, close the connection
            print("Incorrect password. Closing connection.")
            client_socket.close()

if __name__ == "__main__":
    start_server()
