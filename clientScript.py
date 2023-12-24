import socket
import threading

def receive_messages(client_socket, username):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            print(message)
        except:
            break

def start_client():
    # Get user input for username
    username = input("Enter your username: ")

    # Create a socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client.connect(('10.0.0.171', 5555))

    # Send the username to the server
    client.send(username.encode('utf-8'))

    # Create a separate thread to receive messages
    receive_thread = threading.Thread(target=receive_messages, args=(client, username))
    receive_thread.start()

    while True:
        # Get user input and send messages
        message = input(f"{username}> ")
        if message.lower() == 'exit':
            break
        client.send(message.encode('utf-8'))

    # Close the connection
    client.close()

if __name__ == "__main__":
    start_client()
