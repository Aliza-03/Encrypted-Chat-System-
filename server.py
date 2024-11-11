import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to encrypt and decrypt messages (AES)
def encrypt_message(shared_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(shared_key, iv_ciphertext):
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Diffie-Hellman parameters
p = 23  
g = 5   

# Server's private and public keys
server_private_key = secrets.randbelow(p)
server_public_key = pow(g, server_private_key, p)

# Files for storing user and admin credentials
USER_CREDENTIALS_FILE = "user_credentials.txt"
ADMIN_CREDENTIALS_FILE = "admin_credentials.txt"

# Function to store user credentials (username, hashed password)
def store_credentials(username, password, is_admin=False):
    filename = ADMIN_CREDENTIALS_FILE if is_admin else USER_CREDENTIALS_FILE
    with open(filename, "a") as file:
        file.write(f"{username} {password}\n")

# Function to validate user login
def validate_login(username, password, is_admin=False):
    filename = ADMIN_CREDENTIALS_FILE if is_admin else USER_CREDENTIALS_FILE
    try:
        with open(filename, "r") as file:
            for line in file:
                stored_username, stored_hashed_password = line.strip().split()
                if username == stored_username and stored_hashed_password == password:
                    return True
        return False
    except FileNotFoundError:
        return False

# Function for initial admin login check before server setup
def admin_login():
    print("Admin login required to start the server.")
    username = input("Admin username: ")
    password = input("Admin password: ")

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if validate_login(username, hashed_password, is_admin=True):
        print("Admin login successful. Starting the server...")
        return True
    else:
        print("Admin login failed. Exiting.")
        return False

# Perform initial admin login check


# Set up server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server is waiting for a connection...")

client_socket, addr = server_socket.accept()
print(f"Connected by {addr}")

# Send the server's public key to the client
client_socket.send(str(server_public_key).encode())

# Receive the client's public key
client_public_key = int(client_socket.recv(1024).decode())

# Compute shared secret
shared_secret = pow(client_public_key, server_private_key, p)
shared_secret_key = hashlib.sha256(str(shared_secret).encode()).digest()

# Registration or login loop for clients
while True:
    client_socket.send(b"Enter 'register' to create an account or 'login' to authenticate: ")
    option = client_socket.recv(1024).decode().strip().lower()

    if option == "register":
        client_socket.send(b"Enter a username: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"Enter a password: ")
        password = client_socket.recv(1024).decode().strip()

        # Hash the password for storage
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Store the credentials
        store_credentials(username, hashed_password)

        client_socket.send(b"Registration successful. You can now log in.\n")

    elif option == "login":
        client_socket.send(b"Enter your username: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"Enter your password: ")
        password = client_socket.recv(1024).decode().strip()

        # Validate login
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if validate_login(username, hashed_password):
            client_socket.send(b"Login successful.\n")

            # Communication loop
            while True:
                encrypted_message = client_socket.recv(1024)  # Receive encrypted message from client
                if not encrypted_message:
                    break  # Break the loop if the client disconnects
                
                decrypted_message = decrypt_message(shared_secret_key, encrypted_message)
                print(f"Decrypted message from client: {decrypted_message}")
                
                if decrypted_message.lower() == "exit":
                    print("Exiting the communication loop.")
                    break
                
                response_message = input("Enter a response (or 'exit' to quit): ")
                
                if response_message.lower() == "exit":
                    encrypted_response = encrypt_message(shared_secret_key, "exit")
                    client_socket.send(encrypted_response)
                    print("Exiting the communication loop.")
                    break

                encrypted_response = encrypt_message(shared_secret_key, response_message)
                client_socket.send(encrypted_response)

            # Close connections
            client_socket.close()
            server_socket.close()
        else:
            client_socket.send(b"Login failed. Incorrect username or password.\n")

    elif option == "exit":
        client_socket.send(b"Exiting...\n")
        break

# Close connection
client_socket.close()
server_socket.close()
