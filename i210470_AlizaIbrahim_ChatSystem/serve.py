import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Encryption and Decryption Functions
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

# Diffie-Hellman Parameters
p = 23  
g = 5   

# Server's private and public keys
server_private_key = secrets.randbelow(p)
server_public_key = pow(g, server_private_key, p)

# File to store user credentials
USER_CREDENTIALS_FILE = "creds.txt"

# Server Setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server is waiting for a connection...")

client_socket, addr = server_socket.accept()
print(f"Connected by {addr}")

try:
    client_socket.send(b"Enter 'register' to create an account or 'login' to authenticate: ")
    
    while True:
        option = client_socket.recv(1024).decode().strip().lower()
        
        if option == "register":
            username = client_socket.recv(1024).decode().strip()
            email = client_socket.recv(1024).decode().strip() 
            password = client_socket.recv(1024).decode().strip()
                
            # Hash the password for storage
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
                
             
            with open(USER_CREDENTIALS_FILE, "a") as file:
                    file.write(f"{username} {email} {hashed_password}\n")  

            client_socket.send(b"Registration successful. You can now log in.\n")
            client_socket.send(b"Enter 'register' to create an account or 'login' to authenticate: ")

        elif option == "login":
            # Send server's public key to client for Diffie-Hellman exchange
            client_socket.send(str(server_public_key).encode())

            # Receive client's public key
            client_public_key = int(client_socket.recv(1024).decode())
            shared_secret = pow(client_public_key, server_private_key, p)
            shared_secret_key = hashlib.sha256(str(shared_secret).encode()).digest()

            # Receive and decrypt credentials
            encrypted_credentials = client_socket.recv(1024)
            credentials = decrypt_message(shared_secret_key, encrypted_credentials)
            username, password = credentials.split()

              # Validate login credentials
            login_success = False
            with open(USER_CREDENTIALS_FILE, "r") as file:
                for line in file:
                    stored_username, stored_email, stored_hashed_password = line.strip().split()
                    if username == stored_username and stored_hashed_password == hashlib.sha256(password.encode()).hexdigest():
                        login_success = True
                        break

            if login_success:
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

finally:
    client_socket.close()
    server_socket.close()
    print("Server closed.")
