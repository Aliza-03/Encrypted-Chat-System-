import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

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

# Client setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

while True:
    response = client_socket.recv(1024).decode()
    print(response)
    option = input().strip().lower()
    client_socket.send(option.encode())
    
    
    if option == "register":
        username = input("Enter a username: ")
        client_socket.send(username.encode())
        
        email = input("Enter your email: ")
        client_socket.send(email.encode())  # Send email to server

        password = input("Enter a password: ")
        client_socket.send(password.encode())
        
        response = client_socket.recv(1024).decode()
        print(response)
    
    elif option == "login":
        # Diffie-Hellman Key Exchange for Login
        p = 23
        g = 5
        client_private_key = secrets.randbelow(p)
        client_public_key = pow(g, client_private_key, p)

        # Receive server's public key
        server_public_key = int(client_socket.recv(1024).decode())
        client_socket.send(str(client_public_key).encode())
        
        shared_secret = pow(server_public_key, client_private_key, p)
        shared_secret_key = hashlib.sha256(str(shared_secret).encode()).digest()

        # Encrypt and send login credentials
        username = input("Enter username: ")
        password = input("Enter password: ")
        credentials = f"{username} {password}"
        encrypted_credentials = encrypt_message(shared_secret_key, credentials)
        client_socket.send(encrypted_credentials)

        # Receive server response
        response = client_socket.recv(1024).decode()
        print(response)
        if "Login successful" in response:
                # Communication loop
            while True:
                # Input message from the user to send to the server
                message_to_send = input("Enter a message to send to the server (or 'exit' to quit): ")
                
                if message_to_send.lower() == "exit":
                    encrypted_message = encrypt_message(shared_secret_key, "exit")
                    client_socket.send(encrypted_message)  # Send encrypted 'exit' message to server
                    print("Exiting the communication loop.")
                    break
                
                # Encrypt message to send to server
                encrypted_message = encrypt_message(shared_secret_key, message_to_send)
                client_socket.send(encrypted_message)  # Send encrypted message to server
                
                # Receive and decrypt response message from server
                encrypted_response = client_socket.recv(1024)
                decrypted_response = decrypt_message(shared_secret_key, encrypted_response)
                print(f"Decrypted response from server: {decrypted_response}")

            # Close the connection
            client_socket.close()
    
    elif option == "exit":
        client_socket.send(b"Exiting...")
        break

client_socket.close()
