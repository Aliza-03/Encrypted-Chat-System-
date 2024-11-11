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

# Diffie-Hellman parameters (must match the server’s values)
p = 23
g = 5

# Client's private and public keys
client_private_key = secrets.randbelow(p)
client_public_key = pow(g, client_private_key, p)

# Set up client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Receive the server's public key
server_public_key = int(client_socket.recv(1024).decode())

# Send the client's public key to the server
client_socket.send(str(client_public_key).encode())

# Compute the shared secret
shared_secret = pow(server_public_key, client_private_key, p)
shared_secret_key = hashlib.sha256(str(shared_secret).encode()).digest()

# Registration or Login loop
while True:
    option = input("Enter 'register' to create an account, 'login' to authenticate, or 'exit' to quit: ").strip().lower()
    client_socket.send(option.encode())

    if option == "register":
        username = input("Enter a username: ")
        client_socket.send(username.encode())
        password = input("Enter a password: ")
        client_socket.send(password.encode())

        response = client_socket.recv(1024).decode()
        print(response)



    elif option == "login":
        username = input("Enter your username: ")
        client_socket.send(username.encode())
        password = input("Enter your password: ")
        client_socket.send(password.encode())

        response = client_socket.recv(1024).decode()
        print(response)


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
        client_socket.send(b"exit")
        print("Exiting...")
        break

# Close connection
client_socket.close()



