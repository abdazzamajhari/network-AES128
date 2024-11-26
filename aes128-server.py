import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message.encode())
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    except ValueError:
        return data  # If unpadding fails, return data without unpadding

def decrypt(ciphertext, key):
    # Ensure the key is exactly 16 bytes long
    key = key[:16]

    # Pad the key if needed (for example, if it's less than 16 bytes)
    key = key.ljust(16, b'\0')

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadded_data = unpad(decrypted_data)

    try:
        return unpadded_data.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_data.hex()  # Return hex representation if decoding fails


# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
server_socket.bind(('192.168.118.237', 8080))

# Listen for incoming connections
server_socket.listen(5)

print("Server is listening for connections...")

while True:
    # Accept a connection from a client
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    # Receive encrypted data from the client
    encrypted_data = client_socket.recv(1024)
    print(encrypted_data)
    decrypted_data = decrypt(encrypted_data, b'ifyoucanseeyousee')

    # Print decrypted data
    print(decrypted_data)

    # Close the client socket
    client_socket.close()
