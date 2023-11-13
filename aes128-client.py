import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def encrypt(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = pad(message)
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


def main():
    # Buat socket TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Sambungkan ke server
    sock.connect(("localhost", 8080))

    # Kunci rahasia yang digunakan untuk enkripsi dan dekripsi
    key = b'secretkey1234567890'[:16]  # Ensure the key is exactly 16 bytes long

    # Kirim data terenkripsi
    data = "This is me, Azzam!"
    encrypted_data = encrypt(data, key)
    sock.sendall(encrypted_data)

    # Terima data terenkripsi
    encrypted_data = sock.recv(1024)
    decrypted_data = decrypt(encrypted_data, key)

    # Cetak data
    print(data)
    print(decrypted_data)

if __name__ == "__main__":
    main()
