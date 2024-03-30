import base64

from flask import Flask, request
import os
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

server_public_key = None
client_public_key = None
client_private_key = None


def generate_key_pair():
    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def compute_h(p, q):
    s = int.from_bytes(p.encode(), byteorder='big')  # Convert string P to integer
    s = s % (q - 2) + 2  # Ensure s is in the range [2, q]
    return pow(s, 2, 2 * q + 1)  # Compute H(P) = s^2 mod (2q + 1)


def get_K(client_password, q):
    # Convert password to integer in range [2, q]
    h_p = compute_h(client_password, q)

    # Generate random scalar
    r = int.from_bytes(os.urandom(32), byteorder='big')

    # Client sends C = H(P) ** r to server
    C = pow(h_p, r, q)

    client_private_key, client_public_key = generate_key_pair()

    requestBody = {
        "C": C
    }
    response = requests.post("http://localhost:5000/getR", json=requestBody)
    if response.status_code == 200:
        data = response.json()
        R = int(data["R"])
        global server_public_key
        server_public_key = data["server_public_key"]

        z = pow(r, q - 2, q)  # Efficient modular inverse
        return R ** z
    else:
        print("Error fetching R:", response.text)
        return 0


def encrypt_with_rsa_public_key(message, public_key):
    public_key = public_key.encode()
    # Load the public key
    rsa_public_key = serialization.load_pem_public_key(
        public_key,
    )

    # Encrypt the message
    ciphertext = rsa_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def decrypt_with_rsa_private_key(ciphertext, private_key):
    # Load the private key
    rsa_private_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )

    # Decrypt the ciphertext
    plaintext = rsa_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


def login():
    email = input("Enter your email: ")
    client_password = input("Enter your password: ")
    q = 2 ** 2048
    K = get_K(client_password, q)
    # shared_key = diffie_hellman_bob(client_private_key, K, q, 2)

    print("Logging in with email:", email)


def create_user():
    email = input("Enter your email: ")
    client_password = input("Enter your password: ")
    q = 2 ** 2048
    K = get_K(client_password, q)
    M = encrypt_with_rsa_public_key(K, server_public_key)

    requestBody = {
        "email": email,
        "M": M
    }

    response = requests.post("localhost:5000/users", json=requestBody)
    if response.status_code == 200:
        return response.json()
    else:
        print("Error creating user:", response.text)
        return None
    print("Creating user with email:", email)


def main():
    print("Welcome!")
    while True:
        choice = input("Enter 'login' to log in or 'create' to create a new user account: ").strip().lower()
        if choice == 'login':
            login()
            break
        elif choice == 'create':
            create_user()
            break
        else:
            print("Invalid choice. Please enter 'login' or 'create'.")


if __name__ == "__main__":
    main()
