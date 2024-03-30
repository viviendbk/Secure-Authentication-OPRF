import os
import random
import sys

import requests
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

    print("h_p:", h_p)
    # Generate random scalar
    r = random.randint(1, 100)
    print("r:", r)

    sys.set_int_max_str_digits(100000000)
    # Client sends C = H(P) ** r to server
    C = pow(h_p, r)


    client_private_key, client_public_key = generate_key_pair()

    print("C:", C)
    requestBody = {
        "C": C
    }
    response = requests.post("http://localhost:5000/getR", json=requestBody)
    if response.status_code == 200:
        data = response.json()
        R = int(data["R"])
        global server_public_key
        server_public_key = data["server_public_key"]
        print("R:", R)
        z = pow(r, -1, 2 ** 2048)
        print("z:", z)
        print("R^z:", pow(R, z, 2 ** 2048))  # Use pow() with modulus

        return pow(R, z, 2 ** 2048)
    else:
        print("Error fetching R:", response.text)
        return 0


def encrypt_with_rsa_public_key(message, public_key):
    public_key = public_key.encode()
    public_key = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxb5W3DniI+u7hd/upAlQ\nHL3r4R8yRzX/X38Un3a0l1J6EpehTJ8nt2poiSa5edpqRY92nG2YVXG01hB/ACTb\n+GzMzo9gVtYQhXoSNAqCAtbGd97kI26r3eegjpFKUSiHIln5/qlRXUdcMdvykC/O\neySWRe2aaf1qe0BD7MXLvl2kPADs60OJcBl80iD3vMHmZkabA9mEPqmPDaSA+Zx1\nwymhkB2+FB/jurIpNOriDHPwSWbSOHp0zDvrJ90ohZuI59WwvciyOMpFEICKQL5/\n8NBC7sTJnpq2zgPTYVb2IGqSKdxxW8lMtsTj6cnw6sWkVAJun4b2ckpxlFjxRJOn\nuwIDAQAB\n-----END PUBLIC KEY-----\n'
    # Load the public key
    rsa_public_key = serialization.load_pem_public_key(
        public_key,
    )

    print(message)
    print("aadazdazdazdaz")
    # Encrypt the message
    ciphertext = rsa_public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("2")

    return ciphertext


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
    print("K:", K)
    M = encrypt_with_rsa_public_key(bytes(K), server_public_key)

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
