import os
import random
import sys
sys.path.append("../")
import requests
from crypto_utils import p, q


def compute_h(password):
    s = int.from_bytes(password.encode(), "big")
    return pow(s, 2, p)


def get_K(email, client_password):
    h_p = compute_h(client_password)
    r = int.from_bytes(os.urandom(32), 'big')
    C = pow(h_p, r, p)
    z = pow(r, -1, q)

    request_body = {
        "C": C,
        "email": email
    }
    response = requests.post("http://localhost:5000/getR", json=request_body)

    if response.status_code == 200:
        K = pow(response.json()['R'], z, p)
        print(K)
    else:
        print("Error fetching R:", response.text)


def login():
    email = input("Enter your email: ")
    client_password = input("Enter your password: ")
    get_K(email, client_password)
    '''q = 2 ** 2048
    K = get_K(client_password, q)
    # shared_key = diffie_hellman_bob(client_private_key, K, q, 2)

    print("Logging in with email:", email)'''


def create_user():
    email = input("Enter your email: ")
    client_password = input("Enter your password: ")
    get_K(email, client_password)
    '''q = 2 ** 2048
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
    print("Creating user with email:", email)'''


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
