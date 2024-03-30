import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import psycopg2
import os
from dotenv import load_dotenv
import base64

load_dotenv()


def generate_rsa_key_pair(public_exponent=65537, key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )

    public_key = private_key.public_key()

    # PEM encode the private and public keys
    pem_encoded_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_encoded_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_encoded_private_key, pem_encoded_public_key


def create_user(email, password, salt):
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (email, password, salt)
        VALUES (%s, %s)
    ''', (email, password, salt))
    conn.commit()
    cursor.close()
    conn.close()


def check_user(email, password):
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute("SELECT password, salt FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    '''if user:
        secure_password = email + os.getenv('SALT') + password
        try:
            if hasher.verify(user[0], secure_password):
                return True
        except:
            return False
    return False'''


def create_users_table():
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            userId SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()


def drop_users_table():
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('''
        DROP TABLE IF EXISTS users
    ''')
    conn.commit()
    cursor.close()
    conn.close()


def get_all_users():
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return users


def pem_to_int(pem_key):
    pem_key = pem_key.decode('utf-8').split('\n')[1:-1]
    pem_key = ''.join(pem_key)
    der_key = base64.b64decode(pem_key)
    key_as_int = int.from_bytes(der_key, 'big')
    return key_as_int
