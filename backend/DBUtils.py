import time

import psycopg2
import os
from dotenv import load_dotenv
import argon2
from argon2 import PasswordHasher
import hashlib

load_dotenv()
hasher = PasswordHasher(time_cost=15,
                        type=argon2.low_level.Type.ID)


def create_user(email, password):
    secure_password = email + os.getenv('SALT') + password
    # hash the password
    hashed_password = hasher.hash(secure_password)

    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO users (email, password)
        VALUES (%s, %s)
    ''', (email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()


def check_user(email, password):
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        secure_password = email + os.getenv('SALT') + password
        try:
            # verify the password
            if hasher.verify(user[0], secure_password):
                return True
        except:
            return False
    return False


def create_users_table():
    conn = psycopg2.connect(os.getenv('DB_CONNECTION'))
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            userId SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            password TEXT NOT NULL
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