import os
import sys
sys.path.append("../")
from flask import Flask, request, jsonify
from DBUtils import create_users_table, drop_users_table, check_user, create_user, get_all_users, generate_rsa_key_pair, \
    pem_to_int
from crypto_utils import p, q


app = Flask(__name__)
# COMMENT THE FOLLOWING LINE ONCE YOU HAVE RUN THE SERVER FOR THE FIRST TIME
drop_users_table()

create_users_table()
salt = 0


@app.route('/users', methods=['POST'])
def create_user_route():
    email = request.json['email']
    m = request.json['M']
    create_user(email, m, salt)
    print(get_all_users())
    return jsonify({'message': 'User created'}), 200


@app.route('/checkusers', methods=['POST'])
def check_user_route():
    email = request.json['email']
    password = request.json['password']
    user = check_user(email, password)
    if user:
        return jsonify({'message': 'Valid user'}), 200
    return jsonify({'message': 'Invalid user'}), 200


@app.route('/getR', methods=['POST'])
def get_r():
    C = request.json['C']
    global salt
    salt = int.from_bytes(os.urandom(32), 'big')
    R = pow(C, salt, p)
    return jsonify({'R': R}), 200


if __name__ == '__main__':
    app.run(port=5000, debug=True)
