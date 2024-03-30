from flask import Flask, request, jsonify
from DBUtils import create_users_table, drop_users_table, check_user, create_user, get_all_users, generate_rsa_key_pair, pem_to_int
import os
import dotenv

app = Flask(__name__)
create_users_table()
salt = os.urandom(16)
dotenv.load_dotenv()
private_key, public_key = generate_rsa_key_pair()
client_public_key = ""


@app.route('/users', methods=['POST'])
def create_user_route():
    email = request.json['email']
    m = request.json['M']
    create_user(email, m, salt)
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
    global client_public_key
    C = int(request.json['C'])
    client_public_key = request.json['public_key']
    r = pow(C, int.from_bytes(salt, 'big'))
    return jsonify({'R': r, "server_public_key": public_key}), 200


if __name__ == '__main__':
    app.run(port=5000, debug=True)
