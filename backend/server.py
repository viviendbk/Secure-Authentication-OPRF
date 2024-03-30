from flask import Flask, request, jsonify
from DBUtils import create_users_table, drop_users_table, check_user, create_user, get_all_users, generate_rsa_key_pair
import os


app = Flask(__name__)
create_users_table()
private_key, public_key = generate_rsa_key_pair()


@app.route('/users', methods=['POST'])
def create_user_route():
    email = request.json['email']
    m = request.json['M']
    create_user(email, m)
    return jsonify({'message': 'User created'}), 200


@app.route('/checkusers', methods=['POST'])
def check_user_route():
    email = request.json['email']
    password = request.json['password']
    user = check_user(email, password)
    if user:
        return jsonify({'message': 'Valid user'}), 200
    return jsonify({'message': 'Invalid user'}), 200


@app.route('/getR/:C', methods=['GET'])
def get_r(C):
    C = int(C)
    salt = os.urandom(16)
    salt_num = int.from_bytes(salt, 'big')
    r = pow(C, salt_num)
    return jsonify({'r': r}), 200


@app.route('/users/all', methods=['GET'])
def display_all_users():
    users = get_all_users()
    return jsonify(users)


if __name__ == '__main__':
    app.run(port=5000, debug=True)
