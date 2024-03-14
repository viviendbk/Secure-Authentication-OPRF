from flask import Flask, request, jsonify
from DBUtils import create_users_table, drop_users_table, check_user, create_user, get_all_users


app = Flask(__name__)
create_users_table()


@app.route('/users', methods=['POST'])
def create_user_route():
    email = request.json['email']
    password = request.json['password']
    create_user(email, password)
    return jsonify({'message': 'User created'}), 200

@app.route('/checkusers', methods=['POST'])
def check_user_route():
    email = request.json['email']
    password = request.json['password']
    user = check_user(email, password)
    if user:
        return jsonify({'message': 'Valid user'}), 200
    return jsonify({'message': 'Invalid user'}), 200

# Route to display all users
@app.route('/users/all', methods=['GET'])
def display_all_users():
    users = get_all_users()
    return jsonify(users)

if __name__ == '__main__':
    app.run()
