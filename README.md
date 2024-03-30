# OPRF Project
This project aims to implement the OPRF protocol in the communication between a client and a server.

## Members
- Vivien DEBLOCK (CCC1)
- Mathias BALIAN (CCC1)

## Prerequisites
To run this project, you need to have Python installed on your machine.

## Installation
1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/viviendbk/Secure-Authentication-OPRF.git
    ```
   
2. Navigate to the project root folder:

    ```bash
    cd Secure-Authentication-OPRF
    ```
   
3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```
   
4. Copy and paste the .env file submitted by the project members on DVL to the backend folder. Make sure that the file is named ".env" and not "env".
   
## Usage
1. Start the server:

    ```bash
    cd backend
    python server.py
    ```
   IMPORTANT NOTE: once you have run the server for the first time, you will need to open the `server.py` file and comment the line `drop_users_table()`. This line is used to drop the users table in the database, and it should only be executed once.
   
2. Start the client:

    ```bash
    cd frontend
    python frontend.py
    ```
   
3. Follow the instructions displayed in the terminal to interact with the client and the server.

## How it works
1. When trying to log in or sign up, the client starts the OPRF protocol with the server.
```python
# Client
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
```

2. The server then sends back the needed data to the client.
```python
# Server
@app.route('/getR', methods=['POST'])
def get_r():
    C = request.json['C']
    global salt
    salt = int.from_bytes(os.urandom(32), 'big')
    R = pow(C, salt, p)
    return jsonify({'R': R}), 200
```

3. The client can now perform the last step of the OPRF protocol.
```python
# Client
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
```
