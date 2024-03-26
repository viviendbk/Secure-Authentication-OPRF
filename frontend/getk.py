from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def compute_h(p, q):
    """
  Hashes a string P to an integer in the range [2, q]

  Args:
      p: The string to hash.
      q: The prime order of the group G.

  Returns:
      An integer representing H(P).
  """
    s = int.from_bytes(p.encode(), byteorder='big')  # Convert string P to integer
    s = s % (q - 2) + 2  # Ensure s is in the range [2, q]
    return pow(s, 2, 2 * q + 1)  # Compute H(P) = s^2 mod (2q + 1)


def oprf(client_password, server_salt, q):
    """
  Performs the Oblivious Pseudorandom Function (OPRF) protocol.

  Args:
      client_password: The client's password string.
      server_salt: The server's salt string.
      q: The prime order of the group G. (assumed to be 2^2048)

  Returns:
      The OPRF output (K) for the client.
  """
    # Convert password to integer in range [2, q]
    h_p = compute_h(client_password, q)

    # Generate random scalar
    r = int.from_bytes(os.urandom(32), byteorder='big')

    # Client sends C = H(P) ** r to server
    c = pow(h_p, r, q)

    # Server receives C, computes R = C * s, and sends to client
    s = compute_h(server_salt, q)
    r_server = pow(c, s, q)

    # Client computes z and K
    z = pow(r, q - 2, q)  # Efficient modular inverse
    k = pow(r_server, z, q)

    return k


# Example usage
q = 2 ** 2048  # Assuming a 2048-bit group from RFC 3526
client_password = "my_secret_password"
server_salt = "random_server_salt"

k = oprf(client_password, server_salt, q)

print(f"OPRF output (K): {k}")
