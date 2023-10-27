from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3


# Define functions
def int_to_base64(value):  # Convert an integer to a Base64URL-encoded string
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def serialize_key_to_pem(key):  # Serialize the private key to PKCS1 PEM format
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')


def deserialize_pem_to_key(pem_string):  # Deserialize the private key from PKCS1 PEM format
    return serialization.load_pem_private_key(
        pem_string.encode('utf-8'),
        password=None
    )


def get_all_valid_private_keys_with_kid() -> list[tuple[int, RSAPrivateKey]]:  # Get all valid keys from the DB
    current_time = int(datetime.datetime.utcnow().timestamp())
    query = "SELECT kid, key FROM keys WHERE exp > ?"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn1:
        cursor = conn1.execute(query, (current_time,))
        key_data = cursor.fetchall()

    # Deserialize the keys and pair with their respective kid
    keys = [(data[0], deserialize_pem_to_key(data[1])) for data in key_data]
    return keys


def get_private_key_with_kid_from_db(expired=False):  # Get un/expired key from DB
    current_time = int(datetime.datetime.utcnow().timestamp())

    # Query to fetch based on expiration status
    if expired:
        query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1"
    else:
        query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1"

    with sqlite3.connect('totally_not_my_privateKeys.db') as conn2:
        cursor = conn2.execute(query, (current_time,))
        key_data = cursor.fetchone()

    # Deserialize the key and pair with its kid if found
    if key_data:
        return key_data[0], deserialize_pem_to_key(key_data[1])
    return None, None


# Create and initialize DB
conn = sqlite3.connect('totally_not_my_privateKeys.db')  # Create DB
conn.execute('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, '
             'key BLOB NOT NULL, exp INTEGER NOT NULL)')  # Create keys table in DB
conn.commit()  # Commit the above changed to the DB

# Create and serialize keys
init_unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Create RSA key
init_expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
init_unexpired_key_PEM = serialize_key_to_pem(init_unexpired_key)  # Serialize key to PEM format
init_expired_key_PEM = serialize_key_to_pem(init_expired_key)

now = int(datetime.datetime.utcnow().timestamp())  # Get current time
hour_from_now = now + 3600  # Get one hour from now time

# Insert the serialized keys into the DB
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (init_unexpired_key_PEM, hour_from_now))
conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (init_expired_key_PEM, (now - 36000)))
conn.commit()

hostName = "localhost"  # Use localhost for server
serverPort = 8080  # Use port 8080 for server


# Configure web server requests/actions
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):  # Define PUT request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_PATCH(self):  # Define PATCH request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_DELETE(self):  # Define DELETE request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_HEAD(self):  # # Define HEAD request action
        self.send_response(405)  # Return status 405
        self.end_headers()
        return

    def do_POST(self):  # Define POST request action
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Get the appropriate key and its kid based on the "expired" query parameter
            kid, key = get_private_key_with_kid_from_db('expired' in params)

            if not key:  # If no key returned/found
                self.send_response(500, "Unable to fetch private key")
                self.end_headers()
                return

            # Create the JWT
            headers = {
                "kid": str(kid)
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            key_pem = serialize_key_to_pem(key)
            encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

            # Return the JWT
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):  # Define GET request action
        if self.path == "/.well-known/jwks.json":  # Check if requested path is correct
            valid_keys_with_kid = get_all_valid_private_keys_with_kid()
            jwks = {"keys": []}
            # Create list of keys
            for kid, key in valid_keys_with_kid:
                private_numbers = key.private_numbers()
                jwks["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(private_numbers.public_numbers.n),
                    "e": int_to_base64(private_numbers.public_numbers.e)
                })
            # Return list of keys
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)  # Define web server
    try:
        webServer.serve_forever()  # Start web server
    except KeyboardInterrupt:
        pass

    webServer.server_close()  # Close web server
