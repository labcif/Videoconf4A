import os, json, base64
from sys import argv

def parse_local_state_key(local_state_path):
    local_state_path = os.path.expandvars(local_state_path)
    with open(local_state_path, 'r') as file:
        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)
    encrypted_key = encrypted_key[5:]

    return encrypted_key

