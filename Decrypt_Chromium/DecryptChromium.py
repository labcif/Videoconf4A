import os
import json
import sqlite3
import json
import base64
from Crypto.Cipher import AES

def parse_local_state_key(local_state_path):
    local_state_path = os.path.expandvars(local_state_path)
    with open(local_state_path, 'r') as file:
        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key)
    encrypted_key = encrypted_key[5:]

    return encrypted_key

class DecryptChromium():
    def __init__(self, local_state_key, output_dir):
        self.decrypted_key = local_state_key
        self.output_dir = output_dir

    def __decrypt_data(self, encrypted_value):
        decrypted_value = ""
            
        # DPAPI encrypted (before Chrome v80) https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
        if "01000000d08c9ddf0115d1118c7a00c04fc297eb" in str(encrypted_value.hex()):
            print("DPAPI encrypted... Only Chromium legacy versions encrypt like this")
        
        # Encryption of the cookies performed with AES-256 in GCM mode (after Chrome v80)
        else:
            nonce = encrypted_value[3:3+12]
            ciphertext = encrypted_value[3+12:-16]
            tag = encrypted_value[-16:]
            cipher = AES.new(self.decrypted_key, AES.MODE_GCM, nonce=nonce)
            decrypted_value = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")  # the decrypted cookie

            return decrypted_value
    
    def decypher_cookies(self, cookies_path):
        #Connect to the Cookies Database
        conn = sqlite3.connect(cookies_path)
        cursor = conn.cursor()
        cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
        
        results_array = []
        
        # Get the results
        file_obj = open(os.path.join(self.output_dir, "cookies_results.json"), "w")
        
        for results in cursor.fetchall():
            key = results[0]
            name = results[1]
            encrypted_value = results[2]
            decrypted_value = self.__decrypt_data(encrypted_value)
            
            results_array.append({"key": key, "name": name, "value": decrypted_value})

        file_obj.write(json.dumps(results_array, indent=4))
        file_obj.close()
    
    def decrypt_login_data(self, login_data_path):
        #Connect to the Login Data Database
        conn = sqlite3.connect(login_data_path)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_element, username_value, password_value FROM logins')

        results_array = []

        # Get the results
        file_obj = open(os.path.join(self.output_dir, "login_data_results.json"), "w")
        
        for results in cursor.fetchall():
            origin_url = results[0]
            username_element = results[1]
            username_value = results[2]
            password_value_enc = results[3]
            
            password_value = self.__decrypt_data(password_value_enc)

            results_array.append({"url": origin_url, "username_type": username_element, "username": username_value, "password": password_value})
        
        file_obj.write(json.dumps(results_array, indent=4))
        file_obj.close()
