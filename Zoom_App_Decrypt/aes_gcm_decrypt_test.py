import base64, binascii, sys, json
from os import unlink
from Crypto.Cipher import AES
from hashlib import sha256
from DPAPI_Tools.decypher_masterkey import decypher_masterkey

def zoom_database_values():
    # Decrypt zoomus.enc.db values     NOPE -> (and zoommeeting.enc.db values)
    key = sha256("g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs0=".encode("utf-8")).digest()
    print("Key -> " + key.hex())
    content = base64.b64decode("DBHkkc5jI/Vym8VSnwAAIAAAABDb7eMFjws3/KFUz+JRA1evFbJK0mbjUK1mJb9kgVBrYh4Ayc47QmsEazuFXaDGuQ==")

    nonce = content[1:13]
    ignore = content[13:13+6]
    payload = content[13+6:-16]
    tag = content[-16:]

    print("Whole -> " + content.hex() + "\nWhole len -> " + str(len(content)))
    print("Ignore -> " + ignore.hex() + "\nIgnore len -> " + str(len(ignore)))
    print("Nonce (IV) -> " + nonce.hex() + "\nNonce (IV) len -> " + str(len(nonce)))
    print("TAG -> " + tag.hex() + "\nTag len -> " + str(len(tag)))
    print("Payload -> " + payload.hex() + "\nPayload len -> " + str(len(payload)))

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_value = cipher.decrypt_and_verify(payload, tag)
    print(decrypted_value.decode("utf-8"))

def chrome_decrypt():
    key = bytes.fromhex("8BA23AFA6460878D4C3C8B9AE46830B2A15D721A4291B4F9BF49552235D0DB05")
    print("Key -> " + key.hex())
    content = bytes.fromhex("763130aaee4be2cff4e3878f630ecbd85a128d6dbe38e608a59c8693d60219987fbea097f4ea7069dff632a77f5b61b271a1cb13")

    nonce = content[3:3+12]
    payload = content[3+12:-16]
    tag = content[-16:]

    print("Whole -> " + content.hex() + "\nWhole len -> " + str(len(content)))
    print("Nonce (IV) -> " + nonce.hex() + "\nNonce (IV) len -> " + str(len(nonce)))
    print("TAG -> " + tag.hex() + "\nTag len -> " + str(len(tag)))
    print("Payload -> " + payload.hex() + "\nPayload len -> " + str(len(payload)))

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_value = cipher.decrypt_and_verify(payload, tag)
    print(decrypted_value.decode("utf-8"))


def save_master_key():
    user_masterkey = decypher_masterkey("S-1-5-21-319367206-854998040-1939859893-1001", sys.argv[1], "C:\\Users\\jclo9\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-319367206-854998040-1939859893-1001\\f5bffe91-142a-4a1e-a747-89fd497df810")
    with open("master_key_file.json", "w") as file_obj:
        file_obj.write(json.dumps(user_masterkey, indent=4))

def decrypt_db_field(value):
    field_key = sha256("g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs0=".encode("utf-8")).digest()


    content = base64.b64decode(value)

    nonce = content[1:13]
    payload = content[13+6:-16]
    tag = content[-16:]

    cipher = AES.new(field_key, AES.MODE_GCM, nonce=nonce)

    try:
        decrypted_value = cipher.decrypt_and_verify(payload, tag)

        return decrypted_value.decode("utf-8")
    except ValueError:
        return None


def decrypt_db_some_enc_field(value):
    # Able to decrypt some key/value from the zoomus.enc.db on table zoom_kv
        field_key = sha256("S-1-5-21-319367206-854998040-1939859893-1001".encode("utf-8")).digest()

        #print("Key -> " + field_key.decode())

        content = base64.b64decode(value)

        iv = content[:16]
        payload = content[16:]

        cipher = AES.new(field_key, AES.MODE_CBC, iv)

        try:
            decrypted_value = cipher.decrypt(payload)
            return decrypted_value.decode("utf-8")
        except ValueError:
           return None


def zoom_account_databases_key():
    # Get account specific databases key

    value1 = b"g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs"
    value2 = b"/68ZnQkr59CFVH5JKdU+WGEhyES+cnvVha0Az8XwgdE="

    value1_sha256 = sha256(value1).digest()
    value2_sha256 = sha256(value2).digest()
    value3 = sha256(value1_sha256 + value2_sha256).digest()

    key = base64.b64encode(value3)

    print(key)


def test():
    value1 = b"g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs0="
    value2 = b"S-1-5-21-319367206-854998040-1939859893-1001"

    value1_sha256 = sha256(value1).digest()
    value2_sha256 = sha256(value2).digest()
    value3 = sha256(value1_sha256 + value2_sha256).hexdigest()

    value2_sha256_sha256 = sha256(value2_sha256).digest()
    value2_sha256_sha256_sha256 = sha256(value2_sha256_sha256).digest()
    key = base64.b64encode(value2_sha256_sha256_sha256).decode("utf-8")
    
    print(sha256(key.encode("utf-8")).digest().hex())

    #key = base64.b64encode(value3)

    #print(key)

def test_zoom_meeting():
    #D9zMhNbKnTwGAhBg5SRv+EGMAq/oxjUbsCEmQx1jVd8=
    value = base64.b64decode("WipACKm9K18sFA9uJZmZC8qN5FNKtESGPyBMMplzOGg=")
    key = bytes.fromhex("87b0b7c92bb1a923644022c92fd95acf211e7297874274587b70fa20feff6a19")


    iv = value[:16]
    payload = value[16:]
    # nonce = value[1:13]
    # ignore = value[13:13+6]
    # payload = value[19:-16]
    # tag = value[-16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_value = cipher.decrypt(payload)
    print(decrypted_value)
    print(decrypted_value.decode("utf-8"))


if __name__ == "__main__":
    #zoom_account_databases_key()
    #test()
    #zoom_database_values()
    chrome_decrypt()
    #test_zoom_meeting()
    #save_master_key()
    #print(decrypt_db_some_enc_field("WipACKm9K18sFA9uJZmZC8qN5FNKtESGPyBMMplzOGg="))
    #print(decrypt_db_field("DBHkkc5jI/Vym8VSnwAAIAAAABDb7eMFjws3/KFUz+JRA1evFbJK0mbjUK1mJb9kgVBrYh4Ayc47QmsEazuFXaDGuQ=="))