import base64
from os import unlink
from Crypto.Cipher import AES
from hashlib import sha256
import binascii


def zoom_database_values():
    # Decrypt zoomus.enc.db and zoommeeting.enc.db values
    key = sha256("g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs0=".encode("utf-8")).digest()
    print("Key -> " + key.hex())
    content = base64.b64decode("Yw8sJ/AWbQrnbmtcM4XJpg==")

    length = len(content)

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
    value = base64.b64decode("D9zMhNbKnTwGAhBg5SRv+EGMAq/oxjUbsCEmQx1jVd8=")
    key = bytes.fromhex("87b0b7c92bb1a923644022c92fd95acf211e7297874274587b70fa20feff6a19")

    nonce = value[1:13]
    ignore = value[13:13+6]
    payload = value[19:-16]
    tag = value[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_value = cipher.decrypt_and_verify(payload, tag)
    print(decrypted_value.decode("utf-8"))


if __name__ == "__main__":
    #zoom_account_databases_key()
    #test()
    zoom_database_values()
    #test_zoom_meeting()