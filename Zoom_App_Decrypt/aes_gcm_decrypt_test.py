import base64
from os import unlink
from Crypto.Cipher import AES
from hashlib import sha256
import binascii

key = sha256("g6qC86Wju2gqBS6KAn7GCp9G/TWWbWCJuzRlt5GtDs0=".encode("utf-8")).hexdigest()
print("Key -> " + key)
content = base64.b64decode("DFONzhblAKMO+XXLdAAAIAAAAJrXZG5QeyaUAXF5TfWrjohVUNFr/LOa5Yh2X2pqdA/lLPyf8i1i7ALiP2c2GmVNHw==")

file_obj = open("content_b64decode.bin", "wb")
file_obj.write(content)
file_obj.close()

nonce = content[1:13]
payload = content[13+12:-16]
tag = content[-16:]
print("Whole -> " + content.hex() + "\nWhole len -> " + str(len(content)))
print("Nonce (IV) -> " + nonce.hex() + "\nNonce (IV) len -> " + str(len(nonce)))
print("TAG -> " + tag.hex() + "\nTag len -> " + str(len(tag)))
print("Payload -> " + payload.hex() + "\nPayload len -> " + str(len(payload)))

#0c 53 8d ce 16 e5 00 a3 0e f9 75 cb 74 00 00 20 00 00 00 9a d7 64 6e 50 7b 26940171794df5ab8e885550d16bfcb39ae588765f6a6a740fe52cfc9ff22d62ec02e23f67361a654d1f

# cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
# decrypted_value = cipher.decrypt(content)
# print(binascii.hexlify(decrypted_value))

# from Crypto.Cipher import AES
# import binascii, os

# def encrypt_AES_GCM(msg, secretKey):
#     aesCipher = AES.new(secretKey, AES.MODE_GCM)
#     ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
#     return (ciphertext, aesCipher.nonce, authTag)

# def decrypt_AES_GCM(encryptedMsg, secretKey):
#     (ciphertext, nonce, authTag) = encryptedMsg
#     aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
#     plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
#     return plaintext

# secretKey = os.urandom(32)  # 256-bit random encryption key
# print("Encryption key:", binascii.hexlify(secretKey))

# msg = b'Message for AES-256-GCM + Scrypt encryption'
# encryptedMsg = encrypt_AES_GCM(msg, secretKey)
# print("encryptedMsg", {
#     'ciphertext': binascii.hexlify(encryptedMsg[0]),
#     'aesIV': binascii.hexlify(encryptedMsg[1]),
#     'authTag': binascii.hexlify(encryptedMsg[2])
# })

# decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)
# print("decryptedMsg", decryptedMsg)