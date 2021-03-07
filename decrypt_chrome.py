import sys, json

from decypher_masterkey import decypher_masterkey
from decypher_blob import decypher_blob
from DecryptChrome import DecryptChrome, parse_local_state_key


if __name__ == "__main__":
    local_state_enc_file = sys.argv[1]
    sid = sys.argv[2]
    password = sys.argv[3]
    masterkey_file = sys.argv[4]
    cookies_file = sys.argv[5]
    login_data_file = sys.argv[6]
    output_dir = sys.argv[7]

    # Parse the local state key from the local state file
    local_state_key_enc = parse_local_state_key(local_state_enc_file)
    
    # Decipher the masterkey file with the User's password
    master_key = decypher_masterkey(sid, password, masterkey_file)

    # Retrieve the decrypted master key
    if master_key["status"] == "KO":
        print(json.dump(master_key))
        exit(1)

    # Decipher the encrypted local state key
    decrypted_local_state_key = decypher_blob(master_key["mk_key"], local_state_key_enc)

    if decrypted_local_state_key["status"] == "KO":
        print(json.dump(decrypted_local_state_key))
        exit(1)

    decrypt_chrome = DecryptChrome(decrypted_local_state_key["decrypted_blob"], output_dir)
    decrypt_chrome.decypher_cookies(cookies_file)
    decrypt_chrome.decrypt_login_data(login_data_file)