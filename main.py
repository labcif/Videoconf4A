import sys, json, os

from parse_local_state import parse_local_state_key
from decypher_masterkey import decypher_masterkey
from decypher_blob import decypher_blob
from chrome_decrypt import DecryptChrome


if __name__ == "__main__":
    # Too many args, turn into config file
    local_state_file = sys.argv[1]
    sid = sys.argv[2]
    password = sys.argv[3]
    masterkey_file = sys.argv[4]
    cookies_file = sys.argv[5]
    output_file_name = sys.argv[6]

    # Parse the local state key from the local state file
    parsed_local_state_file = parse_local_state_key(local_state_file)
    
    # Decipher the masterkey file with the User's password
    decypher_masterkey(sid, password, masterkey_file, os.path.dirname(os.path.abspath(__file__)) + "\\masterkey_output.json")

    # Retrieve the decrypted master key
    file_obj = open(os.path.dirname(os.path.abspath(__file__)) + "\\masterkey_output.json", "r")
    print(file_obj.name)
    masterkey = json.loads(file_obj.read())["mk_key"]

    # Decipher the encrypted local state key
    decypher_blob(masterkey, parsed_local_state_file, os.path.dirname(os.path.abspath(__file__)) + "\\local_state_key_dec")

    decrypt_chrome = DecryptChrome(os.path.dirname(os.path.abspath(__file__)) + "\\local_state_key_dec")
    decrypt_chrome.decypher_cookies(cookies_file)