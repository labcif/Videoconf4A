from Zoom_App_Decrypt import Zoom_App_Decrypt
from DPAPI_Tools.decypher_masterkey import decypher_masterkey
from DPAPI_Tools.decypher_blob import decypher_blob
import sys, json, os, configparser, base64

# config file -> C:\Users\USER\AppData\Roaming\Zoom\data\Zoom.us.ini
# sqlcipher -> .\sqlcipher_x64.exe
# user sid -> S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxxx-xxxx
# Password -> you know it...
# master key file -> C:\Users\USER\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxxx-xxxx\MASTER_KEY_FILE
# Zoomus.enc.db -> C:\Users\USER\AppData\Roaming\Zoom\data\zoomus.enc.db
# Output directory -> <whatever you want>

def main():
    zoom_config_file = sys.argv[1]
    sqlcipher_path = sys.argv[2]
    user_masterkey = decypher_masterkey(sys.argv[3], sys.argv[4], sys.argv[5])
    db_zoom_us = sys.argv[6]
    output_dir = sys.argv[7]
    
    if user_masterkey["status"] == "OK":
        user_masterkey = user_masterkey["mk_key"]
    else:
        print("Error retrieving user's master key...")
        exit(1)

    dpapi_encrypted_key = get_databases_key(zoom_config_file)

    dpapi_decrypted_key = decypher_blob(user_masterkey, dpapi_encrypted_key)["decrypted_blob"].decode()
    
    zoom_app_decrypt = Zoom_App_Decrypt(sqlcipher_path, dpapi_decrypted_key)
    saved_meetings = zoom_app_decrypt.get_saved_meetings(db_zoom_us)
    cached_profile_pics = zoom_app_decrypt.get_cached_profile_pictures(db_zoom_us)
    zoom_accounts = zoom_app_decrypt.get_zoom_user_account(db_zoom_us)

    
    file_obj = open(os.path.join(output_dir, "saved_meetings.json"), "w")
    file_obj.write(json.dumps(saved_meetings, indent=4))
    file_obj.close()

    file_obj = open(os.path.join(output_dir, "cached_profile_pics.json"), "w")
    file_obj.write(json.dumps(cached_profile_pics, indent=4))
    file_obj.close()

    file_obj = open(os.path.join(output_dir, "zoom_accounts.json"), "w")
    file_obj.write(json.dumps(zoom_accounts, indent=4))
    file_obj.close()

    # print("---------SAVED MEETINGS---------")
    # print(saved_meetings)
    # print("---------CACHED PROFILES PICTURES---------")
    # print(cached_profile_pics)
    # print("---------ZOOM ACCOUNTS---------")
    # print(zoom_accounts)


def get_databases_key(zoom_config_file):
        config = configparser.ConfigParser()

        try:
            config.read(zoom_config_file)
        except configparser.MissingSectionHeaderError:
            print("File is not a config file or is incorrectly built.")
            exit(1)

        encoded_dpapi_encrypted_key = config.get("ZoomChat", "win_osencrypt_key").replace("ZWOSKEY", "")

        dpapi_encrypted_key = base64.b64decode(encoded_dpapi_encrypted_key)

        return dpapi_encrypted_key

if __name__ == "__main__":
    main()
