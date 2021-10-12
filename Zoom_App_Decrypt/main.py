from Zoom_App_Decrypt import Zoom_App_Decrypt
from DPAPI_Tools.decypher_masterkey import decypher_masterkey
import sys, json, os

# config file -> C:\Users\USER\AppData\Roaming\Zoom\data\Zoom.us.ini
# sqlcipher -> .\sqlcipher_x64.exe
# mimikatz -> .\mimikatz.exe
# user sid -> S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxxx-xxxx
# Password -> you know it...
# master key file -> C:\Users\USER\AppData\Roaming\Microsoft\Protect\S-1-5-21-xxxxxxxxx-xxxxxxxxx-xxxxxxxxxx-xxxx\MASTER_KEY_FILE
# Zoomus.enc.db -> C:\Users\USER\AppData\Roaming\Zoom\data\zoomus.enc.db

if __name__ == "__main__":
    zoom_config_file = sys.argv[1]
    sqlcipher_path = sys.argv[2]
    mimikatz_path = sys.argv[3]
    user_masterkey = decypher_masterkey(sys.argv[4], sys.argv[5], sys.argv[6])
    db_zoom_us = sys.argv[7]
    output_dir = sys.argv[8]
    
    if user_masterkey["status"] == "OK":
        user_masterkey = user_masterkey["mk_key"]
    else:
        print("Error retrieving user's master key...")
        exit(1)
    
    zoom_app_decrypt = Zoom_App_Decrypt(zoom_config_file, sqlcipher_path, mimikatz_path, user_masterkey)
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
