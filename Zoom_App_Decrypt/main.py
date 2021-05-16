from Zoom_App_Decrypt import Zoom_App_Decrypt
from DPAPI_Tools.decypher_masterkey import decypher_masterkey
import sys

# config file -> C:\Users\jclo9\AppData\Roaming\Zoom\data\Zoom.us.ini
# sqlcipher -> .\sqlcipher_x64.exe
# mimikatz -> .\mimikatz.exe
# sid -> S-1-5-21-319367206-854998040-1939859893-1001
# Password -> you know it...
# master key file -> C:\Users\jclo9\AppData\Roaming\Microsoft\Protect\S-1-5-21-319367206-854998040-1939859893-1001\f5bffe91-142a-4a1e-a747-89fd497df810
# Zoomus.enc.db -> C:\Users\jclo9\AppData\Roaming\Zoom\data\zoomus.enc.db

if __name__ == "__main__":
    zoom_config_file = sys.argv[1]
    sqlcipher_path = sys.argv[2]
    mimikatz_path = sys.argv[3]
    user_masterkey = decypher_masterkey(sys.argv[4], sys.argv[5], sys.argv[6])
    db_zoom_us = sys.argv[7]
    
    if user_masterkey["status"] == "OK":
        user_masterkey = user_masterkey["mk_key"]
    else:
        print("Error retrieving user's master key...")
        exit(1)
    
    zoom_app_decrypt = Zoom_App_Decrypt(zoom_config_file, sqlcipher_path, mimikatz_path, user_masterkey)
    saved_meetings = zoom_app_decrypt.get_saved_meetings(db_zoom_us)
    cached_profile_pics = zoom_app_decrypt.get_cached_profile_pictures(db_zoom_us)

    print("---------SAVED MEETINGS---------")
    print(saved_meetings)
    print("---------CACHED PROFILES PICTURES---------")
    print(cached_profile_pics)