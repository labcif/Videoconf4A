import get_database_key, sys

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("6 arguments are required.\n1 - Zoom config file (Zoom.us.ini)\n2 - mimikatz.exe file path\n3 - User windows password\n4 - User's masterkey SID\n5 - User's masterkey\n6 - Directory for any generated files")
        exit(1)

    masterkey_json = get_database_key.decypher_masterkey(sys.argv[4], sys.argv[3], sys.argv[5])
    if masterkey_json["status"] == "OK":
        database_key = get_database_key.get_database_key(sys.argv[1], sys.argv[2], masterkey_json["mk_key"])
        print(database_key)
        #decryptor.decrypt_file("C:\\Users\\jclo9\\AppData\\Roaming\\Zoom\\data\\zoomus.enc.db", bytearray(database_key, "utf-8"), "decrypted_db.db")