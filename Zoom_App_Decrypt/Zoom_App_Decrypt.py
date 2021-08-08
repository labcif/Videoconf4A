import configparser, os, subprocess, base64, ntpath, sqlite3, math
from urllib.parse import unquote_plus
from html import unescape
from datetime import datetime
from Crypto.Cipher import AES
from hashlib import sha256

def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])

class Zoom_App_Decrypt():
    def __init__(self, zoom_config_file, sqlcipher_path, mimikatz_path, user_masterkey): #db_zoom_us=None, db_zoom_meetings=None, db_user_jid=None, db_user_jid_asyn=None, db_user_jid_sync=None, db_user_jid_idx=None):
        self.user_masterkey = user_masterkey
        self.mimikatz_path = mimikatz_path
        self.sqlcipher_path = sqlcipher_path
        self.databases_key = self.__get_databases_key(zoom_config_file)

    def __decrypt_db_field(self, value):
        field_key = sha256(self.databases_key.encode("utf-8")).digest()

        content = base64.b64decode(value)

        nonce = content[1:13]
        payload = content[13+6:-16]
        tag = content[-16:]

        cipher = AES.new(field_key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_value = cipher.decrypt_and_verify(payload, tag)
            print(decrypted_value)

            return decrypted_value.decode("utf-8")
        except ValueError:
            return None

    def __decrypt_database(self, db_enc_path):
        
        decrypted_db_dir_path = ntpath.dirname(__file__)
        decrypted_db_path = os.path.join(decrypted_db_dir_path, ntpath.basename(db_enc_path).replace(".enc", ""))
        
        if os.path.exists(decrypted_db_path):
            return decrypted_db_path

        sqlcipher_args = [self.sqlcipher_path, db_enc_path]
        
        communication = "PRAGMA key ='{0}';\nPRAGMA kdf_iter = '4000';\nPRAGMA cipher_page_size = 1024;\nATTACH DATABASE '{1}' AS zoom KEY '';\nSELECT sqlcipher_export('zoom');\nDETACH DATABASE zoom;\n.exit\n".format(self.databases_key, decrypted_db_path)
        communication_bytes = str.encode(communication)

        p = subprocess.Popen(sqlcipher_args, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
        p.stdin.write(communication_bytes)
        
        # Communicate with process to get return code
        p.communicate()
        
        if p.returncode == 0:
            return decrypted_db_path
        
        os.remove(decrypted_db_path)
        
        # Make custom exception?
        print("Error while decrypting " + ntpath.basename(db_enc_path) + "database...")
        exit(1)

    def __get_databases_key(self, zoom_config_file):
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

        mimikatz_args = [self.mimikatz_path, "privilege::debug", "log log_mimikatz.txt", "dpapi::blob /in:\"{0}\" /masterkey:{1} /unprotect /out:\"{2}\"".format(dpapi_encrypted_key_file, self.user_masterkey, database_key_file), "exit"]

        p = subprocess.Popen(args=mimikatz_args, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
        p.wait()
        
        if p.returncode == 0:


            os.remove(dpapi_encrypted_key_file)
            
            file_obj = open(database_key_file, "r")
            database_key = file_obj.read()
            file_obj.close()
            #os.remove(os.path.abspath(file_obj.name))
            return database_key

    
    def __executeSqliteQuery(self, db_file, query):
        conn = None

        try:
            conn = sqlite3.connect(db_file)
        except sqlite3.Error as e:
            print(e)
            exit(1)
        
        cur = conn.cursor()
        cur.execute(query)

        rows = cur.fetchall()

        return rows
        
    def get_saved_meetings(self, db_zoomus_enc_path):
        
        decrypted_db = self.__decrypt_database(db_zoomus_enc_path)
        query = "SELECT hostID, meetNo, topic, joinTime, duration, recordPath FROM zoom_meet_history"
        
        rows = self.__executeSqliteQuery(decrypted_db, query)

        saved_meetings = []

        for row in rows:
            saved_meetings.append({
                "host_id": row[0],
                "meet_number": row[1],
                "topic": row[2],
                "join_time": datetime.strftime(datetime.utcfromtimestamp(float(row[3])), "%Y-%m-%d %H:%M:%S UTC"),
                "duration": row[4],
                "record_path": unquote_plus(row[5])
            })
        
        return saved_meetings

    def get_cached_profile_pictures(self, db_zoomus_enc_path):

        decrypted_db = self.__decrypt_database(db_zoomus_enc_path)

        query = "SELECT url, path, filesize, timestamp FROM zoom_conf_avatar_image_cache"
        
        rows = self.__executeSqliteQuery(decrypted_db, query)

        cached_profile_pictures = []

        for row in rows:
            cached_profile_pictures.append({
                "url": row[0],
                "path": row[1],
                "filesize": convert_size(row[2]),
                "timestamp": datetime.strftime(datetime.utcfromtimestamp(float(row[3])), "%Y-%m-%d %H:%M:%S UTC")
            })

        return cached_profile_pictures

    
    def get_zoom_user_account(self, db_zoomus_enc_path):

        decrypted_db = self.__decrypt_database(db_zoomus_enc_path)

        query = "SELECT uid, uname, zoom_uid, account_id, zoomRefreshToken, zoomEmail, firstName, lastName FROM zoom_user_account_enc"

        rows = self.__executeSqliteQuery(decrypted_db, query)

        zoom_accounts = []

        for row in rows:
            zoom_accounts.append({
                "uid": self.__decrypt_db_field(row[0]) if row[0] != "" else "",
                "uname": self.__decrypt_db_field(row[1]) if row[1] != "" else "",
                "zoom_uid": self.__decrypt_db_field(row[2]) if row[2] != "" else "",
                "account_id": self.__decrypt_db_field(row[3]) if row[3] != "" else "",
                "zoomRefreshToken": self.__decrypt_db_field(row[4]) if row[4] != "" else "",
                "zoomEmail": self.__decrypt_db_field(row[5]) if row[5] != "" else "",
                "firstName": self.__decrypt_db_field(row[6]) if row[6] != "" else "",
                "lastName": self.__decrypt_db_field(row[7]) if row[7] != "" else ""
            })
        
        return zoom_accounts