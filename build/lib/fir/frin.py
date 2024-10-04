# #!/usr/bin/env python3

# import os
# import subprocess
# import hashlib
# import json
# from datetime import datetime
# from cryptography.fernet import Fernet
# import sys
# import getpass

# KEY_FILE = "key.key"

# def load_or_generate_key():
#     if os.path.exists(KEY_FILE):
 
#         with open(KEY_FILE, "rb") as key_file:
#             return key_file.read()
#     else:
 
#         new_key = Fernet.generate_key()
#         with open(KEY_FILE, "wb") as key_file:
#             key_file.write(new_key)
#         return new_key

# ENCRYPTION_KEY = load_or_generate_key()
# cipher = Fernet(ENCRYPTION_KEY)


# case_list = []

# def print_header():
#     subprocess.run("figlet FIR Tool | lolcat", shell=True)

# def check_dependencies():
#     required_tools = ["figlet", "lolcat", "dd", "foremost", "yara"]
#     missing_tools = []
    
#     for tool in required_tools:
#         if subprocess.call(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
#             missing_tools.append(tool)

#     if subprocess.call("pipx list | grep volatility3", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
#         missing_tools.append("volatility3 (pipx)")

#     if subprocess.call("pipx list | grep yara", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
#         missing_tools.append("yara (pipx)")

#     if missing_tools:
#         print(f"Missing tools: {', '.join(missing_tools)}")
#         print("Please install the missing tools using the following commands:")
#         print("\nInstall the required packages:\n")
#         print("sudo apt install figlet lolcat dcfldd foremost yara")
#         print("pipx install volatility3")
#         print("pipx install yara")
#         print("pip install cryptography yara-python")
#         sys.exit(1)

# def save_case_data(case_list):
#     encrypted_data = cipher.encrypt(json.dumps(case_list).encode())
#     with open("cases.enc", "wb") as f:
#         f.write(encrypted_data)

# def load_case_data():
#     if os.path.exists("cases.enc"):
#         with open("cases.enc", "rb") as f:
#             encrypted_data = f.read()
#         return json.loads(cipher.decrypt(encrypted_data).decode())
#     return []

# def create_case(case_name, investigator_name, description):
#     case_id = hashlib.sha256(case_name.encode()).hexdigest()[:10]
#     timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#     pin = getpass.getpass("Set a PIN for this case: ")
#     case_data = {
#         "case_id": case_id,
#         "case_name": case_name,
#         "investigator": investigator_name,
#         "description": description,
#         "timestamp": timestamp,
#         "status": "open",
#         "pin": hashlib.sha256(pin.encode()).hexdigest(),
#         "notes": [],
#         "evidence": []
#     }
#     case_list.append(case_data)
#     save_case_data(case_list)
#     print(f"Case Created with ID: {case_id}")

# def add_case_note(case_id, note):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             pin_check = getpass.getpass("Enter PIN to unlock this case: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 case["notes"].append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "note": note})
#                 save_case_data(case_list)
#                 print("Note added to the case.")
#             else:
#                 print("Incorrect PIN.")
#             return
#     print(f"Case ID {case_id} not found.")

# def add_evidence(case_id, evidence_name):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             pin_check = getpass.getpass("Enter PIN to unlock this case: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 case["evidence"].append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "evidence_name": evidence_name})
#                 save_case_data(case_list)
#                 print("Evidence added to the case.")
#             else:
#                 print("Incorrect PIN.")
#             return
#     print(f"Case ID {case_id} not found.")

# def list_all_cases():
#     print("List of All Cases:")
#     for case in case_list:
#         print(f"Case ID: {case['case_id']} | Case Name: {case['case_name']} | Status: {case['status']}")

# def lock_case(case_id):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             pin_check = getpass.getpass("Enter PIN to lock this case: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 case["status"] = "locked"
#                 save_case_data(case_list)
#                 print(f"Case {case_id} has been locked.")
#             else:
#                 print("Incorrect PIN.")
#             return
#     print(f"Case ID {case_id} not found.")

# def transfer_case(case_id, new_investigator):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             # Verify PIN before allowing the transfer
#             pin_check = getpass.getpass("Enter PIN to authorize case transfer: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 old_investigator = case["investigator"]
#                 case["investigator"] = new_investigator
#                 save_case_data(case_list)
#                 print(f"Case {case_id} has been successfully transferred from {old_investigator} to {new_investigator}.")
#             else:
#                 print("Incorrect PIN. Case transfer not authorized.")
#             return
#     print(f"Case ID {case_id} not found.")

# def view_case(case_id):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             pin_check = getpass.getpass("Enter PIN to view case details: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 print(f"Case ID: {case['case_id']}\nInvestigator: {case['investigator']}\nDescription: {case['description']}")
#                 print(f"Notes: {case['notes']}\nEvidence: {case['evidence']}")
#             else:
#                 print("Incorrect PIN.")
#             return
#     print(f"Case ID {case_id} not found.")

# def close_case(case_id):
#     for case in case_list:
#         if case["case_id"] == case_id:
#             pin_check = getpass.getpass("Enter PIN to close this case: ")
#             if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
#                 case['status'] = 'closed'
#                 save_case_data(case_list)
#                 print(f"Case {case_id} closed.")
#             else:
#                 print("Incorrect PIN.")
#             return
#     print(f"Case ID {case_id} not found.")


# def image_disk(device):
#     output_file = f"{device}_image.dd"
#     subprocess.run(f"sudo dd if={device} of={output_file} bs=64K conv=noerror,sync", shell=True)
#     print(f"Disk image saved to {output_file}")

# def dump_memory(output_file):
#     subprocess.run(f"volatility3 -f {output_file} --profile=Win7SP1x64", shell=True)
#     print(f"Memory dumped to {output_file}")


# def find_evidence(disk_image, file_type):
#     subprocess.run(f"foremost -t {file_type} -i {disk_image} -o output_dir", shell=True)
#     print(f"Evidence scanned for {file_type} in {disk_image}")

# def collect_system_info():
#     print("System Information:")
#     os.system("uname -a | lolcat")
#     os.system("ifconfig | lolcat")


# def generate_hash(file_path):
#     with open(file_path, "rb") as f:
#         file_hash_md5 = hashlib.md5(f.read()).hexdigest()
#         f.seek(0)  # Reset file pointer to the beginning
#         file_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
#     print(f"MD5: {file_hash_md5}\nSHA256: {file_hash_sha256}")

# def generate_timeline():
#     print("Generating forensic timeline (mock-up)...")
#     os.system("grep -a 'timestamp' * | sort")

# def recover_files(disk_image):
#     subprocess.run(f"foremost -i {disk_image} -o output_dir", shell=True)
#     print("File carving complete. Recovered files are in output_dir")

# def memory_analysis(memory_dump):
#     subprocess.run(f"volatility3 -f {memory_dump} pslist", shell=True)
#     print("Memory analysis complete.")

# def backup_files(file_paths, backup_dir):
#     for file_path in file_paths:
#         subprocess.run(f"cp {file_path} {backup_dir}", shell=True)
#         print(f"Backed up {file_path} to {backup_dir}")

# def restore_backup(backup_dir, restore_dir):
#     subprocess.run(f"cp {backup_dir}/* {restore_dir}", shell=True)
#     print(f"Restored backup from {backup_dir} to {restore_dir}")


# def smart_search(disk_image, keyword):
#     subprocess.run(f"grep -ai '{keyword}' {disk_image}", shell=True)
#     print(f"Searched for '{keyword}' in {disk_image}")

# def yara_scan(directory, yara_rule):
#     subprocess.run(f"yara -r {yara_rule} {directory}", shell=True)
#     print(f"YARA scan complete in {directory} using rule {yara_rule}")

# # Developer Bio
# def bio():
#     print("\nDeveloper Bio:")
#     print("Name: Suleiman Yahaya Garo")
#     print("Nickname: garogenius")
#     print("Email: garogenius@gmail.com")
#     print("Designation: SOC/Software Engineer")
#     print("Specification: Ethical Hacker and Security Engineer")
#     print("This tool is designed for ethical and security defense use.")

# def help_menu():
#     print("""
#     FIR Tool Commands:
#     - fir create_case "case_name" "investigator_name" "description": Create a new case
#     - fir view_case "case_id": View details of a specific case
#     - fir add_note "case_id" "note": Add a note to a specific case
#     - fir add_evidence "case_id" "evidence_name": Add evidence to a specific case
#     - fir list_cases: List all cases
#     - fir lock_case "case_id": Lock a case with its PIN
#     - fir transfer_case "case_id" "new_investigator": Transfer a case to another investigator
#     - fir close_case "case_id": Close a case
#     - fir image_disk "/dev/sda": Create disk image using dd
#     - fir dump_memory "output.mem": Dump memory using volatility3
#     - fir find_evidence "disk_image" "file_type": Search for specific files
#     - fir collect_info: Collect system metadata
#     - fir generate_hash "file_path": Generate file hash
#     - fir generate_timeline: Generate forensic timeline
#     - fir recover_files "disk_image": Recover deleted files
#     - fir memory_analysis "memory_dump": Analyze memory dump
#     - fir backup "file1 file2" "/backup_dir": Backup specified files
#     - fir restore_backup "/backup_dir" "/restore_dir": Restore files from backup
#     - fir smart_search "disk_image" "keyword": Search for keyword
#     - fir yara_scan "/directory" "yara_rule": Scan with YARA rules
#     - fir bio: Developer bio
#     - fir version: Display tool version
#     - fir help: Display this help menu
#     """)


# def version():
#     print("FIR Tool Version 1.0.0")


# def update():
#     print("Checking for updates (mock-up)...")
#     print("FIR Tool is up to date.")

# def uninstall():
#     print("Uninstalling FIR Tool...")
#     os.remove("cases.enc")
#     print("Tool uninstalled successfully.")

# commands = {
#     "create_case": create_case,
#     "view_case": view_case,
#     "add_note": add_case_note,
#     "add_evidence": add_evidence,
#     "list_cases": list_all_cases,
#     "lock_case": lock_case,
#     "transfer_case": transfer_case, 
#     "close_case": close_case,
#     "image_disk": image_disk,
#     "dump_memory": dump_memory,
#     "find_evidence": find_evidence,
#     "collect_info": collect_system_info,
#     "generate_hash": generate_hash,
#     "generate_timeline": generate_timeline,
#     "recover_files": recover_files,
#     "memory_analysis": memory_analysis,
#     "backup": backup_files,
#     "restore_backup": restore_backup,
#     "smart_search": smart_search,
#     "yara_scan": yara_scan,
#     "bio": bio,
#     "help": help_menu,
#     "version": version,
#     "update": update,
#     "uninstall": uninstall
# }

# def main():
#     try:
#         check_dependencies()
#         print_header()
        
#         if len(sys.argv) < 2:
#             print("No command provided. Use 'fir help' for usage.")
#             sys.exit(1)

#         command = sys.argv[1]
#         if command in commands:
#             commands[command](*sys.argv[2:])
#         else:
#             print("Invalid command. Use 'fir help' for usage.")
#     except Exception as e:
#         print(f"An error occurred: {e}")

# if __name__ == "__main__":
   
#     case_list = load_case_data()
#     main()
