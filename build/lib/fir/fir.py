#!/usr/bin/env python3

import os
import subprocess
import hashlib
import json
import re
from datetime import datetime
from cryptography.fernet import Fernet
import sys
import getpass
import time
from pyicloud import PyiCloudService
from google.oauth2 import service_account
from googleapiclient.discovery import build

KEY_FILE = "key.key"

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        new_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(new_key)
        return new_key

ENCRYPTION_KEY = load_or_generate_key()
cipher = Fernet(ENCRYPTION_KEY)

case_list = []

def print_header():
    subprocess.run("figlet FIR Tool | lolcat", shell=True)

def check_dependencies():
    required_tools = ["figlet", "lolcat", "adb", "foremost", "yara", ]
    missing_tools = []
    
    for tool in required_tools:
        if subprocess.call(f"which {tool}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_tools.append(tool)

    if subprocess.call("pipx list | grep volatility3", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        missing_tools.append("volatility3 (pipx)")

    if missing_tools:
        print(f"Missing tools: {', '.join(missing_tools)}")
        print("Please install the missing tools:")
        print("sudo apt install figlet lolcat adb libimobiledevice foremost yara")
        print("pipx install volatility3")
        print("pip install cryptography yara-python")
        sys.exit(1)

def save_case_data(case_list):
    encrypted_data = cipher.encrypt(json.dumps(case_list).encode())
    with open("cases.enc", "wb") as f:
        f.write(encrypted_data)

def load_case_data():
    if os.path.exists("cases.enc"):
        with open("cases.enc", "rb") as f:
            encrypted_data = f.read()
        return json.loads(cipher.decrypt(encrypted_data).decode())
    return []

def create_case(case_name, investigator_name, description):
    case_id = hashlib.sha256(case_name.encode()).hexdigest()[:10]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pin = getpass.getpass("Set a PIN for this case: ")
    case_data = {
        "case_id": case_id,
        "case_name": case_name,
        "investigator": investigator_name,
        "description": description,
        "timestamp": timestamp,
        "status": "open",
        "pin": hashlib.sha256(pin.encode()).hexdigest(),
        "notes": [],
        "evidence": []
    }
    case_list.append(case_data)
    save_case_data(case_list)
    print(f"Case Created with ID: {case_id}")

def add_case_note(case_id, note):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to unlock this case: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                case["notes"].append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "note": note})
                save_case_data(case_list)
                print("Note added to the case.")
            else:
                print("Incorrect PIN.")
            return
    print(f"Case ID {case_id} not found.")

def add_evidence(case_id, evidence_name):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to unlock this case: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                case["evidence"].append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "evidence_name": evidence_name})
                save_case_data(case_list)
                print("Evidence added to the case.")
            else:
                print("Incorrect PIN.")
            return
    print(f"Case ID {case_id} not found.")

def list_all_cases():
    print("List of All Cases:")
    for case in case_list:
        print(f"Case ID: {case['case_id']} | Case Name: {case['case_name']} | Status: {case['status']}")

def lock_case(case_id):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to lock this case: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                case["status"] = "locked"
                save_case_data(case_list)
                print(f"Case {case_id} has been locked.")
            else:
                print("Incorrect PIN.")
            return
    print(f"Case ID {case_id} not found.")

def transfer_case(case_id, new_investigator):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to authorize case transfer: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                old_investigator = case["investigator"]
                case["investigator"] = new_investigator
                save_case_data(case_list)
                print(f"Case {case_id} has been successfully transferred from {old_investigator} to {new_investigator}.")
            else:
                print("Incorrect PIN. Case transfer not authorized.")
            return
    print(f"Case ID {case_id} not found.")

def view_case(case_id):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to view case details: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                print(f"Case ID: {case['case_id']}\nInvestigator: {case['investigator']}\nDescription: {case['description']}")
                print(f"Notes: {case['notes']}\nEvidence: {case['evidence']}")
            else:
                print("Incorrect PIN.")
            return
    print(f"Case ID {case_id} not found.")

def close_case(case_id):
    for case in case_list:
        if case["case_id"] == case_id:
            pin_check = getpass.getpass("Enter PIN to close this case: ")
            if hashlib.sha256(pin_check.encode()).hexdigest() == case["pin"]:
                case['status'] = 'closed'
                save_case_data(case_list)
                print(f"Case {case_id} closed.")
            else:
                print("Incorrect PIN.")
            return
    print(f"Case ID {case_id} not found.")

def image_disk(device):
    output_file = f"{device}_image.dd"
    subprocess.run(f"sudo dd if={device} of={output_file} bs=64K conv=noerror,sync", shell=True)
    print(f"Disk image saved to {output_file}")

def dump_memory(output_file):
    subprocess.run(f"volatility3 -f {output_file} --profile=Win7SP1x64", shell=True)
    print(f"Memory dumped to {output_file}")

def find_evidence(disk_image, file_type):
    subprocess.run(f"foremost -t {file_type} -i {disk_image} -o output_dir", shell=True)
    print(f"Evidence scanned for {file_type} in {disk_image}")

def collect_system_info():
    print("System Information:")
    os.system("uname -a | lolcat")
    os.system("ifconfig | lolcat")

def generate_hash(file_path):
    with open(file_path, "rb") as f:
        file_hash_md5 = hashlib.md5(f.read()).hexdigest()
        f.seek(0)  # Reset file pointer to the beginning
        file_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
    print(f"MD5: {file_hash_md5}\nSHA256: {file_hash_sha256}")

def generate_timeline():
    print("Generating forensic timeline (mock-up)...")
    os.system("grep -a 'timestamp' * | sort")

def recover_files(disk_image):
    subprocess.run(f"foremost -i {disk_image} -o output_dir", shell=True)
    print("File carving complete. Recovered files are in output_dir")

def memory_analysis(memory_dump):
    subprocess.run(f"volatility3 -f {memory_dump} pslist", shell=True)
    print("Memory analysis complete.")

def backup_files(file_paths, backup_dir):
    for file_path in file_paths:
        subprocess.run(f"cp {file_path} {backup_dir}", shell=True)
        print(f"Backed up {file_path} to {backup_dir}")

def restore_backup(backup_dir, restore_dir):
    subprocess.run(f"cp {backup_dir}/* {restore_dir}", shell=True)
    print(f"Restored backup from {backup_dir} to {restore_dir}")

def smart_search(disk_image, keyword):
    subprocess.run(f"grep -ai '{keyword}' {disk_image}", shell=True)
    print(f"Searched for '{keyword}' in {disk_image}")

def yara_scan(directory, yara_rule):
    subprocess.run(f"yara -r {yara_rule} {directory}", shell=True)
    print(f"YARA scan complete in {directory} using rule {yara_rule}")

# New Forensic Features

def brute_force_unlock(device):
    print(f"Starting brute force PIN/pattern unlock on device {device}...")

    for pin in range(10000):  # Assuming a 4-digit PIN
        pin_str = f"{pin:04d}"
        print(f"Trying PIN: {pin_str}")
        
        # Send PIN via ADB
        subprocess.run(f"adb -s {device} shell input text {pin_str}", shell=True)
        subprocess.run(f"adb -s {device} shell input keyevent 66", shell=True)  # KeyEvent 66 is the 'Enter' key

        # Introduce small delay between attempts to simulate human-like interaction and avoid detection
        time.sleep(1)

        # Check if the phone is unlocked (e.g., screen state check)
        output = subprocess.check_output(f"adb -s {device} shell dumpsys window | grep mCurrentFocus", shell=True)
        if b"com.android.systemui" not in output:
            print(f"Device unlocked with PIN: {pin_str}")
            break

    print("Brute force completed.")

def extract_mobile_data(device):
    print(f"Extracting data from {device}...")

    data_paths = [
        "/sdcard/",  
        "/storage/emulated/0/WhatsApp/Media/WhatsApp Images/",  
        "/storage/emulated/0/DCIM/",  
        "/storage/emulated/0/Download/"  
    ]

    for path in data_paths:
        print(f"Extracting data from {path}")
        subprocess.run(f"adb -s {device} pull {path} /output_dir", shell=True)

    print("Data extraction complete.")
    
    
    
def analyze_installed_apps():
    print("Analyzing installed apps...")
    subprocess.run("adb shell pm list packages", shell=True)

def recover_deleted_files(disk_image):
    print("Recovering deleted files...")
    subprocess.run(f"foremost -i {disk_image} -o recovered_files", shell=True)

def analyze_network_connections():
    print("Analyzing network connections...")
    subprocess.run("adb shell dumpsys netstats", shell=True)

def fetch_location_data():
    print("Fetching location data...")
    subprocess.run("adb shell dumpsys location", shell=True)

def extract_cloud_data():
    print("Accessing cloud backups...")
    # Placeholder for cloud integration; this function would handle the actual cloud extraction process

def check_root_status():
    print("Checking root/jailbreak status...")
    output = subprocess.run("adb shell su -c 'id'", shell=True, stdout=subprocess.PIPE)
    if b'root' in output.stdout:
        print("Device is rooted.")
    else:
        print("Device is not rooted.")

def scan_for_malware():
    print("Scanning for malware...")
    subprocess.run("yara -r malware_rules.yar /output_dir", shell=True)

    
    

def extract_icloud_data(username, password):
    print(f"Connecting to iCloud for {username}...")

    api = PyiCloudService(username, password)
    
    if api.requires_2sa:
        print("Two-factor authentication is required.")
        code = input("Enter the code you received: ")
        result = api.validate_2fa_code(code)
        if not result:
            print("Failed to validate code.")
            return
    
    for file in api.drive.dir().values():
        print(f"Downloading {file['name']} from iCloud...")
        with open(f"/output_dir/{file['name']}", "wb") as output_file:
            file.download(output_file)

    print("iCloud data extraction complete.")
    
    

def extract_google_drive_data():
    print("Connecting to Google Drive...")

    SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
    SERVICE_ACCOUNT_FILE = 'path_to_your_service_account.json'

    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    
    service = build('drive', 'v3', credentials=creds)

    results = service.files().list(pageSize=10, fields="files(id, name)").execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
        for item in items:
            file_id = item['id']
            file_name = item['name']
            print(f"Downloading {file_name} from Google Drive...")
            request = service.files().get_media(fileId=file_id)
            with open(f'/output_dir/{file_name}', 'wb') as output_file:
                output_file.write(request.execute())

    print("Google Drive data extraction complete.")

# Developer Bio
def bio():
    print("\nDeveloper Bio:")
    print("Name: Suleiman Yahaya Garo")
    print("Nickname: garogenius")
    print("Email: garogenius@gmail.com")
    print("Designation: SOC/Software Engineer")
    print("Specification: Ethical Hacker and Security Engineer")
    print("This tool is designed for ethical and security defense use.")

def help_menu():
    print("""
    FIR Tool Commands:
    - fir create_case "case_name" "investigator_name" "description": Create a new case
    - fir view_case "case_id": View details of a specific case
    - fir add_note "case_id" "note": Add a note to a specific case
    - fir add_evidence "case_id" "evidence_name": Add evidence to a specific case
    - fir list_cases: List all cases
    - fir lock_case "case_id": Lock a case with its PIN
    - fir transfer_case "case_id" "new_investigator": Transfer a case to another investigator
    - fir close_case "case_id": Close a case
    - fir image_disk "/dev/sda": Create disk image using dd
    - fir dump_memory "output.mem": Dump memory using volatility3
    - fir find_evidence "disk_image" "file_type": Search for specific files
    - fir collect_info: Collect system metadata
    - fir generate_hash "file_path": Generate file hash
    - fir generate_timeline: Generate forensic timeline
    - fir recover_files "disk_image": Recover deleted files
    - fir memory_analysis "memory_dump": Analyze memory dump
    - fir backup "file1 file2" "/backup_dir": Backup specified files
    - fir restore_backup "/backup_dir" "/restore_dir": Restore files from backup
    - fir smart_search "disk_image" "keyword": Search for keyword
    - fir yara_scan "/directory" "yara_rule": Scan with YARA rules
    - fir unlock_device: Attempt to unlock a mobile device
    - fir extract_data: Extract data from a mobile device
    - fir analyze_apps: Analyze installed apps on a mobile device
    - fir recover_deleted: Recover deleted files from a disk image
    - fir analyze_network: Analyze mobile network connections
    - fir fetch_location: Fetch location data from a mobile device
    - fir extract_cloud: Extract cloud-synced data from a mobile device
    - fir check_root: Check if the device is rooted or jailbroken
    - fir scan_malware: Scan for malware using YARA rules
    - fir bio: Developer bio
    - fir version: Display tool version
    - fir help: Display this help menu
    """)

def version():
    print("FIR Tool Version 2.0.0")

def update():
    print("Checking for updates (mock-up)...")
    print("FIR Tool is up to date.")

def uninstall():
    print("Uninstalling FIR Tool...")
    os.remove("cases.enc")
    print("Tool uninstalled successfully.")

commands = {
    "create_case": create_case,
    "view_case": view_case,
    "add_note": add_case_note,
    "add_evidence": add_evidence,
    "list_cases": list_all_cases,
    "lock_case": lock_case,
    "transfer_case": transfer_case, 
    "close_case": close_case,
    "image_disk": image_disk,
    "dump_memory": dump_memory,
    "find_evidence": find_evidence,
    "collect_info": collect_system_info,
    "generate_hash": generate_hash,
    "generate_timeline": generate_timeline,
    "recover_files": recover_files,  # Fixing this mapping
    "memory_analysis": memory_analysis,
    "backup": backup_files,
    "restore_backup": restore_backup,
    "smart_search": smart_search,
    "yara_scan": yara_scan,
    "brute_force_unlock": brute_force_unlock,
    "extract_data": extract_mobile_data,
    "extract_icloud": extract_icloud_data,
    "extract_google_drive": extract_google_drive_data,
    "analyze_apps": analyze_installed_apps,  # Matches analyze_installed_apps() function
    "recover_deleted": recover_deleted_files,  # Matches recover_deleted_files() function
    "analyze_network": analyze_network_connections,  # Matches analyze_network_connections() function
    "fetch_location": fetch_location_data,  # Matches fetch_location_data() function
    "extract_cloud": extract_cloud_data,  # Matches extract_cloud_data() function
    "check_root": check_root_status,  # Matches check_root_status() function
    "scan_malware": scan_for_malware,  # Matches scan_for_malware() function
    "bio": bio,
    "help": help_menu,
    "version": version,
    "update": update,
    "uninstall": uninstall
}

def main():
    try:
        check_dependencies()
        print_header()
        
        if len(sys.argv) < 2:
            print("No command provided. Use 'fir help' for usage.")
            sys.exit(1)

        command = sys.argv[1]
        if command in commands:
            commands[command](*sys.argv[2:])
        else:
            print("Invalid command. Use 'fir help' for usage.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    case_list = load_case_data()
    main()
