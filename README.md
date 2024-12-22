# SMB Brute Force Tool

## Overview
This is a Python-based SMB Brute Force tool designed for penetration testing and security auditing. It attempts to crack SMB credentials by iterating through a list of usernames and passwords. 

> **Disclaimer**: Ensure you have explicit permission to test the target system before using this tool. Unauthorized access to computer systems is illegal and unethical.

## Features
- Supports brute forcing SMB credentials with provided username and password lists.
- Outputs results to the console, indicating whether valid credentials were found or not.
- Handles errors gracefully, including file reading issues and SMB login failures.

## Example :

```bash
python SMB_Brute-Force_Tool.py 192.168.1.100 usernames.txt passwords.txt

