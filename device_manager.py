import json
import os

TRUSTED_FILE = "trusted_devices.json"

def load_trusted():
    if not os.path.exists(TRUSTED_FILE):
        return {}
    with open(TRUSTED_FILE, "r") as f:
        return json.load(f)

def save_trusted(devices):
    with open(TRUSTED_FILE, "w") as f:
        json.dump(devices, f, indent=2)

def add_trusted(ip, mac):
    trusted = load_trusted()
    trusted[ip] = mac
    save_trusted(trusted)

def remove_trusted(ip):
    trusted = load_trusted()
    if ip in trusted:
        del trusted[ip]
        save_trusted(trusted)
