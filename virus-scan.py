import requests
import time
import os 
import dotenv

dotenv.load_dotenv()

# VirusTotal API key (set in environment)
VT_API_KEY = os.environ.get("VT_API_KEY", "")

FILE_PATH = "<PATH_TO_FILE>"

headers = {"x-apikey": VT_API_KEY}

# --- Upload File ---
print("[*] Uploading file to VirusTotal...")
with open(FILE_PATH, "rb") as f:
    files = {"file": (FILE_PATH, f)}
    upload = requests.post("https://www.virustotal.com/api/v3/files",
                           headers=headers, files=files)

upload_data = upload.json()
analysis_id = upload_data["data"]["id"]
print(f"[*] Analysis ID: {analysis_id}")

# --- Wait for Scan to Finish ---
print("[*] Waiting for analysis...")
while True:
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers).json()
    status = analysis["data"]["attributes"]["status"]
    if status == "completed":
        break
    time.sleep(5)  # wait 5s before checking again

# --- Process Results ---
stats = analysis["data"]["attributes"]["stats"]
malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)

print("\n=== Scan Results ===")
print(f"Malicious: {malicious}")
print(f"Suspicious: {suspicious}")
print(f"Harmless: {stats.get('harmless', 0)}")
print(f"Undetected: {stats.get('undetected', 0)}")

# --- Decide if Good or Bad ---
if malicious > 0 or suspicious > 0:
    print("\n🚨 BAD FILE: This file is flagged as malicious/suspicious.")
else:
    print("\n✅ GOOD FILE: No detections reported.")
