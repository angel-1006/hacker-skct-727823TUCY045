# Sona Angel R A | 727823TUCY045
# student_name: Sona Angel R A
# roll_number: 727823TUCY045
# project_name: StaticMalwareAnalyzer
# date: 2025-03-28

import os, sys, subprocess
from datetime import datetime

ROLL_NUMBER = "727823TUCY045"

print(f"ROLL_NUMBER : {ROLL_NUMBER}")
print(f"TIMESTAMP   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"SCRIPT      : setup_lab.py — Stage 1 (Lab Setup)")
print("-" * 55)

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, "..")

DIRS = [
    "test_samples", "outputs/reports",
    "outputs/logs", "screenshots",
    "report", "notebooks"
]

for d in DIRS:
    path = os.path.join(ROOT, d)
    os.makedirs(path, exist_ok=True)
    log(f"Directory OK : {d}")

log("Installing dependencies...")
try:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install",
         "reportlab", "--quiet", "--break-system-packages"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    log("pip install  : OK (reportlab)")
except Exception as e:
    log(f"pip warning  : {e}")

SAMPLES = os.path.join(ROOT, "test_samples")

s1 = os.path.join(SAMPLES, "sample_benign.txt")
with open(s1, "w") as f:
    f.write("# Configuration file\nserver=localhost\nport=8080\n")
    f.write("log_level=INFO\nauthor=Sona Angel R A\nroll=727823TUCY045\n")
log(f"Sample 1 OK : {s1}")

s2 = os.path.join(SAMPLES, "sample_suspicious.ps1")
with open(s2, "w") as f:
    f.write("# Synthetic test script - not real malware\n")
    f.write("# roll_number: 727823TUCY045\n")
    f.write("powershell -EncodedCommand dABlAHMAdAA=\n")
    f.write('$url = "http://192.168.1.100/payload"\n')
    f.write("GetAsyncKeyState keystroke logger test\n")
    f.write("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
log(f"Sample 2 OK : {s2}")

s3 = os.path.join(SAMPLES, "sample_ransom.txt")
with open(s3, "w") as f:
    f.write("YOUR FILES HAVE BEEN ENCRYPTED\n")
    f.write("Send 0.05 bitcoin to wallet address\n")
    f.write("Visit http://darksite.onion/decrypt for key\n")
    f.write("ransom deadline is 72 hours\n")
log(f"Sample 3 OK : {s3}")

print("-" * 55)
log(f"Stage 1 COMPLETE — ROLL_NUMBER : {ROLL_NUMBER}")
