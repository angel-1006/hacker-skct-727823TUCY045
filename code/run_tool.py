# Sona Angel R A | 727823TUCY045
# student_name: Sona Angel R A
# roll_number: 727823TUCY045
# project_name: StaticMalwareAnalyzer
# date: 2025-03-28

import os, sys, json, csv
from datetime import datetime

ROLL_NUMBER = "727823TUCY045"

print(f"ROLL_NUMBER : {ROLL_NUMBER}")
print(f"TIMESTAMP   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"SCRIPT      : run_tool.py — Stage 2 (Tool Execution)")
print("-" * 55)

BASE     = os.path.dirname(os.path.abspath(__file__))
ROOT     = os.path.join(BASE, "..")
SAMPLES  = os.path.join(ROOT, "test_samples")
OUTDIR   = os.path.join(ROOT, "outputs", "reports")
LOGDIR   = os.path.join(ROOT, "outputs", "logs")

os.makedirs(OUTDIR, exist_ok=True)
os.makedirs(LOGDIR, exist_ok=True)

sys.path.insert(0, BASE)
from tool_main import analyze_file, print_report

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

files = sorted([
    os.path.join(SAMPLES, f)
    for f in os.listdir(SAMPLES)
    if os.path.isfile(os.path.join(SAMPLES, f))
])

log(f"Found {len(files)} sample file(s)")

all_reports = []

for i, filepath in enumerate(files, 1):
    log(f"[{i}/{len(files)}] Analyzing: {os.path.basename(filepath)}")
    report = analyze_file(filepath)
    if "error" in report:
        log(f"  ERROR: {report['error']}")
        continue
    print_report(report)
    all_reports.append(report)

    jname = os.path.basename(filepath).replace(".", "_") + "_report.json"
    jpath = os.path.join(OUTDIR, jname)
    with open(jpath, "w") as jf:
        json.dump(report, jf, indent=2)
    log(f"  JSON saved → {jname}")

combined = os.path.join(OUTDIR, "all_reports.json")
with open(combined, "w") as cf:
    json.dump(all_reports, cf, indent=2)
log(f"Combined JSON → all_reports.json")

csv_path = os.path.join(OUTDIR, "summary.csv")
fields = ["file","file_size_bytes","entropy","string_count",
          "risk_score","verdict","timestamp"]
with open(csv_path, "w", newline="") as cf:
    writer = csv.DictWriter(cf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in all_reports:
        r2 = dict(r)
        r2["file"] = os.path.basename(r2["file"])
        writer.writerow(r2)
log(f"CSV saved     → summary.csv")

logfile = os.path.join(LOGDIR, "run_tool.log")
with open(logfile, "w") as lf:
    lf.write(f"roll_number: {ROLL_NUMBER}\n")
    lf.write(f"timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lf.write("=" * 55 + "\n")
    for r in all_reports:
        lf.write(
            f"{r['timestamp']} | {os.path.basename(r['file']):30s} | "
            f"entropy={r['entropy']:.4f} | score={r['risk_score']:3d} | {r['verdict']}\n"
        )
log(f"Log saved     → run_tool.log")

print("-" * 55)
log(f"Stage 2 COMPLETE — analyzed {len(all_reports)} file(s)")
log(f"ROLL_NUMBER : {ROLL_NUMBER}")
