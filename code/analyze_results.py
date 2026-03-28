# Sona Angel R A | 727823TUCY045
# student_name: Sona Angel R A
# roll_number: 727823TUCY045
# project_name: StaticMalwareAnalyzer
# date: 2025-03-28

import os, json
from datetime import datetime

ROLL_NUMBER = "727823TUCY045"

print(f"ROLL_NUMBER : {ROLL_NUMBER}")
print(f"TIMESTAMP   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"SCRIPT      : analyze_results.py — Stage 3 (Analysis)")
print("-" * 65)

BASE    = os.path.dirname(os.path.abspath(__file__))
ROOT    = os.path.join(BASE, "..")
OUTDIR  = os.path.join(ROOT, "outputs", "reports")

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

combined = os.path.join(OUTDIR, "all_reports.json")
if not os.path.isfile(combined):
    log("ERROR: all_reports.json not found. Run run_tool.py first.")
    raise SystemExit(1)

with open(combined) as f:
    reports = json.load(f)

log(f"Loaded {len(reports)} report(s)")

print("\n" + "=" * 75)
print(f"{'FILE':30s} {'SIZE':>8} {'ENTROPY':>8} {'SCORE':>6}  VERDICT")
print("=" * 75)
for r in reports:
    fname = os.path.basename(r["file"])[:29]
    print(f"{fname:30s} {r['file_size_bytes']:>8} "
          f"{r['entropy']:>8.4f} {r['risk_score']:>6}  {r['verdict']}")
print("=" * 75)

scores    = [r["risk_score"] for r in reports]
entropies = [r["entropy"]    for r in reports]

print(f"\n── Statistics ──")
print(f"  Total files  : {len(reports)}")
print(f"  Avg score    : {sum(scores)/len(scores):.1f}")
print(f"  Max score    : {max(scores)}")
print(f"  Min score    : {min(scores)}")
print(f"  Avg entropy  : {sum(entropies)/len(entropies):.4f}")

print(f"\n── Verdict Distribution ──")
counts = {}
for r in reports:
    v = r["verdict"].strip()
    counts[v] = counts.get(v, 0) + 1
for v, c in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {v:20s} : {c} file(s)")

print("-" * 65)
log(f"Stage 3 COMPLETE — ROLL_NUMBER : {ROLL_NUMBER}")
