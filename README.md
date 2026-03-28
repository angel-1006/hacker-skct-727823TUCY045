# Static Malware Analyzer
**Roll No:** 727823TUCY045 | **Student:** Sona Angel R A
**Category:** Malware Analysis / Cybersecurity
**Repo:** hacker-skct-727823TUCY045

---

## What This Tool Does
A Python tool that examines suspicious files **without executing them**.
It checks file hashes, entropy, PE headers, suspicious imports,
and dangerous patterns to give a risk score from 0 to 100.

---

## Lab Environment
- OS: Kali Linux (VirtualBox VM)
- Python: 3.13
- All testing done on synthetic files created by the student
- No real malware was used at any point

---

## Setup
```bash
git clone https://github.com/angel-1006/hacker-skct-727823TUCY045.git
cd hacker-skct-727823TUCY045
pip3 install -r requirements.txt --break-system-packages
```

---

## Usage

### Analyze a single file
```bash
python3 code/tool_main.py test_samples/sample_benign.txt
```

### Analyze all files
```bash
python3 code/tool_main.py test_samples/*
```

### Run full pipeline
```bash
python3 code/setup_lab.py
python3 code/run_tool.py
python3 code/analyze_results.py
```

---

## Test Results

| # | File | Entropy | Score | Verdict |
|---|------|---------|-------|---------|
| 1 | sample_benign.txt | ~4.9 | 0 | CLEAN |
| 2 | sample_suspicious.ps1 | ~5.5 | 50 | MEDIUM RISK |
| 3 | sample_ransom.txt | ~5.1 | 20 | LOW RISK |

---

## Project Structure
```
SKCT_727823TUCY045_StaticMalwareAnalyzer/
├── code/
│   ├── tool_main.py
│   ├── setup_lab.py
│   ├── run_tool.py
│   └── analyze_results.py
├── test_samples/
├── outputs/
├── screenshots/
├── notebooks/
├── report/
├── pipeline_727823TUCY045.yml
├── requirements.txt
└── README.md
```

---

## Ethical Notice
All testing was done on synthetic files created by the student
inside an isolated VirtualBox VM. No real malware was used.
