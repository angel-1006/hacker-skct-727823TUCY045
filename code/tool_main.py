# student_name: Sona Angel R A
# roll_number: 727823TUCY045
# project_name: StaticMalwareAnalyzer
# date: 2025-03-28

import os, sys, math, hashlib, struct, string, re, json, argparse
from datetime import datetime
from collections import Counter

ROLL_NUMBER  = "727823TUCY045"
STUDENT_NAME = "Sona Angel R A"

def print_banner():
    print("=" * 60)
    print(f"  Static Malware Analyzer | Roll No: {ROLL_NUMBER}")
    print(f"  Student   : {STUDENT_NAME}")
    print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

def compute_hashes(data):
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def compute_entropy(data):
    if not data:
        return 0.0
    freq  = Counter(data)
    total = len(data)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())

def extract_strings(data, min_len=4):
    printable = set(string.printable.encode())
    results, current = [], []
    for byte in data:
        if byte in printable:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc","VirtualProtect","CreateRemoteThread",
    "WriteProcessMemory","ReadProcessMemory","OpenProcess",
    "LoadLibraryA","GetProcAddress","RegSetValueEx",
    "ShellExecuteA","WinExec","CreateProcess",
    "IsDebuggerPresent","SetWindowsHookEx","GetAsyncKeyState",
    "CryptEncrypt","InternetOpenA","URLDownloadToFile",
    "WSAStartup","connect","send","recv",
}

def parse_pe(data):
    result = {"is_pe": False, "error": None}
    if data[:2] != b'MZ':
        result["error"] = "Not a PE file (no MZ header)"
        return result
    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            result["error"] = "Invalid PE signature"
            return result
        result["is_pe"] = True
        coff = e_lfanew + 4
        machine      = struct.unpack_from('<H', data, coff)[0]
        num_sections = struct.unpack_from('<H', data, coff+2)[0]
        timestamp    = struct.unpack_from('<I', data, coff+4)[0]
        opt_size     = struct.unpack_from('<H', data, coff+16)[0]
        machines = {0x014c:"x86",0x8664:"x64",0x01c0:"ARM"}
        result["machine"]    = machines.get(machine, f"0x{machine:04x}")
        result["sections"]   = num_sections
        result["compiled"]   = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S UTC")
        raw_str = " ".join(extract_strings(data))
        result["suspicious_imports"] = sorted(
            [a for a in SUSPICIOUS_IMPORTS if a in raw_str]
        )
    except struct.error as e:
        result["error"] = f"struct.error: {e}"
    return result

RULES = [
    ("Hardcoded IP",        rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    ("URL",                 rb'https?://[^\s"\']{8,}'),
    ("Registry key",        rb'HKEY_[A-Z_]+\\[^\x00\r\n]{4,}'),
    ("PowerShell encoded",  rb'(?i)powershell.*-enc'),
    ("CMD/PowerShell",      rb'(?i)cmd\.exe|powershell'),
    ("UPX packer",          rb'UPX[0-9!]'),
    ("Ransom keyword",      rb'(?i)bitcoin|ransom|decrypt|your files|\.onion'),
    ("Keylogger keyword",   rb'(?i)keystroke|GetAsyncKeyState|keylogger'),
    ("Base64 blob",         rb'[A-Za-z0-9+/]{40,}={0,2}'),
]

def scan_patterns(data):
    hits = []
    for name, pattern in RULES:
        matches = re.findall(pattern, data)
        if matches:
            sample = matches[0][:60].decode(errors='replace') if isinstance(matches[0], bytes) else str(matches[0])[:60]
            hits.append({"rule": name, "count": len(matches), "sample": sample})
    return hits

def risk_score(entropy, pe, patterns):
    score, reasons = 0, []
    if entropy >= 7.5:
        score += 35; reasons.append(f"Very high entropy ({entropy:.2f}) — packed/encrypted")
    elif entropy >= 6.5:
        score += 20; reasons.append(f"High entropy ({entropy:.2f}) — possible obfuscation")
    if pe.get("is_pe"):
        imps = pe.get("suspicious_imports", [])
        if len(imps) >= 5:
            score += 25; reasons.append(f"{len(imps)} suspicious API imports")
        elif len(imps) >= 2:
            score += 12; reasons.append(f"{len(imps)} suspicious API imports")
    dangerous = {"PowerShell encoded","UPX packer","Ransom keyword","Keylogger keyword"}
    for p in patterns:
        if p["rule"] in dangerous:
            score += 15; reasons.append(f"Dangerous pattern: {p['rule']}")
        else:
            score += 5
    score = min(score, 100)
    if score >= 70:   verdict = "HIGH RISK   🔴"
    elif score >= 40: verdict = "MEDIUM RISK 🟡"
    elif score >= 15: verdict = "LOW RISK    🟢"
    else:             verdict = "CLEAN       ✅"
    return score, verdict, reasons

def analyze_file(filepath):
    if not os.path.isfile(filepath):
        return {"error": f"File not found: {filepath}"}
    with open(filepath, "rb") as f:
        data = f.read()
    hashes   = compute_hashes(data)
    entropy  = round(compute_entropy(data), 4)
    strings  = extract_strings(data)
    pe       = parse_pe(data)
    patterns = scan_patterns(data)
    score, verdict, reasons = risk_score(entropy, pe, patterns)
    return {
        "file": filepath, "file_size_bytes": len(data),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hashes": hashes, "entropy": entropy,
        "string_count": len(strings), "sample_strings": strings[:10],
        "pe_info": pe, "pattern_matches": patterns,
        "risk_score": score, "verdict": verdict, "reasons": reasons,
    }

def print_report(r):
    sep = "─" * 60
    print(f"\n{sep}")
    print(f"  FILE    : {r['file']}")
    print(f"  SIZE    : {r['file_size_bytes']} bytes")
    print(f"  TIME    : {r['timestamp']}")
    print(sep)
    print(f"  MD5     : {r['hashes']['md5']}")
    print(f"  SHA256  : {r['hashes']['sha256']}")
    print(sep)
    print(f"  Entropy : {r['entropy']} / 8.0")
    print(f"  Strings : {r['string_count']} found")
    pe = r["pe_info"]
    if pe.get("is_pe"):
        print(f"  PE Type : Machine={pe['machine']}  Sections={pe['sections']}")
        print(f"  Compiled: {pe['compiled']}")
        imps = pe.get("suspicious_imports", [])
        if imps:
            print(f"  Suspicious Imports ({len(imps)}): {', '.join(imps[:5])}")
    else:
        print(f"  PE Info : {pe.get('error','Not a PE file')}")
    print(sep)
    if r["pattern_matches"]:
        print("  Patterns found:")
        for p in r["pattern_matches"]:
            print(f"    [{p['rule']:22s}] x{p['count']}  eg: {p['sample'][:45]}")
    else:
        print("  Patterns : None found")
    print(sep)
    print(f"  SCORE   : {r['risk_score']} / 100")
    print(f"  VERDICT : {r['verdict']}")
    for reason in r["reasons"]:
        print(f"    • {reason}")
    print(f"{sep}\n")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Static Malware Analyzer")
    parser.add_argument("files", nargs="+", help="File(s) to analyze")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    args = parser.parse_args()
    for filepath in args.files:
        print(f"\n[*] Analyzing: {filepath}")
        report = analyze_file(filepath)
        if "error" in report:
            print(f"  ERROR: {report['error']}")
            continue
        print_report(report)
        if args.json:
            out = filepath + "_report.json"
            with open(out, "w") as f:
                json.dump(report, f, indent=2)
            print(f"  [+] JSON saved → {out}")

if __name__ == "__main__":
    main()
