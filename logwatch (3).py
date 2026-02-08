"""
LogWatch Security Monitor
Author: Devon Williams
Description:
Monitors system logs suspicious activity, assigns risk levels,
detects brute-force patterns, and generates security reports.
"""

import re
from collections import Counter
from datetime import datetime

LOG_FILE ="samplelog"
print("looking for log file:", LOG_FILE)
ALERTS_FILE = "alerts.log"
OVERRIDE_RULES = {"unauthorized": "HIGH", "denied": "MEDIUM",}
SUSPICIOUS_KEYWORDS = [
    "failed",
    "error",
    "denied",
    "unauthorized",
    "invalid",
    "timeout",
    ]
SEVERITY= {
    "error": "HIGH",
    "unauthorized": "HIGH",
    "failed": "MEDIUM",
    "invalid": "MEDIUM",
    "timeout": "LOW",
    "denied": "LOW",
}   

RISK_WEIGHT = {
    "HIGH": 5,
    "MEDIUM": 3,
    "LOW": 1,
}
    
def load_logs(filename: str) -> list:
    try:
        with open(filename, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        print("Log file not found.")
        return []
        
        
def scan_logs(lines: list) -> dict:
    counts = Counter()
    examples = {k: [] for k in SUSPICIOUS_KEYWORDS}
    
    for line in lines:
        line_lower = line.lower()
        
        for word in SUSPICIOUS_KEYWORDS:
            if word in line_lower:
                counts[word] += 1
                if len(examples[word]) < 3: # keep 3 example lines per keyword
                    examples[word].append(line.strip())
    
    return {"counts": counts, "examples": examples}
    

def calc_risk_score(counts: Counter) -> int:
    score = 0
    
    for keyword, count in counts.items():
        severity = SEVERITY.get(keyword, "LOW")
        score += RISK_WEIGHT[severity] * count
        
    return score
    
def risk_label(score: int) -> str:
    if score >= 15:
        return "CRITICAL"
    elif score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif level == "MEDIUM":
        print("\n Notice: MEDIUM risk dectected.")
        print("Action: Review withn 24 hours, correlate with other logs.\n")
    else:
        print("\n Info: LOW risk activity.")
        print("Action: Monitor only.\n")
            
def build_report(counts: Counter, examples: dict) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    score = calc_risk_score(counts)
    level = risk_label(score)
    
    lines = []
    
    lines.append("=== LogWatch Security Monitor ===")
    lines.append(f"Generated: {timestamp}")
    lines.append("")
    lines.append("--- Threat Summary ---")
    
    if not counts:
        lines.append("No suspicious activity found.")
    else:
         for keyword, count in counts.most_common():
             severity = SEVERITY.get(keyword, " LOW")
             lines.append(f"{keyword.upper():<12} : {count} (severity={severity})")
         for example in examples.get(keyword, []):
             lines.append(f" - {example}")
            
    lines.append("")
    lines.append("--- Risk Assessment ---")
    lines.append(f"Score: {score} | Level: {level}")
    
    return "\n".join(lines)
    
def export_report(report: str, filename="logwatch_report.txt") -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[+] Report saved as {filename}")

def log_alert(level: str, score: int, counts: Counter) -> None:
    """Append a single alert line to alerts.log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = ", ".join([f"{k}={v}" for k, v in counts.items()])
    line = f"{ts} | level={level} | score={score} | {summary}\n"
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(line)
def top_findings(counts: Counter, n: int = 3) -> list:
    """Return top N keyword findings as list of (keyword, count)."""
    return counts.most_common(n)

def apply_override(level: str, counts: Counter) -> str:
    """Force the risk level upward if certain keywords appear.
       Example: unathorized >= 1 forces HIGH."""
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    
    forced = level
    for keyword, forced_level in OVERRIDE_RULES.items():
        if counts.get(keyword, 0) >= 1:
            if rank[forced_level] > rank[forced]:
                forced = forced_level
    return forced
    
    
def main() -> None:
    logs = load_logs(LOG_FILE)
    if not logs:
        return
    
    results = scan_logs(logs)
    counts = results["counts"]
    examples = results["examples"]
    score = calc_risk_score(counts)
    level = risk_label(score)
    level = apply_override(level, counts)
    report = build_report(counts, examples)
    print("\n" + report)
    export_report(report)
    print("\n--- Top Findings ---")
    for k, c in top_findings(counts, 3):
        print(f"{k.upper():12} : {c}")
    if level == "CRITICAL":
        print("\n [ALERT] Critical security risk detected!")
        print("Immediate investigation required.\n")
    elif level == "HIGH":
        print("\n [WARNING] High risk activity detected.\n")
    elif level == "MEDIUM":
        print("\n Notice: MEDIUM risk detected.")
        print("Action: Review within 24 hours, correlate with other logs.\n")
    else:
        print("\n [Info] LOW risk activity.")
        print("Action: Monitor only.\n")
        
    if level in ("MEDIUM", "HIGH", "CRITICAL"):
        log_alert(level, score, counts)
        print(f"[=] Alert written to {ALERTS_FILE}")
            
if __name__ == "__main__":
    main()