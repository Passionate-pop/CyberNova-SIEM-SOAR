"""
CyberNova — Continuous Attack Generator
Runs REAL_HACKER_ATTACK.py in a loop every 25 seconds
"""
import subprocess, time, sys, os
from datetime import datetime

script_dir = os.path.dirname(os.path.abspath(__file__))
attack_script = os.path.join(script_dir, "REAL_HACKER_ATTACK.py")
run_count = 0
total_alerts = 0

print("=" * 60)
print("  CYBERNOVA — CONTINUOUS ATTACK GENERATOR")
print("  Running attacks every 25 seconds")
print("  Dashboard: http://localhost:8080/app/")
print("=" * 60)

while True:
    run_count += 1
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{ts}] Run #{run_count} — launching 13 attacks...")
    
    start = time.time()
    result = subprocess.run(
        [sys.executable, attack_script],
        capture_output=True, text=True, timeout=60,
        cwd=os.path.dirname(script_dir)
    )
    elapsed = time.time() - start
    
    # Parse alerts from output
    alerts_found = 0
    for line in result.stdout.split("\n"):
        if "alerts created" in line.lower() or "alerts found" in line.lower():
            try:
                parts = line.split()
                for p in parts:
                    if p.isdigit():
                        alerts_found = int(p)
                        break
            except:
                pass
        if "CRITICAL:" in line or "HIGH:" in line or "MEDIUM:" in line:
            print(f"    {line.strip()}")
    
    if alerts_found:
        total_alerts = alerts_found
        print(f"  [{ts}] DONE — {alerts_found} alerts on dashboard ({elapsed:.0f}s)")
    else:
        # If it didn't print alerts, check the output differently
        print(f"  [{ts}] DONE ({elapsed:.0f}s)")
    
    # Show stderr if any
    if result.stderr.strip():
        for line in result.stderr.split("\n")[-3:]:
            print(f"  stderr: {line.strip()}")
    
    print(f"  [{ts}] Waiting 25s before next wave...")
    time.sleep(25)
