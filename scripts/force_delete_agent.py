#!/usr/bin/env python3
"""Force-delete the CyberNova agent installation at C:\Program Files\CyberNova."""

import os
import shutil
import subprocess
import time
import sys

AGENT_DIR = r"C:\Program Files\CyberNova"

def run_cmd(cmd):
    """Run a command and return output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def kill_processes():
    """Kill any processes that might be holding agent files open."""
    targets = [
        ["taskkill", "/F", "/IM", "python.exe"],
        ["taskkill", "/F", "/IM", "pythonw.exe"],
        ["taskkill", "/F", "/IM", "powershell.exe"],
        ["taskkill", "/F", "/IM", "cmd.exe"],
    ]
    for target in targets:
        output = run_cmd(target)
        print(f"  {' '.join(target[-2:])}: {output.strip()}")

    # Also try to stop any CyberNova scheduled task
    run_cmd(["schtasks", "/end", "/tn", "CyberNova-HostDefender"])
    run_cmd(["schtasks", "/delete", "/tn", "CyberNova-HostDefender", "/f"])

    time.sleep(2)  # wait for processes to fully close handles

def force_delete_dir():
    """Delete the agent directory by any means necessary."""
    if not os.path.exists(AGENT_DIR):
        print(f"Directory '{AGENT_DIR}' does not exist. Nothing to delete.")
        return True

    print(f"Attempting to delete: {AGENT_DIR}")

    # First try normal shutil.rmtree
    try:
        shutil.rmtree(AGENT_DIR, ignore_errors=False)
        if not os.path.exists(AGENT_DIR):
            print("Deleted successfully via shutil.rmtree!")
            return True
    except Exception as e:
        print(f"shutil.rmtree failed: {e}")

    # If that fails, try with retries and handle individual files
    for attempt in range(5):
        print(f"Attempt {attempt + 1} with retry logic...")
        try:
            for root, dirs, files in os.walk(AGENT_DIR, topdown=False):
                for name in files:
                    fpath = os.path.join(root, name)
                    try:
                        os.chmod(fpath, 0o777)
                        os.remove(fpath)
                        print(f"  Removed: {fpath}")
                    except Exception as e:
                        print(f"  Failed: {fpath} - {e}")
                for name in dirs:
                    dpath = os.path.join(root, name)
                    try:
                        os.rmdir(dpath)
                        print(f"  Removed dir: {dpath}")
                    except Exception as e:
                        print(f"  Failed dir: {dpath} - {e}")
            # Try root dir
            try:
                os.rmdir(AGENT_DIR)
                print("Root directory removed!")
                return True
            except Exception as e:
                print(f"Root dir removal failed: {e}")
        except Exception as e:
            print(f"Walk error: {e}")

        if not os.path.exists(AGENT_DIR):
            return True

        # Try harder: use cmd's rmdir
        output = run_cmd(["cmd", "/c", f'rmdir /S /Q "{AGENT_DIR}"'])
        print(f"  cmd rmdir: {output.strip()}")

        if not os.path.exists(AGENT_DIR):
            print("Deleted via cmd rmdir!")
            return True

        time.sleep(2)

    return False

def main():
    print("=" * 60)
    print("CyberNova Agent Force Deletion Tool")
    print("=" * 60)

    if not os.path.exists(AGENT_DIR):
        print(f"\nDirectory '{AGENT_DIR}' does not exist. Nothing to delete.")
        return

    print(f"\n[Step 1/3] Killing processes with handles on {AGENT_DIR}...")
    kill_processes()

    print(f"\n[Step 2/3] Deleting {AGENT_DIR}...")
    success = force_delete_dir()

    print(f"\n[Step 3/3] Result:")
    if success:
        print(f"  ✅ '{AGENT_DIR}' has been completely removed!")
    else:
        remaining = os.path.exists(AGENT_DIR)
        if remaining:
            print(f"  ❌ Some files could not be deleted.")
            print(f"     Try rebooting your computer, then delete the folder manually.")
            print(f"     1. Open cmd as Administrator")
            print(f"     2. Run: rmdir /S /Q \"{AGENT_DIR}\"")
            print(f"     3. If that fails, restart and try again.")
        else:
            print(f"  ✅ Deleted successfully!")


if __name__ == "__main__":
    main()
