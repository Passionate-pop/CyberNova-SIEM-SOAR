#!/usr/bin/env python3
"""
Convenience runner to execute load tests for a given EPS profile.
Usage:
    python tests/load/run.py --profile 10k-eps
    python tests/load/run.py --profile 100k-eps --workers 4 --web

Launches locust with the correct user count and spawn rate for the profile.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from tests.load.configs import PROFILES, PROFILE_LABELS


def main():
    parser = argparse.ArgumentParser(description="CyberNOVA Pipeline Load Test Runner")
    parser.add_argument(
        "--profile", "-p",
        choices=PROFILE_LABELS,
        default="10k-eps",
        help="EPS profile to run",
    )
    parser.add_argument(
        "--host", "-H",
        default="http://localhost:8000",
        help="Pipeline API host",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of Locust worker processes (default: 1, 0 = standalone)",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start the web UI (default: headless)",
    )
    parser.add_argument(
        "--run-time", "-t",
        default=None,
        help="Override run time (e.g. 5m, 1h)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Unique run identifier for this load test",
    )
    args = parser.parse_args()

    profile = next(p for p in PROFILES if p.label == args.profile)
    os.environ["LOCUST_EPS_PROFILE"] = args.profile
    os.environ["LOCUST_PIPELINE_HOST"] = args.host
    if args.run_id:
        os.environ["LOCUST_RUN_ID"] = args.run_id

    locust_dir = Path(__file__).resolve().parent
    cmd = [
        sys.executable, "-m", "locust",
        "-f", str(locust_dir / "locustfile.py"),
        "--host", args.host,
        "--users", str(profile.num_users),
        "--spawn-rate", str(profile.spawn_rate),
    ]

    if args.run_time:
        cmd.extend(["--run-time", args.run_time])
    elif profile.run_time_sec:
        minutes = profile.run_time_sec // 60
        cmd.extend(["--run-time", f"{minutes}m"])

    if args.web:
        cmd.extend([ "--web-port", "8089"])
    else:
        cmd.append("--headless")

    if args.workers > 1:
        cmd.extend(["--master", "--expect-workers", str(args.workers)])

    print(f"Starting load test: profile={args.profile} users={profile.num_users} target_eps={profile.target_eps}")
    print(f"  Command: {' '.join(cmd)}")
    sys.stdout.flush()

    if args.workers > 1:
        workers = []
        for i in range(args.workers):
            worker_cmd = [
                sys.executable, "-m", "locust",
                "-f", str(locust_dir / "locustfile.py"),
                "--worker",
                "--master-host", "127.0.0.1",
            ]
            p = subprocess.Popen(worker_cmd)
            workers.append(p)
        master = subprocess.Popen(cmd)
        master.wait()
        for w in workers:
            w.terminate()
    else:
        proc = subprocess.Popen(cmd)
        proc.wait()


if __name__ == "__main__":
    main()
