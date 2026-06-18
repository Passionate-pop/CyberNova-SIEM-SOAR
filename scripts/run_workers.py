"""
CyberNova — Run All Pipeline Workers
python scripts/run_workers.py [normalizer|enrichment|detection|correlation|soar|all]
"""
from __future__ import annotations

import asyncio
import multiprocessing as mp
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run_worker(stage: str):
    import subprocess
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from cybernova.streaming.pipeline_worker import main as pipeline_main
    from cybernova.streaming.soar_worker import main as soar_main

    if stage == "soar":
        asyncio.run(soar_main())
    else:
        sys.argv = ["worker.py", stage]
        asyncio.run(pipeline_main())


def main():
    if len(sys.argv) < 2:
        stages = ["normalizer", "enrichment", "detection", "correlation", "soar"]
        print(f"Starting all {len(stages)} workers...")
        processes = []
        for stage in stages:
            p = mp.Process(target=run_worker, args=(stage,))
            p.start()
            processes.append(p)
            print(f"  Started {stage} worker (PID={p.pid})")
        for p in processes:
            p.join()
    else:
        stage = sys.argv[1]
        print(f"Starting {stage} worker...")
        run_worker(stage)


if __name__ == "__main__":
    main()
