import sys
import urllib.request

try:
    req = urllib.request.Request("http://localhost:8000/health")
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status == 200:
            sys.exit(0)
        else:
            print(f"Health check failed: HTTP {resp.status}", file=sys.stderr)
            sys.exit(1)
except Exception as e:
    print(f"Health check error: {e}", file=sys.stderr)
    sys.exit(1)
