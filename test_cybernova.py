"""
CyberNova — Complete End-to-End System Test
Tests EVERYTHING in one run against live Docker stack.
"""
import requests, json, time, subprocess, sys

BASE = "http://localhost:8000"
PASS = 0; FAIL = 0; STEP = 1

def s(name):
    global STEP
    print(f"\n--- STEP {STEP}: {name} ---")
    STEP += 1

def ok(name, detail=""):
    global PASS; PASS += 1
    print(f"  [PASS] {name} {detail}")

def fail(name, detail=""):
    global FAIL; FAIL += 1
    print(f"  [FAIL] {name} {detail}")

print("="*70)
print("CYBERNOVA — FULL SYSTEM END-TO-END TEST")
print("="*70)

# STEP 1
s("DOCKER STACK")
r = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Status}}"], capture_output=True, text=True, timeout=10)
for l in [x for x in r.stdout.strip().split("\n") if x]:
    (ok if "healthy" in l else fail)(f"Container: {l}")

# STEP 2
s("BACKEND HEALTH")
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    ok("Backend healthy", f'uptime={r.json()["uptime_seconds"]}s') if r.ok and r.json().get("status")=="healthy" else fail("Backend health", str(r.status_code))
except Exception as e: fail("Backend health", str(e))

# STEP 3
s("AUTH — REGISTER")
uname = "e2e_"+str(int(time.time()))
r = requests.post(f"{BASE}/api/v1/auth/register", json={"username":uname,"email":uname+"@t.io","password":"TestPass123!","roles":["admin"]}, timeout=10)
ok(f"Registered: {uname}") if r.ok else fail("Register", f"{r.status_code}")

# STEP 4
s("AUTH — LOGIN")
r = requests.post(f"{BASE}/api/v1/auth/login", json={"username":uname,"password":"TestPass123!"}, timeout=10)
token = ""
if r.ok:
    token = r.json().get("access_token") or r.json().get("token","")
    ok("Login OK") if token else fail("No token")
else: fail("Login", str(r.status_code))

if not token: print("\nABORT: No token"); sys.exit(1)
h = {"Authorization": f"Bearer {token}"}

# STEP 5
s("AUTH — PROFILE")
r = requests.get(f"{BASE}/api/v1/auth/me", headers=h, timeout=5)
ok(f'User: {r.json()["username"]} Role: {r.json()["role"]}') if r.ok else fail("Profile", str(r.status_code))

# STEP 6-20: API Endpoints
for step_name, method, path, body in [
    ("DASHBOARD SUMMARY", "get", "/api/v1/dashboard/summary", None),
    ("DASHBOARD ALERTS", "get", "/api/v1/dashboard/alerts", None),
    ("DETECT ALERTS", "get", "/api/v1/detect/alerts", None),
    ("DETECT INCIDENTS", "get", "/api/v1/detect/incidents", None),
    ("DETECT RULES", "get", "/api/v1/detect/rules", None),
    ("DETECT STATS", "get", "/api/v1/detect/stats", None),
    ("DEVICES LIST", "get", "/api/v1/devices", None),
    ("SOAR PLAYBOOKS", "get", "/api/v1/automation/playbooks", None),
    ("AI ASK", "post", "/api/v1/ai/ask", {"query": "Show me top threats"}),
    ("PIPELINE STATUS", "get", "/api/v1/pipeline/status", None),
    ("AUDIT LOGS", "get", "/api/v1/audit/logs", None),
    ("ADMIN USERS", "get", "/api/v1/admin/users", None),
    ("ADMIN DEVICES", "get", "/api/v1/admin/devices", None),
    ("RAG SEARCH", "get", "/api/rag/search?q=test", None),
    ("RAG DOCUMENTS", "get", "/api/rag/documents", None),
    ("WORM ENTRIES", "get", "/api/v1/worm/entries", None),
    ("CSPM PROVIDERS", "get", "/api/v1/cspm/providers", None),
    ("COMPLIANCE STDS", "get", "/api/v1/compliance/standards", None),
    ("ANALYTICS SUMMARY", "get", "/api/v1/analytics/summary", None),
    ("TESTING TESTS", "get", "/api/v1/testing/tests", None),
    ("MONITORING METRICS", "get", "/api/v1/monitoring/metrics", None),
]:
    fn = requests.post if method == "post" else requests.get
    kwargs = {"headers": h, "timeout": 10}
    if body: kwargs["json"] = body
    try:
        r = fn(BASE + path, **kwargs)
        (ok if r.ok else fail)(step_name, str(r.status_code))
    except Exception as e: fail(step_name, str(e))

# NGINX
s("NGINX — FULL STACK")
try:
    r = requests.get("http://localhost:8888/", timeout=5)
    ok("Homepage", "200+CyberNova") if r.ok and "CyberNova" in r.text else fail("Homepage", str(r.status_code))
except: fail("Homepage", "unreachable")

for page in ["/features","/platform","/pricing","/docs","/about","/blog","/careers","/contact","/security","/privacy","/terms"]:
    try:
        r = requests.get(f"http://localhost:8888{page}", timeout=5)
        ok(f"Page {page}") if r.ok else fail(f"Page {page}", str(r.status_code))
    except: fail(f"Page {page}", "unreachable")

# SPA
try:
    r = requests.get("http://localhost:8888/app/", timeout=5)
    ok("SPA /app/", "200") if r.ok else fail("SPA /app/", str(r.status_code))
except: fail("SPA /app/", "unreachable")

# API via nginx
try:
    r = requests.get("http://localhost:8888/health", timeout=5)
    ok("API via nginx", "200") if r.ok else fail("API via nginx", str(r.status_code))
except: fail("API via nginx", "unreachable")

print(f"\n{'='*70}")
print(f"RESULT: {PASS}/{PASS+FAIL} PASSED, {FAIL} FAILED")
print(f"{'ALL SYSTEMS GO' if FAIL==0 else f'{FAIL} FAILURES — see above'}")
print("="*70)
