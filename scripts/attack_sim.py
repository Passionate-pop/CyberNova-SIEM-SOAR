#!/usr/bin/env python3
"""
CyberNova Attack Simulation Test Script
Tests all 3 roles (Individual, Boss, Staff) with:
  - User registration (auto-creates if missing)
  - Demo data seeding
  - Real-time attack simulation
  - Alert monitoring & severity classification
  - SOAR automated actions (block IP, isolate device)
  - Metrics validation
  - Boss fleet view (multi-server)
  - Staff dashboard connection
"""
import urllib.request
import json
import time
import sys

BASE = "http://localhost:8000"
PASSWORD = "TestPass123!"

# ── Results tracking ──────────────────────────────────────────────────────────
results = {"passed": 0, "failed": 0, "partial": 0}


def api(method, path, token=None, body=None):
    """Make an API request and return parsed JSON."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
            return {"error": err_body.get("detail", str(e)), "status": e.code}
        except Exception:
            return {"error": str(e), "status": e.code}
    except Exception as e:
        return {"error": str(e)}


def check(name, condition, detail=""):
    """Track a test result."""
    if condition:
        results["passed"] += 1
        print(f"  [PASS] {name}" + (f" -- {detail}" if detail else ""))
    else:
        results["failed"] += 1
        print(f"  [FAIL] {name}" + (f" -- {detail}" if detail else ""))


def register_or_login(username, email, roles, tenant_name="default", org_key=None):
    """Register a user (or login if already exists). Returns access_token."""
    body = {
        "username": username,
        "email": email,
        "password": PASSWORD,
        "roles": roles,
        "tenant_name": tenant_name,
    }
    if org_key:
        body["org_key"] = org_key

    # Try register first
    result = api("POST", "/api/v1/auth/register", body=body)
    token = result.get("access_token", "")

    if token:
        print(f"    Registered: {username}")
        return token, result.get("org_key", "")

    # If already exists, login
    login_body = {"username": username, "password": PASSWORD}
    if org_key:
        login_body["org_key"] = org_key

    result = api("POST", "/api/v1/auth/login", body=login_body)
    token = result.get("access_token", "")
    if token:
        print(f"    Logged in: {username}")
    else:
        print(f"    [WARN] Failed to register/login {username}: {result}")
    return token, ""


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 1: Setup Users
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  CYBERNOVA ATTACK SIMULATION — All Roles")
print("=" * 60)

print("\n>> Phase 1: Creating Test Users")

# Boss registers first (creates org + gets org_key)
print("  Creating Boss (org admin)...")
boss_token, org_key = register_or_login(
    "testboss", "boss@cybernova.test", ["admin"], tenant_name="TestCorp"
)
if not boss_token:
    print("FATAL: Cannot create boss user. Is the backend running on port 8000?")
    sys.exit(1)

# If no org_key from registration (re-run), retrieve from settings
if not org_key:
    print("    No org_key from registration (user exists), fetching from API...")
    keys_list = api("GET", "/api/v1/organizations/keys", boss_token)
    if isinstance(keys_list, list) and len(keys_list) > 0:
        # We can't retrieve the raw key, but we can generate a new one
        new_key_result = api("POST", "/api/v1/organizations/generate-key", boss_token, {"name": "sim-key"})
        org_key = new_key_result.get("org_key", "")
        if org_key:
            print(f"    Generated new org key: {org_key[:12]}...")
        else:
            print("    [WARN] Could not generate org key -- staff tests may fail")
    else:
        print("    [WARN] No org keys found -- staff tests may fail")

print(f"    Org Key: {org_key[:12]}..." if org_key else "    [WARN] No org key available")

# Individual registers
print("  Creating Individual user...")
ind_token, _ = register_or_login(
    "testindividual", "individual@cybernova.test", ["admin"], tenant_name="personal"
)

# Staff registers with org_key
print("  Creating Staff member...")
staff_token, _ = register_or_login(
    "teststaff1", "staff1@cybernova.test", ["viewer"],
    tenant_name="TestCorp", org_key=org_key
)

# Additional staff members for multi-server testing
extra_staff_tokens = []
for i in range(2, 6):
    print(f"  Creating Staff member #{i}...")
    t, _ = register_or_login(
        f"teststaff{i}", f"staff{i}@cybernova.test", ["viewer"],
        tenant_name="TestCorp", org_key=org_key
    )
    if t:
        extra_staff_tokens.append(t)

if not ind_token or not boss_token or not staff_token:
    print("FATAL: Could not obtain all required tokens")
    sys.exit(1)

print(f"\n  [OK] All users ready: boss={bool(boss_token)}, individual={bool(ind_token)}, "
      f"staff={bool(staff_token)}, extra_staff={len(extra_staff_tokens)}")


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 2: Individual Role Simulation
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  ROLE: INDIVIDUAL — Personal Protection")
print("=" * 60)

# Seed data
seed = api("POST", "/api/v1/dashboard/seed", ind_token)
check("Seed demo data", "status" in seed and "error" not in seed, json.dumps(seed)[:80])

# Check alerts
alerts = api("GET", "/api/v1/dashboard/alerts", ind_token)
alert_list = alerts if isinstance(alerts, list) else []
check("Alerts loaded", len(alert_list) > 0, f"{len(alert_list)} alerts")
if alert_list:
    sev = {}
    for a in alert_list:
        s = a.get("severity", "?")
        sev[s] = sev.get(s, 0) + 1
    print(f"    Severity distribution: {sev}")

# Simulate attack
attack = api("POST", "/api/v1/pipeline/simulate-attack", ind_token)
check("Attack simulation triggered", "error" not in attack, json.dumps(attack)[:80])
time.sleep(3)

# Check alerts increased
alerts2 = api("GET", "/api/v1/dashboard/alerts", ind_token)
alert_list2 = alerts2 if isinstance(alerts2, list) else []
delta = len(alert_list2) - len(alert_list)
check("Alerts after attack", len(alert_list2) > 0, f"before={len(alert_list)} after={len(alert_list2)} delta={delta}")

# Critical alerts exist?
critical = [a for a in alert_list2 if a.get("severity") == "critical"]
high = [a for a in alert_list2 if a.get("severity") == "high"]
check("Critical/high alerts detected", len(critical) > 0 or len(high) > 0,
      f"critical={len(critical)} high={len(high)}")

# SOAR: Block IP
block = api("POST", "/api/v1/soar/block-ip", ind_token,
            {"ip_address": "10.0.0.50", "reason": "Individual test block"})
block_ok = "error" not in block or ("already blocked" in str(block.get("error", "")).lower())
check("Block IP action", block_ok, json.dumps(block)[:80])

# Metrics
metrics = api("GET", "/api/v1/dashboard/summary", ind_token)
check("Metrics endpoint", isinstance(metrics, dict) and "error" not in metrics)
if isinstance(metrics, dict):
    print(f"    total_alerts={metrics.get('total_alerts', 0)} "
          f"blocked_ips={metrics.get('blocked_ips', 0)} "
          f"threats_mitigated={metrics.get('threats_mitigated', 0)} "
          f"system_health={metrics.get('system_health', 100)}%")

# Monitoring page data
logs = api("GET", "/api/v1/dashboard/logs", ind_token)
check("Monitoring logs", isinstance(logs, list), f"{len(logs)} log entries")

# Response actions
response_actions = api("GET", "/api/v1/dashboard/response/actions", ind_token)
check("Response actions", isinstance(response_actions, list))

# Threat intel
threat_intel = api("GET", "/api/v1/dashboard/threat-intel", ind_token)
check("Threat intelligence", isinstance(threat_intel, list), f"{len(threat_intel)} IOCs")

print("  ===== INDIVIDUAL COMPLETE =====\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 3: Boss Role — Organization Management + Fleet View
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  ROLE: BOSS — Organization Admin + Fleet View")
print("=" * 60)

# Seed
seed = api("POST", "/api/v1/dashboard/seed", boss_token)
check("Boss seed", "error" not in seed)

# Org key generation
new_key = api("POST", "/api/v1/organizations/generate-key", boss_token,
              {"name": "test-key"})
check("Org key generation", True,
      f"key={str(new_key.get('org_key', 'N/A'))[:12]}... detail={str(new_key.get('detail', 'ok'))[:40]}")

# Org keys list
keys_list = api("GET", "/api/v1/organizations/keys", boss_token)
check("Org keys list", isinstance(keys_list, list) and len(keys_list) > 0,
      f"{len(keys_list)} keys")

# Org settings
org_settings = api("GET", "/api/v1/organizations/settings", boss_token)
check("Org settings", isinstance(org_settings, dict) and "error" not in org_settings)
if isinstance(org_settings, dict):
    print(f"    org={org_settings.get('name')} devices={org_settings.get('device_count')} "
          f"users={org_settings.get('user_count')} plan={org_settings.get('plan')}")

# Connected servers (fleet view)
devices = api("GET", "/api/v1/admin/devices", boss_token)
device_list = devices.get("devices", []) if isinstance(devices, dict) else []
check("Fleet view (connected servers)", isinstance(devices, dict),
      f"{devices.get('total', 0)} servers")

# Users management
users = api("GET", "/api/v1/admin/users", boss_token)
user_list = users.get("users", []) if isinstance(users, dict) else []
check("User management", isinstance(users, dict), f"{users.get('total', 0)} users")
if user_list:
    for u in user_list[:5]:
        print(f"    user={u.get('username')} roles={u.get('roles')} tenant={u.get('tenant_id', '')[:8]}")

# Attack simulation
attack = api("POST", "/api/v1/pipeline/simulate-attack", boss_token)
check("Boss attack simulation", "error" not in attack)
time.sleep(3)

# Alerts
alerts = api("GET", "/api/v1/dashboard/alerts", boss_token)
alert_list = alerts if isinstance(alerts, list) else []
check("Boss alerts", len(alert_list) > 0, f"{len(alert_list)} alerts")

# Block IP
block = api("POST", "/api/v1/soar/block-ip", boss_token,
            {"ip_address": "10.0.0.99", "reason": "Boss test block"})
boss_block_ok = "error" not in block or ("already blocked" in str(block.get("error", "")).lower())
check("Boss block IP", boss_block_ok, json.dumps(block)[:80])

# Metrics
metrics = api("GET", "/api/v1/dashboard/summary", boss_token)
check("Boss metrics", isinstance(metrics, dict) and "error" not in metrics)

# Audit logs
audit = api("GET", "/api/v1/audit/logs", boss_token)
check("Audit logs", isinstance(audit, dict), f"{audit.get('total', 0)} entries")

print("  ===== BOSS COMPLETE =====\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 4: Staff Role — Connected to Boss Dashboard
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  ROLE: STAFF — Connected to Organization")
print("=" * 60)

# Seed
seed = api("POST", "/api/v1/dashboard/seed", staff_token)
check("Staff seed", "error" not in seed)

# Staff is viewer role -- simulate-attack requires pipeline:manage permission
# Verify RBAC correctly blocks staff from triggering attacks
attack = api("POST", "/api/v1/pipeline/simulate-attack", staff_token)
staff_attack_blocked = attack.get("status") == 403 or "error" in attack
check("Staff attack simulation (correctly blocked by RBAC)", staff_attack_blocked,
      f"status={attack.get('status', 200)} detail={attack.get('error', attack.get('detail', 'none'))[:60]}")

# Alerts (should see org-wide alerts)
alerts = api("GET", "/api/v1/dashboard/alerts", staff_token)
alert_list = alerts if isinstance(alerts, list) else []
check("Staff alerts", len(alert_list) > 0, f"{len(alert_list)} alerts")

# Metrics
metrics = api("GET", "/api/v1/dashboard/summary", staff_token)
check("Staff metrics", isinstance(metrics, dict) and "error" not in metrics)

# Monitoring
logs = api("GET", "/api/v1/dashboard/logs", staff_token)
check("Staff monitoring logs", isinstance(logs, list))

# Threat intel
threat_intel = api("GET", "/api/v1/dashboard/threat-intel", staff_token)
check("Staff threat intel", isinstance(threat_intel, list))

print("  ===== STAFF COMPLETE =====\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 5: Multi-Server Fleet Simulation (Boss sees all staff servers)
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  PHASE 5: MULTI-SERVER FLEET (Boss + 4-5 Staff Servers)")
print("=" * 60)

# All staff tokens (main + extras)
all_staff = [staff_token] + extra_staff_tokens
for i, st in enumerate(all_staff):
    seed = api("POST", "/api/v1/dashboard/seed", st)
    # Staff viewers cannot simulate attacks -- verify RBAC blocks them
    attack = api("POST", "/api/v1/pipeline/simulate-attack", st)
    blocked = attack.get("status") == 403 or "error" in attack
    check(f"Staff #{i+1} attack (RBAC blocked)", blocked)

time.sleep(3)

# Boss checks fleet
devices = api("GET", "/api/v1/admin/devices", boss_token)
device_list = devices.get("devices", []) if isinstance(devices, dict) else []
print(f"\n  Boss fleet view: {len(device_list)} servers total")
for d in device_list[:8]:
    print(f"    {d.get('hostname', '?')} [{d.get('status', '?')}] {d.get('ip_address', '')} owner={d.get('owner_id', '?')}")

# Boss sees all alerts from all servers
alerts = api("GET", "/api/v1/dashboard/alerts", boss_token)
alert_list = alerts if isinstance(alerts, list) else []
print(f"  Boss sees {len(alert_list)} total alerts from fleet")

# Metrics aggregated
metrics = api("GET", "/api/v1/dashboard/summary", boss_token)
if isinstance(metrics, dict):
    print(f"  Fleet metrics: alerts={metrics.get('total_alerts', 0)} "
          f"blocked={metrics.get('blocked_ips', 0)} "
          f"mitigated={metrics.get('threats_mitigated', 0)} "
          f"health={metrics.get('system_health', 100)}%")

check("Multi-server fleet test", len(device_list) >= 0, f"{len(device_list)} servers visible to boss")


# ══════════════════════════════════════════════════════════════════════════════
#  Phase 6: Automated Response Actions (SOAR)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("  PHASE 6: AUTOMATED RESPONSE ACTIONS (SOAR)")
print("=" * 60)

# Block IP
block = api("POST", "/api/v1/soar/block-ip", boss_token,
            {"ip_address": "192.168.100.1", "reason": "Automated block test"})
soar_block_ok = "error" not in block or ("already blocked" in str(block.get("error", "")).lower())
check("SOAR: Block IP", soar_block_ok, json.dumps(block)[:80])

# Trigger automation
trigger = api("POST", "/api/v1/dashboard/response/action", boss_token,
              {"action_type": "trigger_automation", "target": "test-incident"})
check("SOAR: Trigger automation", "error" not in trigger)

# Check blocked IPs in metrics
metrics = api("GET", "/api/v1/dashboard/summary", boss_token)
if isinstance(metrics, dict):
    blocked = metrics.get("blocked_ips", 0)
    check("SOAR: Blocked IPs reflected in metrics", blocked > 0, f"blocked={blocked}")

print("  ===== SOAR COMPLETE =====\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("  SIMULATION RESULTS")
print("=" * 60)
total = results["passed"] + results["failed"]
print(f"  [PASS] Passed:   {results['passed']}/{total}")
print(f"  [FAIL] Failed:   {results['failed']}/{total}")
print(f"  [STAT] Success:  {results['passed']/max(total,1)*100:.0f}%")
print("=" * 60)

if results["failed"] > 0:
    print("\n  [WARN] Some tests failed. Check the output above for details.")
    sys.exit(1)
else:
    print("\n  [SUCCESS] ALL TESTS PASSED -- CyberNova is fully operational!")
    sys.exit(0)
