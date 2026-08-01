"""Fix host_agent.py - patch main() to support --config argument and fix encoding."""
import re

def fix_host_agent():
    with open('host_agent.py', 'rb') as f:
        content = f.read()

    # Decode with latin-1 to handle any encoding issues
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        text = content.decode('latin-1')
        print("WARNING: Decoded with latin-1 instead of UTF-8")

    # The old main() section to replace
    old_main = '''async def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberNova Enterprise Host Agent")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--tenant", default="default")
    args = parser.parse_args()

    agent = HostAgent(
        backend_url=args.backend,
        username=args.username,
        password=args.password,
        tenant_id=args.tenant
    )'''

    new_main = '''async def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberNova Enterprise Host Agent")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--tenant", default="default")
    parser.add_argument("--config", default="", help="Path to agent_config.json (reads api_url and token)")
    parser.add_argument("--token", default="", help="Device token for direct Bearer auth")
    args = parser.parse_args()

    backend_url = args.backend
    device_token = args.token
    username = args.username
    password = args.password

    # If --config is provided, read config file for backend URL and device token
    if args.config:
        try:
            with open(args.config, "r") as f:
                config = json.load(f)
            if "api_url" in config:
                backend_url = config["api_url"]
                log.info("Config: backend URL = %s", backend_url)
            if "token" in config and not device_token:
                device_token = config["token"]
                log.info("Config: device token loaded from config")
                os.environ["CYBERNOVA_DEVICE_TOKEN"] = device_token
        except Exception as e:
            log.error("Failed to read config file %s: %s", args.config, e)

    agent = HostAgent(
        backend_url=backend_url,
        username=username,
        password=password,
        tenant_id=args.tenant,
        device_token=device_token
    )'''

    if old_main in text:
        text = text.replace(old_main, new_main, 1)
        with open('host_agent.py', 'w', encoding='utf-8') as f:
            f.write(text)
        print("SUCCESS: host_agent.py main() patched with --config support")
        return True
    else:
        print("ERROR: Could not find the old main() section to replace!")
        print("--- Looking for partial match...")
        # Try to find it with different whitespace
        if "async def main():" in text:
            print("Found 'async def main():' in file")
        if "import argparse" in text:
            print("Found 'import argparse' in file")
        if "parser.add_argument(\"--backend\"" in text:
            print("Found 'parser.add_argument(\"--backend\"' in file")
        return False

if __name__ == "__main__":
    fix_host_agent()
