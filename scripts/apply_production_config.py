"""Apply production configuration to .env file."""
import secrets
import os

env_path = os.path.join(os.path.dirname(__file__), "..", ".env")

with open(env_path, "r", encoding="utf-8") as f:
    content = f.read()

# Only rotate secrets if they are still the dev defaults
import re
jwt_match = re.search(r'JWT_SECRET=(.+)', content)
jwt_val = jwt_match.group(1).strip() if jwt_match else ''
secret_match = re.search(r'SECRET_KEY=(.+)', content)
secret_val = secret_match.group(1).strip() if secret_match else ''

weak_defaults = {'', 'CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING', 'dev-jwt-secret-key-change-in-production-min-32-chars!!'}

if jwt_val in weak_defaults or len(jwt_val) < 32:
    new_jwt = secrets.token_hex(32)
    content = content.replace(f'JWT_SECRET={jwt_val}', f'JWT_SECRET={new_jwt}')
    print(f'  JWT_SECRET: rotated ({new_jwt[:8]}...{new_jwt[-8:]})')
else:
    print(f'  JWT_SECRET: already set ({jwt_val[:8]}...), skipping')
    new_jwt = jwt_val

if secret_val in weak_defaults or len(secret_val) < 32:
    new_secret = secrets.token_hex(32)
    content = content.replace(f'SECRET_KEY={secret_val}', f'SECRET_KEY={new_secret}')
    print(f'  SECRET_KEY: rotated ({new_secret[:8]}...{new_secret[-8:]})')
else:
    print(f'  SECRET_KEY: already set ({secret_val[:8]}...), skipping')
    new_secret = secret_val

new_webhook = secrets.token_hex(24)

# Add webhook token if missing
if "CYBERNOVA_WEBHOOK_TOKEN=" not in content:
    content = content.rstrip() + f"\nCYBERNOVA_WEBHOOK_TOKEN={new_webhook}\n"
elif "CYBERNOVA_WEBHOOK_TOKEN=" in content:
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("CYBERNOVA_WEBHOOK_TOKEN="):
            lines[i] = f"CYBERNOVA_WEBHOOK_TOKEN={new_webhook}"
    content = "\n".join(lines)

# Update SMTP for real email delivery
content = content.replace("SMTP_HOST=mailhog", "SMTP_HOST=smtp.gmail.com")
content = content.replace("SMTP_PORT=1025", "SMTP_PORT=587")
# Only set placeholder if empty
if "SMTP_USER=\n" in content:
    content = content.replace("SMTP_USER=\n", "SMTP_USER=your-email@gmail.com\n")
if "SMTP_PASSWORD=\n" in content:
    content = content.replace("SMTP_PASSWORD=\n", "SMTP_PASSWORD=your-app-password\n")

with open(env_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Production config applied:")
print(f"  WEBHOOK_TOKEN: {new_webhook[:8]}...{new_webhook[-8:]}")
print("  SMTP_HOST:     smtp.gmail.com")
print("  SMTP_PORT:     587")
print("  SMTP_USER:     your-email@gmail.com (update with real email)")
print("  SMTP_PASSWORD: your-app-password (update with real password)")
print("  NOTE: Run this script only once. Re-running skips existing secrets.")
