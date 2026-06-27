"""
CyberNova — Combined HTTP Server for End-to-End Testing
Serves:
  - Marketing site (web-page/out/) at / with clean URLs
  - Frontend SPA (cybernova-frontend/dist/) at /app/
  - Proxies /api/* to the backend at localhost:8000
Mirrors what nginx does in production.
"""

import os
import sys
import json
import urllib.request
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "cybernova-frontend", "dist")
MARKETING_DIR = os.path.join(os.path.dirname(__file__), "web-page", "out")
BACKEND_URL = "http://127.0.0.1:8000"


class CombinedHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves marketing site + frontend SPA + API proxy."""

    def translate_path(self, path):
        """Route requests to the correct directory."""
        parsed = urlparse(path)
        clean_path = parsed.path

        # API proxy -- forward to backend
        if clean_path.startswith("/api/"):
            return None  # handled in do_GET/do_POST

        # Frontend SPA -- serve from /app/
        if clean_path.startswith("/app/"):
            relative = clean_path[len("/app/"):] or ""
            if not relative:
                relative = "index.html"
            result = os.path.join(FRONTEND_DIR, relative)
            if os.path.exists(result) and not os.path.isdir(result):
                return result
            # SPA fallback: send index.html for any /app/* path
            return os.path.join(FRONTEND_DIR, "index.html")

        # Marketing site -- clean URLs: /features -> features.html
        if not clean_path or clean_path == "/":
            return os.path.join(MARKETING_DIR, "index.html")

        # Strip leading /
        relative = clean_path.lstrip("/")

        # Try exact file first
        exact = os.path.join(MARKETING_DIR, relative)
        if os.path.exists(exact) and not os.path.isdir(exact):
            return exact

        # Try .html extension
        html_path = os.path.join(MARKETING_DIR, relative + ".html")
        if os.path.exists(html_path):
            return html_path

        # Try directory index
        dir_index = os.path.join(MARKETING_DIR, relative, "index.html")
        if os.path.exists(dir_index):
            return dir_index

        # Fallback to the path as-is
        return os.path.join(MARKETING_DIR, relative)

    def _proxy_api(self, method="GET"):
        """Proxy API requests to the backend."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        url = BACKEND_URL + self.path
        req = urllib.request.Request(url, data=body, method=method)

        # Forward headers
        for header in ["Content-Type", "Authorization", "Accept"]:
            if header in self.headers:
                req.add_header(header, self.headers[header])

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._proxy_api("GET")
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._proxy_api("POST")
        return super().do_POST()

    def do_PUT(self):
        if self.path.startswith("/api/"):
            return self._proxy_api("PUT")
        return super().do_PUT()

    def do_DELETE(self):
        if self.path.startswith("/api/"):
            return self._proxy_api("DELETE")
        return super().do_DELETE()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def log_message(self, format, *args):
        """Quiet logging."""
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    server = HTTPServer(("0.0.0.0", port), CombinedHandler)
    sys.stderr.write("CyberNova server running at http://127.0.0.1:" + str(port) + "\n")
    sys.stderr.write("  Marketing site: http://127.0.0.1:" + str(port) + "/\n")
    sys.stderr.write("  Frontend SPA:   http://127.0.0.1:" + str(port) + "/app/\n")
    sys.stderr.write("  API proxy:      http://127.0.0.1:" + str(port) + "/api/* -> " + BACKEND_URL + "\n")
    sys.stderr.flush()
    server.serve_forever()
