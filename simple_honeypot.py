#!/usr/bin/env python3
"""
simple_honeypot.py — Multi-service low-interaction honeypot
Usage:  sudo python3 simple_honeypot.py
"""

import socket
import threading
import logging
import datetime
import os
import sys
import select
import json
from socketserver import ThreadingTCPServer, StreamRequestHandler

# ── Configuration ──────────────────────────────────────────────────────────
BIND_IP = "0.0.0.0"
SSH_PORT = 2222          # Use non-privileged; redirect 22→2222 with iptables
HTTP_PORT = 8080          # Same idea for port 80
FTP_PORT = 2121           # Same idea for port 21
LOG_FILE = "honeypot_attacks.log"
CAPTURE_DIR = "captured_payloads"

# ── Logging Setup ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("honeypot")

os.makedirs(CAPTURE_DIR, exist_ok=True)

# ── Fake Banner Strings ────────────────────────────────────────────────────
SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
HTTP_BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
    b"Content-Type: text/html; charset=UTF-8\r\n"
    b"Connection: close\r\n\r\n"
    b"<html><body><h1>Ubuntu Server</h1><p>Default Apache page</p></body></html>"
)
FTP_BANNER = b"220 ProFTPD 1.3.5 Server ready.\r\n"

# ── Helper: Log to JSON too ────────────────────────────────────────────────
def log_attack(service, src_ip, src_port, data):
    """Write structured JSON log alongside plain-text logging."""
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "service": service,
        "src_ip": src_ip,
        "src_port": src_port,
        "data": data,
    }
    with open(LOG_FILE.replace(".log", ".json"), "a") as f:
        f.write(json.dumps(entry) + "\n")
    # Also dump raw payload to file
    safe_ip = src_ip.replace(".", "_").replace(":", "_")
    fname = f"{CAPTURE_DIR}/{service}_{safe_ip}_{int(datetime.datetime.utcnow().timestamp())}.bin"
    with open(fname, "ab") as f:
        if isinstance(data, str):
            f.write(data.encode("utf-8", errors="replace"))
        else:
            f.write(data)
    logger.info(f"[{service}] {src_ip}:{src_port} → {data!r}")

# ── SSH Handler ────────────────────────────────────────────────────────────
class SSHHandler(StreamRequestHandler):
    def handle(self):
        ip, port = self.client_address
        logger.info(f"[SSH] Connection from {ip}:{port}")
        self.request.sendall(SSH_BANNER)
        while True:
            try:
                ready, _, _ = select.select([self.request], [], [], 30)
                if not ready:
                    break
                data = self.request.recv(4096)
                if not data:
                    break
                log_attack("SSH", ip, port, data)
                # If it looks like a password auth attempt, log extracted creds
                if b"\x00" in data:
                    parts = data.split(b"\x00")
                    if len(parts) >= 5:
                        username = parts[3].decode("utf-8", errors="replace")
                        password = parts[4].decode("utf-8", errors="replace")
                        logger.warning(f"[SSH-CREDS] {ip}:{port} → {username}:{password}")
                        log_attack("SSH_CREDS", ip, port, f"{username}:{password}")
                # Send fake auth failure
                self.request.sendall(b"\x00\x00\x00\x0e\x06\x00\x00\x00\x00\x00\x00\x00\x00Authentication failed.\r\n")
            except (ConnectionResetError, BrokenPipeError, OSError):
                break

class SSHServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

# ── HTTP Handler ───────────────────────────────────────────────────────────
class HTTPHandler(StreamRequestHandler):
    def handle(self):
        ip, port = self.client_address
        logger.info(f"[HTTP] Connection from {ip}:{port}")
        try:
            data = self.request.recv(8192)
            if data:
                log_attack("HTTP", ip, port, data.decode("utf-8", errors="replace"))
                # Log interesting patterns
                decoded = data.decode("utf-8", errors="replace")
                if "POST" in decoded:
                    if "password" in decoded.lower() or "passwd" in decoded.lower():
                        logger.warning(f"[HTTP-FORM] Potential credential capture from {ip}:{port}")
                # Respond with fake page
                self.request.sendall(HTTP_BANNER)
            # Try to keep connection open briefly for slow attacks
            ready, _, _ = select.select([self.request], [], [], 5)
            if ready:
                extra = self.request.recv(4096)
                if extra:
                    log_attack("HTTP_EXTRA", ip, port, extra.decode("utf-8", errors="replace"))
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

class HTTPServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

# ── FTP Handler ────────────────────────────────────────────────────────────
class FTPHandler(StreamRequestHandler):
    def handle(self):
        ip, port = self.client_address
        logger.info(f"[FTP] Connection from {ip}:{port}")
        self.request.sendall(FTP_BANNER)
        while True:
            try:
                ready, _, _ = select.select([self.request], [], [], 30)
                if not ready:
                    self.request.sendall(b"421 Timeout.\r\n")
                    break
                data = self.request.recv(4096)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="replace").strip()
                log_attack("FTP", ip, port, cmd)
                # Simulate FTP responses
                if cmd.upper().startswith("USER"):
                    self.request.sendall(b"331 Password required for user.\r\n")
                elif cmd.upper().startswith("PASS"):
                    # Extract username from previous command
                    logger.warning(f"[FTP-CREDS] {ip}:{port} → Attempted login")
                    self.request.sendall(b"530 Login incorrect.\r\n")
                elif cmd.upper().startswith("QUIT"):
                    self.request.sendall(b"221 Goodbye.\r\n")
                    break
                elif cmd.upper().startswith("SYST"):
                    self.request.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd.upper().startswith("PWD"):
                    self.request.sendall(b'257 "/var/www" is current directory.\r\n')
                elif cmd.upper().startswith("LIST") or cmd.upper().startswith("NLST"):
                    self.request.sendall(b"150 Opening ASCII mode data connection.\r\n")
                    self.request.sendall(b"226 Transfer complete.\r\n")
                elif cmd.upper().startswith("CWD"):
                    self.request.sendall(b"250 Directory successfully changed.\r\n")
                else:
                    self.request.sendall(b"500 Unknown command.\r\n")
            except (ConnectionResetError, BrokenPipeError, OSError):
                break

class FTPServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

# ── Main ───────────────────────────────────────────────────────────────────
def print_banner():
    print(r"""
  ╔══════════════════════════════════════════╗
  ║       Simple Honeypot — Active           ║
  ╚══════════════════════════════════════════╝
    """)

def main():
    print_banner()
    servers = []

    # SSH
    ssh_server = SSHServer((BIND_IP, SSH_PORT), SSHHandler)
    servers.append(("SSH", SSH_PORT, ssh_server))
    logger.info(f"SSH honeypot listening on {BIND_IP}:{SSH_PORT}")

    # HTTP
    http_server = HTTPServer((BIND_IP, HTTP_PORT), HTTPHandler)
    servers.append(("HTTP", HTTP_PORT, http_server))
    logger.info(f"HTTP honeypot listening on {BIND_IP}:{HTTP_PORT}")

    # FTP
    ftp_server = FTPServer((BIND_IP, FTP_PORT), FTPHandler)
    servers.append(("FTP", FTP_PORT, ftp_server))
    logger.info(f"FTP honeypot listening on {BIND_IP}:{FTP_PORT}")

    logger.info("=" * 50)
    logger.info("Honeypot running. Ctrl+C to stop.")
    logger.info(f"Logs: {LOG_FILE} | JSON: {LOG_FILE.replace('.log', '.json')}")
    logger.info(f"Payloads: {CAPTURE_DIR}/")
    logger.info("=" * 50)

    # Start all server threads
    threads = []
    for name, port, svr in servers:
        t = threading.Thread(target=svr.serve_forever, daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot...")
        for _, _, svr in servers:
            svr.shutdown()
        logger.info("Honeypot stopped.")

if __name__ == "__main__":
    main()