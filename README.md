# 🛡️ Simple Multi-Protocol Honeypot

A lightweight, Python-based honeypot that simulates multiple network services to detect, log, and analyze unauthorized connection attempts. This project is designed for cybersecurity learning, research, and demonstration purposes.

---

## 📌 Overview

This honeypot emulates common network services such as **SSH**, **HTTP**, and **FTP**, allowing security enthusiasts to observe attacker behavior without exposing real systems.

When an attacker connects, the honeypot:

- Logs connection details
- Records requests and payloads
- Stores attack information in JSON and log files
- Captures basic authentication attempts (where applicable)

---

## ✨ Features

- 🔐 SSH Honeypot
- 🌐 HTTP Honeypot
- 📁 FTP Honeypot
- 📊 JSON-based attack logging
- 📝 Human-readable log file
- 📂 Payload capture
- ⚡ Multi-threaded server
- 🖥️ Easy to run and configure

---

## 📂 Project Structure

```
Simple-Honeypot/
│
├── simple_honeypot.py
├── honeypot_attacks.log
├── honeypot_attacks.json
├── captured_payloads/
├── README.md
├── requirements.txt
└── .gitignore
```

---

## 🛠️ Technologies Used

- Python 3
- socketserver
- socket
- threading
- logging
- json
- datetime
- selectors

> Uses only Python's standard library.

---

## 🌐 Supported Services

| Service | Port |
|----------|------|
| SSH | 2222 |
| HTTP | 8080 |
| FTP | 2121 |

> These ports can be modified inside the source code if needed.

---

## 🚀 Getting Started

### Clone the repository

```bash
git clone https://github.com/HARSHITH290307/HONEYPOT.git
cd Simple-Honeypot
```

### Run the honeypot

```bash
python3 simple_honeypot.py
```

You should see output similar to:

```
[INFO] SSH honeypot listening on 0.0.0.0:2222
[INFO] HTTP honeypot listening on 0.0.0.0:8080
[INFO] FTP honeypot listening on 0.0.0.0:2121

Honeypot running...
```

---

## 📋 Logging

The honeypot records attacks in two formats:

### Log File

```
honeypot_attacks.log
```

Contains readable logs of attacker activity.

### JSON File

```
honeypot_attacks.json
```

Contains structured attack data for further analysis.

Example:

```json
{
    "timestamp": "2026-07-28T16:50:31Z",
    "protocol": "SSH",
    "ip": "192.168.29.119",
    "port": 38846,
    "data": "SSH-2.0-OpenSSH_9.6"
}
```

---

## 📸 Screenshots

Add screenshots here after uploading them to GitHub.

Example:

- Running Honeypot
- SSH Connection Attempt
- HTTP Request Logging
- FTP Connection Logging
- Generated JSON Logs

---

## 📚 Learning Objectives

This project helped me understand:

- Socket Programming
- TCP Servers
- Multi-threading
- Network Protocols
- Honeypot Design
- Cybersecurity Monitoring
- Attack Logging
- JSON Data Storage

---

## 🔮 Future Improvements

- Web Dashboard
- Email Alerts
- GeoIP Lookup
- Malware Hash Detection
- Telnet Honeypot
- SMTP Honeypot
- DNS Honeypot
- MySQL Honeypot
- Docker Support
- SQLite Database Logging
- Web-based Log Viewer
- Real-time Monitoring

---

## ⚠️ Disclaimer

This project is intended **only for educational and research purposes**.

Deploy and use it only on systems and networks that you own or are explicitly authorized to test.

The author is not responsible for any misuse of this software.

---

## 👨‍💻 Author

**Harshith V**

B.Tech Computer Science and Business Systems (CSBS)

Cybersecurity Enthusiast | Python | Networking | Ethical Hacking

GitHub: https://github.com/YOUR_USERNAME

---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.
