# Intrusion Detection System 🛡️

A lightweight **host-based intrusion detection system (IDS)** written in pure Python.
It parses Apache / Nginx combined access logs in real time and flags suspicious
activity — SQL injection, XSS, path traversal, shell injection, brute force,
credential stuffing, and known-bad scanning tools.

Built as a portfolio project to demonstrate:
- Practical **cybersecurity** knowledge (OWASP Top 10 attack patterns)
- Clean, modular **Python** design (dataclasses, type hints, pluggable rules)
- **Real-world engineering** habits (sample data, tests, CLI, reports)

---

## 🚀 Quick start

```bash
git clone https://github.com/Izu-Cmd/intrusion-detection-system.git
cd intrusion-detection-system
python main.py sample_logs/access.log
```

That's it — no third-party dependencies. Just standard library Python 3.9+.

---

## 🔍 What it detects

| Rule | Severity | Description |
| --- | --- | --- |
| **SQLInjection** | high | `UNION SELECT`, `' OR '1'='1'`, `DROP TABLE`, `sleep()`, `benchmark()`, etc. |
| **XSSAttempt** | medium | `<script>`, `onerror=`, `javascript:`, `document.cookie`, etc. |
| **PathTraversal** | high | `../`, `..%2f`, encoded variants targeting `/etc/passwd`, etc. |
| **ShellInjection** | critical | `;ls`, `|whoami`, backticks, `$(...)` command substitution |
| **SensitivePathProbe** | medium | Hits on `/.env`, `/wp-config.php`, `/.git/config`, `/phpmyadmin` |
| **SuspiciousUserAgent** | high | UA from `sqlmap`, `nikto`, `nmap`, `wpscan`, `gobuster`, etc. |
| **HighErrorRate** | medium | 5xx errors from an IP with elevated anomaly score |
| **BruteForceLogin** | high | N+ failed logins from one IP within a sliding time window |
| **CredentialStuffing** | critical | Many distinct usernames tried from a single IP |

Every alert contributes to a **per-IP anomaly score** (0–100). IPs that cross
the threshold appear in the suspicious-IP report.

---

## 🧱 Architecture

```
   ┌─────────────┐    ┌──────────────┐    ┌─────────────┐
   │ log_parser  │ -> │ ids engine   │ -> │  alerter    │
   │ (regex)     │    │ (state,      │    │  (CLI +     │
   │             │    │  scoring,    │    │   report)   │
   │             │    │  thresholds) │    │             │
   └─────────────┘    └──────────────┘    └─────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │   rules.py   │
                     │  (pluggable  │
                     │   signature  │
                     │    rules)    │
                     └──────────────┘
```

- `log_parser.py` — Regex-based parser for Apache/Nginx combined log format.
  Handles URL decoding and basic parameter extraction.
- `rules.py` — Each detection rule is its own class. Drop a new one in `RULES`
  and it's live. Easy to extend with regex patterns or anomaly thresholds.
- `ids.py` — The stateful engine: tracks failed logins, usernames per IP,
  and rolling time windows. Holds `IDSConfig` for tunable thresholds.
- `alerter.py` — Color-coded CLI output plus a summary report
  (severity / rule / IP breakdowns).
- `main.py` — One-line entry point for ad-hoc analysis.

---

## ⚙️ CLI

```bash
python main.py path/to/access.log
python main.py path/to/access.log --threshold 60 --quiet
```

Or import directly:

```python
from ids import IntrusionDetectionSystem, IDSConfig
from alerter import Alerter

ids = IntrusionDetectionSystem(
    config=IDSConfig(brute_force_threshold=10),
    alerter=Alerter(),
)
hits = ids.process_file("sample_logs/access.log")
for h in hits:
    print(h)
```

---

## 🧪 Tests

```bash
python -m unittest tests/test_ids.py
```

Covers the parser, every signature rule, brute-force state machine, user-agent
detection, and anomaly score accumulation.

---

## 📊 Sample output

```
[HIGH     ] SQLInjection          10.0.0.55         SQLi signature in GET /products?id=1%20UNION%20SELECT...
[HIGH     ] SuspiciousUserAgent   10.0.0.55         Suspicious UA 'sqlmap/1.5.2'
[MEDIUM   ] XSSAttempt            203.0.113.7       XSS payload in GET /search?q=<script>alert(1)</script>
[HIGH     ] PathTraversal         172.16.99.42      Path traversal in GET /../../../etc/passwd
[CRITICAL ] ShellInjection        77.88.99.11       Shell injection in GET /index.php?id=1;ls
[HIGH     ] BruteForceLogin       45.33.32.156      6 failed logins from 45.33.32.156 within 0:05:00
...
```

---

## 🛠️ Extending

Add a new rule in three lines:

```python
class MyNewRule:
    name = "MyNewRule"
    def match(self, entry, ids):
        if "bad-pattern" in entry.decoded_path():
            return RuleHit(rule_name=self.name, severity="high",
                           ip=entry.ip, description="...", weight=20)
        return None

RULES.append(MyNewRule())
```

---

## 📚 What I learned building this

- Designing a pluggable rule pipeline
- Working with sliding-window state without an external DB
- Regex is great until it isn't — easy to add a structured log parser later
- Cybersecurity tooling is mostly about *patterns + thresholds + speed*

---

## 📄 License

MIT — see [LICENSE](LICENSE).