# Smart Honeypot for Attacker Behavior Analysis

A high-interaction web honeypot that captures full HTTP request data, classifies attacker
behaviour with a rules engine, maps each action to the **MITRE ATT&CK** framework, and
visualises everything on a live dashboard.

The architecture is service-pluggable: the prototype implements **Web / HTTP(S)**, but the
capture pipeline, storage schema, classifier, and dashboard are designed so SSH / SMB /
database emulators can be added later as additional "service modules".

---

## 1. Project goals

1. **Lure** opportunistic and targeted attackers with believable web targets
   (fake admin panels, exposed `.env` files, phpMyAdmin, WordPress, custom API).
2. **Capture** every interaction with full fidelity: headers, body, source IP, user-agent,
   timing, payload.
3. **Classify** each request into an attack category (SQLi, XSS, LFI, RCE, scanner, brute
   force, recon, etc.) using a deterministic rules engine.
4. **Map** classified events to MITRE ATT&CK techniques (T1190, T1110, T1059, T1083, ...).
5. **Group** events into per-attacker sessions and surface them on a dashboard with a
   timeline, technique heatmap, and per-session drill-down.
6. **Reproducibility**: ship an attack simulator so the project is demoable on a laptop
   without exposing it to the internet.

## 2. Architecture

```
                    +--------------------------+
   attacker /       |  honeypot/server.py      |
   simulator  --->  |  Flask app (port 8080)   |
                    |  - fake login            |
                    |  - fake admin/wp/pma     |
                    |  - fake API + files      |
                    |  capture middleware -----+--> storage/db.py (SQLite)
                    +--------------------------+         |
                                                         v
                    +--------------------------+   +-------------+
                    |  analyzer/               |<--|  events     |
                    |  classifier + mitre +    |   |  sessions   |
                    |  sessioniser             |-->|  technique  |
                    +--------------------------+   |  hits       |
                                                   +-------------+
                                                         ^
                    +--------------------------+         |
   analyst   --->   |  dashboard/server.py     |---------+
                    |  Flask UI (port 5000)    |
                    |  overview / sessions /   |
                    |  session detail          |
                    +--------------------------+
```

Key design decisions:

* **Single SQLite file** for storage – zero-setup, plays well with grading/demo.
* **Synchronous capture-then-classify** in a background thread so the honeypot itself
  stays fast.
* **Rules-based classifier** instead of ML – cheap to demo, deterministic for the
  evaluation rubric, and easy to extend with more signatures. ML/anomaly detection is
  noted as future work in the writeup.
* **Service-pluggable**: every captured event has a `service` column, so adding an SSH
  honeypot later is just a new module that writes events with `service="ssh"`.

## 3. Repo layout

```
smart-honeypot/
├── README.md
├── requirements.txt
├── config.yaml                # ports, db path, classifier toggles
├── run.py                     # launches honeypot + dashboard together
│
├── honeypot/
│   ├── server.py              # Flask honeypot (fake services)
│   ├── responses.py           # fake HTML/JSON response generators
│   ├── fingerprint.py         # tool / scanner detection from request
│   └── capture.py             # request -> DB pipeline
│
├── analyzer/
│   ├── classifier.py          # signature/regex based attack classifier
│   ├── mitre.py               # attack category -> MITRE technique mapping
│   └── sessions.py            # group events into attacker sessions
│
├── storage/
│   └── db.py                  # SQLite schema + helpers
│
├── dashboard/
│   ├── server.py              # Flask dashboard
│   ├── templates/
│   │   ├── base.html
│   │   ├── overview.html
│   │   ├── sessions.html
│   │   └── session_detail.html
│   └── static/style.css
│
├── data/
│   └── mitre_techniques.json  # technique reference (id -> name + tactic)
│
├── tools/
│   └── simulate_attacks.py    # fires realistic attacker traffic
│
└── tests/
    └── test_classifier.py
```

## 4. Quick start

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Run honeypot + dashboard together (DB auto-initialises)
python run.py
#   honeypot  -> http://127.0.0.1:8080
#   dashboard -> http://127.0.0.1:5000

# 3. In another terminal, fire simulated attacker traffic
python tools/simulate_attacks.py

# 4. Open the dashboard and watch sessions, classifications, and
#    MITRE technique hits populate in real time.
```

## 5. What the dashboard shows

* **Overview** – total events, unique attackers, top attack categories, top MITRE
  techniques, requests per minute over the last hour.
* **Sessions** – one row per attacker session (source IP + 10-min idle window), with
  request count, distinct techniques, first/last seen, dominant tool fingerprint.
* **Session detail** – full request timeline, every payload, the attack category and
  MITRE technique assigned to each request, and a per-session technique heatmap.

## 6. MITRE ATT&CK coverage (prototype)

| Category               | Technique  | Tactic                     |
|------------------------|------------|----------------------------|
| Recon / scanner        | T1595.002  | Reconnaissance             |
| Brute force login      | T1110.001  | Credential Access          |
| Default-creds attempt  | T1078.001  | Initial Access             |
| SQL injection          | T1190      | Initial Access             |
| Cross-site scripting   | T1059.007  | Execution                  |
| Local file inclusion   | T1083      | Discovery                  |
| Path traversal         | T1083      | Discovery                  |
| Remote code execution  | T1059      | Execution                  |
| Webshell upload        | T1505.003  | Persistence                |
| Sensitive file access  | T1552.001  | Credential Access          |

The mapping lives in `data/mitre_techniques.json` and `analyzer/mitre.py`, so adding
new categories is one entry.

## 7. Running tests

```bash
pytest -q
```

## 8. Suggested writeup structure (for the coursework report)

1. Background – honeypot taxonomy, MITRE ATT&CK, related work (Cowrie, T-Pot, Dionaea).
2. Threat model – who you are luring (opportunistic web scanners + targeted bots).
3. Design – architecture diagram from this README, design decisions section above.
4. Implementation – tour each module (honeypot / analyzer / storage / dashboard).
5. Evaluation – run the simulator, screenshot the dashboard, table of classifier
   precision against `tests/test_classifier.py` ground truth, ATT&CK coverage map.
6. Limitations + future work – ML anomaly detection, additional service modules,
   deception escalation engine, deploying behind a reverse proxy with TLS.
7. Ethics + legal – never deploy to a production network without authorisation; obey
   the local computer-misuse legislation; sanitise captured data before publication.

## 9. Safety / ethics note

This project is intended for **educational and defensive research** in a **controlled
lab environment**. Do not deploy on the public internet without:

* explicit authorisation from the network owner,
* legal review (computer misuse, data protection of attacker IPs),
* hardening of the host (the honeypot intentionally exposes attractive surfaces –
  the host running it must be sandboxed: container, dedicated VM, isolated VLAN).
