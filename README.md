# Splunk-Lab
Brute-Force Detection using Splunk

### Splunk Enterprise | Windows Event Logging | Kali Linux Attack Simulation

> A closed-loop Security Information and Event Management (SIEM) environment engineered to ingest, parse, normalize, and visualize unauthorized SMB network authentication attempts in real time.

---

## 📸 Dashboard Preview

<!-- Replace with your actual screenshot -->
![Splunk Dashboard](screenshots/dashboard_overview.png)

---

## 🗺️ Lab Topology

```
┌─────────────────────────────────────────────────────────┐
│                      NAT / Host-Only Network             │
│                                                         │
│  ┌──────────────────┐        ┌──────────────────────┐  │
│  │  Kali Linux VM   │──SMB──▶│  Windows 11 VM       │  │
│  │  (Attacker Node) │        │  (Target Node)       │  │
│  │  CrackMapExec    │        │  Splunk Universal    │  │
│  │  Metasploit      │        │  Forwarder           │  │
│  └──────────────────┘        └──────────┬───────────┘  │
│                                          │ TCP/9997     │
│                               ┌──────────▼───────────┐  │
│                               │  macOS Host          │  │
│                               │  Splunk Enterprise   │  │
│                               │  (SIEM / Indexer)    │  │
│                               └──────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

| Node | OS | Role | Tool |
|---|---|---|---|
| Host | macOS | SIEM Indexer / Dashboarding | Splunk Enterprise |
| Target | Windows 11 VM | Endpoint / Log Source | Splunk Universal Forwarder |
| Attacker | Kali Linux VM | Threat Emulation | CrackMapExec, Metasploit |

---

## ⚙️ Setup & Configuration

### 1. Windows 11 — Audit Policy

Default Windows logging does **not** capture all authentication events. The following must be enabled manually:

```
secpol.msc → Security Settings
  └─ Advanced Audit Policy Configuration
       └─ System Audit Policies
            └─ Logon/Logoff
                 └─ Audit Logon → ✅ Success + ✅ Failure
```

This enables generation of:
- **Event ID 4624** — Successful Logon
- **Event ID 4625** — Failed Logon (Brute Force Indicator)

### 2. Splunk Universal Forwarder — Windows Target

- Install the Splunk UF on the Windows VM
- Set the `SplunkForwarder` service to run as **Local System** (required to read the protected `Security.evtx` channel)
- Configure forwarding to the macOS host on **TCP/9997**

> See [`configs/inputs.conf`](configs/inputs.conf) for the full forwarder configuration.

### 3. Splunk Enterprise — macOS Host

Configure Splunk to receive forwarded data:

```
Settings → Forwarding and Receiving → Configure Receiving → New → Port 9997
```

> See [`configs/props.conf`](configs/props.conf) for the timestamp normalization fix.

---

## 🕐 Timestamp Normalization Fix

**Problem:** Windows VM and macOS host had a timezone mismatch. Events generated at `00:30 EST` were being indexed as `03:30 EST`, placing them outside Splunk's default "Last 60 Minutes" search window — making the attack **invisible**.

**Root Cause:** The raw Windows XML event payload lacked an explicit `%Z` timezone token, causing Splunk's indexer to misinterpret the local timestamp.

**Fix — `props.conf`:**

```ini
[WinEventLog:Security]
MAX_TIMESTAMP_LOOKAHEAD = 30
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%Q%Z
```

This forces the indexer to rigorously extract the timestamp string directly from the Windows XML payload, eliminating the 3-hour drift.

---

## 💥 Attack Simulation

Attacks were launched from the **Kali Linux** node using `crackmapexec` over **SMB**.

### Phase 1 — Brute Force (Noise Generation)
```bash
crackmapexec smb [TARGET_IP] -u Administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```
Generates a flood of **Event ID 4625** (Failed Logon) entries.

### Phase 2 — Successful Compromise (Signal Generation)
```bash
crackmapexec smb [TARGET_IP] -u [TARGET_USER] -p [CORRECT_PASSWORD]
```
Generates a single **Event ID 4624** (Successful Logon) — the needle in the haystack.

---

## 🔍 SPL Detection Queries

See [`queries/detection_rules.spl`](queries/detection_rules.spl) for all queries. Key examples below.

### Detect All SMB Brute Force Attempts
```spl
index=main source="WinEventLog:Security" EventCode=4625 Logon_Type=3
| stats count by IpAddress, Account_Name, _time
| sort -count
```

### Isolate Successful Network Breach from Noise
```spl
index=main source="WinEventLog:Security" Logon_Type=3
| eval Security_State = case(
    Logon_Type == 3 AND EventCode == 4624, "🎯 NETWORK BREACH",
    Logon_Type == 3 AND EventCode == 4625, "❌ BRUTE FORCE",
    1=1, "Normal Noise"
  )
| search Security_State != "Normal Noise"
| table _time, IpAddress, Account_Name, Security_State
```

### Attack Velocity Over Time
```spl
index=main source="WinEventLog:Security" EventCode=4625 Logon_Type=3
| timechart span=1m count AS "Failed_Attempts"
```

---

## 📊 Dashboard

The custom dashboard was built by writing **raw Simple XML** directly in Splunk's source editor, bypassing the Free Tier GUI restriction on the Visualization tab.

**Panels:**
| Panel | Type | Purpose |
|---|---|---|
| Brute Force KPI | `<single>` | Count of `Logon_Type=3` failures — turns red on detection |
| Network Breach KPI | `<single>` | Count of `Logon_Type=3` successes |
| Attack Velocity | `<chart>` | `timechart span=1m` stacked columns — shows spike vs. baseline |
| Forensic Timeline | `<table>` | Full incident table with tokenized IP filter (`$ip_tok$`) |

> See [`dashboards/brute_force_dashboard.xml`](dashboards/brute_force_dashboard.xml) for the full Simple XML source.

---

## 🔬 False Positive Reduction — Logon_Type Analysis

Raw searches on `EventCode=4625` alone return massive amounts of background Windows service noise. The key insight was filtering on **Logon_Type**:

| Logon_Type | Description | Classification |
|---|---|---|
| `2` | Interactive (Console Login) | ✅ Normal |
| `5` | Service (Background Services) | ✅ Normal |
| `3` | **Network (SMB/RPC)** | 🚨 **Attack Surface** |

Only `Logon_Type=3` events are relevant to network-based brute force via SMB.

---

## 🛠️ Incident: CLI Recovery from Splunk Lockout

During deployment, the Splunk Enterprise trial license expired/glitched, locking the web UI at `localhost:8000` and rejecting all admin credentials.

**Resolution (no reinstall required):**
1. Accessed the Splunk filesystem directly via macOS Terminal
2. Navigated to `/Applications/Splunk/etc/system/local/`
3. Manually edited `user-seed.conf` to reset the admin credential hash
4. Edited `server.conf` to force migration to the **Splunk Free License**
5. Cleared orphaned daemon processes blocking ports `8000`, `8089`, and `8191`:

```bash
# Identify orphaned PIDs hoarding critical ports
sudo lsof -t -i:8000 -i:8089 -i:8191

# Force-kill all orphaned daemons
sudo lsof -t -i:8000 -i:8089 -i:8191 | xargs sudo kill -9

# Clean restart
sudo /Applications/Splunk/bin/splunk start
```

---

## 🔒 OPSEC Notes

All internal network topology data has been sanitized prior to publishing:
- RFC 1918 IP addresses replaced with `[TARGET_IP]` / `[ATTACKER_IP]`
- Internal hostnames replaced with `[TARGET_HOST]`
- User account names replaced with `[TARGET_USER]`

---

## 📁 Repository Structure

```
siem-lab/
├── README.md
├── configs/
│   ├── inputs.conf          # Splunk UF — what to collect & forward
│   └── props.conf           # Splunk Indexer — timestamp normalization
├── dashboards/
│   └── brute_force_dashboard.xml   # Simple XML dashboard source
├── queries/
│   └── detection_rules.spl  # All SPL queries used in the lab
├── screenshots/
│   ├── dashboard_overview.png
│   ├── attack_velocity_chart.png
│   ├── brute_force_kpi_red.png
│   ├── forensic_table.png
│   ├── windows_event_viewer_4625.png
│   ├── windows_audit_policy.png
│   └── crackmapexec_terminal.png
└── docs/
    └── full_technical_report.md
```

---

## 🧰 Tech Stack

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Windows](https://img.shields.io/badge/Windows_11-0078d4?style=for-the-badge&logo=windows-11&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)

---

*Lab designed and engineered by Howard Wu*
