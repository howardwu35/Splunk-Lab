# Technical Engineering Report: SIEM Deployment & Brute-Force Detection Lab

**Lead Engineer:** Howard Wu  
**Classification:** Public (Sanitized)

---

## Objective

Architect a closed-loop Security Information and Event Management (SIEM) environment to ingest, parse, and visualize unauthorized SMB network authentication attempts in real time.

---

## 1. Infrastructure & Topology Overview

| Component | Details |
|---|---|
| **Host OS** | macOS (Running Splunk Enterprise Core) |
| **Target Node** | Windows 11 VM (Running Splunk Universal Forwarder) |
| **Attacker Node** | Kali Linux VM (Running Metasploit / CrackMapExec) |
| **Network Schema** | Internal NAT/Host-Only routing |
| **IPs** | Redacted — `[TARGET_IP]`, `[ATTACKER_IP]` |

---

## 2. Endpoint Telemetry Configuration (Windows 11 Target)

To ensure the target machine generated high-fidelity forensic data, default Windows logging had to be overridden.

### Audit Policy Modification

By default, Windows does not log all authentication events. Configuration path:

```
secpol.msc → Security Settings → Advanced Audit Policy Configuration
  → System Audit Policies → Logon/Logoff → Audit Logon
    → ✅ Success  ✅ Failure
```

**Result:** OS now generates:
- **Event ID 4624** — Successful Logon
- **Event ID 4625** — Failed Logon

### Universal Forwarder (UF) Deployment

- Installed Splunk UF on the Windows VM
- Verified the `SplunkForwarder` service runs as **Local System**  
  *(Required to read the protected `Security.evtx` channel — `NT AUTHORITY` level access)*

---

## 3. SIEM Core Configuration & Access Recovery (macOS Host)

During the initial macOS deployment, the Splunk instance suffered an identity and license lockout.

### The Access Crisis

The default 60-day Enterprise Trial expired/glitched, locking the web interface at `localhost:8000` and rejecting all administrative credentials.

### CLI Recovery & License Migration

Rather than reinstalling, the backend filesystem was accessed directly via macOS Terminal:

1. Navigated to `/Applications/Splunk/etc/system/local/`
2. Manually edited `user-seed.conf` to reset the admin credential hash
3. Edited `server.conf` to force downgrade to **Splunk Free License**

**Significance:** Demonstrated ability to manage Splunk via CLI when the GUI is unavailable — a critical operational skill.

---

## 4. Network Contention & Process Management

Before ingestion could begin, the Splunk daemon crashed and left orphaned background processes holding critical network ports.

### Symptom

Splunk failed to start, throwing errors that **Port 8000** (Web UI) and **Port 8191** (KV Store / Internal MongoDB) were already occupied.

### Forensic Process Hunting

```bash
# Map listening ports to hidden PIDs
sudo lsof -t -i:8000 -i:8089 -i:8191

# Force-kill all orphaned daemons
sudo lsof -t -i:8000 -i:8089 -i:8191 | xargs sudo kill -9

# Clean restart
sudo /Applications/Splunk/bin/splunk start
```

**Root Cause:** The KV Store process did not shut down cleanly during the license migration, leaving a zombie daemon on port 8191.

### Ingestion Port Configuration

Configured Splunk Web to actively listen on **TCP/9997** for incoming Universal Forwarder traffic:

```
Settings → Forwarding and Receiving → Configure Receiving → New → 9997
```

---

## 5. The Parsing Pipeline & Timestamp Synchronization

This was the most complex technical hurdle of the project.

### Symptom

An attack executed at **00:30 EST** was being indexed by Splunk as **03:30 EST**. Splunk's native "Last 60 Minutes" search window filtered out the events because it perceived them as future data — the attack was invisible.

### Root Cause Analysis

The Windows VM and the macOS host had a timezone offset. The Splunk Indexer was misinterpreting the local Windows timestamp due to a lack of explicit `%Z` (timezone) declarations in the raw Windows XML event payload.

### Engineering Fix

Forced data normalization at the parsing phase via `props.conf`:

```ini
[WinEventLog:Security]
MAX_TIMESTAMP_LOOKAHEAD = 30
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%Q%Z
```

**Result:** Splunk now rigorously extracts the exact time string from the Windows XML payload, correcting the 3-hour drift and allowing logs to populate in real time.

---

## 6. Attack Simulation & Threat Emulation

With the pipeline stable, a simulated adversary attack was launched from the Kali Linux node.

### Phase 1 — Brute Force (Noise Generation)

```bash
crackmapexec smb [TARGET_IP] \
  -u Administrator \
  -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Generates a flood of **Event ID 4625** (Failed Logon) logs in the target's `Security.evtx`.

### Phase 2 — Successful Compromise (Signal Generation)

```bash
crackmapexec smb [TARGET_IP] -u [TARGET_USER] -p [CORRECT_PASSWORD]
```

Generates a single **Event ID 4624** (Successful Logon) — the needle in the haystack that the dashboard must surface.

---

## 7. SIEM Tuning & False Positive Reduction

Initial searches for `EventCode=4625` and `EventCode=4624` yielded massive amounts of irrelevant data because Windows constantly authenticates background services.

### Tuning Strategy: Shift Focus to Logon_Type

| Logon_Type | Meaning | Classification |
|---|---|---|
| `2` | Interactive (Console Login) | ✅ Normal Background Noise |
| `5` | Service (Background Service Auth) | ✅ Normal Background Noise |
| `3` | **Network (SMB / RPC)** | 🚨 **Attack Surface** |

### SPL Implementation

The `eval` + `case()` commands dynamically reclassify events during the search phase:

```spl
| eval Security_State = case(
    Logon_Type == 3 AND EventCode == 4624, "🎯 NETWORK BREACH",
    Logon_Type == 3 AND EventCode == 4625, "❌ BRUTE FORCE",
    1=1, "Normal Noise"
  )
```

---

## 8. Custom Dashboard Engineering

The Splunk Free Tier restricts the drag-and-drop dashboarding interface (Visualization tab is grayed out).

### Workaround

Bypassed the GUI entirely by writing raw **Simple XML** directly in Splunk's source code editor.

### Architected Panels

| Panel | Visualization | Key Detail |
|---|---|---|
| Brute Force KPI | `<single>` | `rangeColors` turns red when `Logon_Type=3` failures detected |
| Network Breach KPI | `<single>` | `rangeColors` turns red on successful `Logon_Type=3` event |
| Attack Velocity | `<chart>` | `timechart span=1m` — visual spike of Kali traffic vs flat baseline |
| Forensic Timeline | `<table>` | Tokenized `$ip_tok$` input — analysts filter by attacker IP dynamically |
| Noise Analysis | `<table>` | Full Logon_Type distribution breakdown |

---

## 9. Operations Security (OPSEC)

Prior to publishing this documentation:

- Sanitized all internal RFC 1918 IP addresses (`10.0.0.x` → `[TARGET_IP]`, `[ATTACKER_IP]`)
- Replaced explicit user account names with `[TARGET_USER]`
- Removed internal hostname references
- Confirmed no SSID, MAC address, or hardware identifiers present

*Leaking internal topology schemas, even for a home lab, constitutes poor security hygiene and violates enterprise data handling best practices.*
