# Windows Event Log Forensic Analyzer (`windows_evtx_analyzer`)

An enterprise-grade, modular Python framework for offline Windows Event Log (`.evtx`) ingestion, normalization, SQLite + FTS5 full-text indexing, Sigma rule threat hunting, cross-channel correlation, and timeline reconstruction. Built for Digital Forensics and Incident Response (DFIR) practitioners, this engine eliminates the manual overhead of sifting through Windows Event Viewer by transforming raw binary XML records into a unified, queryable UTC timeline.

---

## Core Capabilities

* **Chunk-Level `.evtx` Ingestion (`src/core/ingester.py`):** Safely iterates through binary chunks and records across entire log directories (e.g., `C:\Windows\System32\winevt\Logs`) offline using `python-evtx`, gracefully handling zero-byte, truncated, or corrupted records.
* **SQLite + FTS5 Indexing (`src/core/storage.py`):** High-throughput WAL-mode database with B-Tree indexes and an external-content FTS5 virtual table for sub-second full-text search across millions of records.
* **Plug-and-Play Normalizer Registry (`src/normalizers/`):** Automatically routes log channels to specialized parsers while preserving unmapped auxiliary system logs via a universal `GenericNormalizer` fallback—ensuring zero telemetry loss.
* **Sigma Rule Detection Engine (`src/hunting/sigma_engine.py`):** Evaluates standard YAML Sigma rules with modifier support (`contains`, `startswith`, `endswith`, `re`, `all`) and boolean condition parsing, generating MITRE ATT&CK-mapped alerts.
* **Enterprise Breach & Threat Hunting Focus:** Purpose-built extractors for tracking initial access, privilege escalation, persistence mechanisms, lateral movement, Kerberos/Active Directory abuse, and data exfiltration.
* **Stateful Event Correlation (`src/engine/`):** Reconstructs parent-child process execution trees (`ProcessGuid`), tracks authentication logon sessions (`LogonId` / `LogonGuid`), and pivots across network and DNS telemetry.
* **Structured Reporting (`src/exporters/`):** Exports clean, chronologically sorted timelines and detection alerts in JSON and CSV formats for rapid threat hunting and reporting.

---

## Supported Log Channels & Telemetry

| Module | Target Channels | Key Forensic Artifacts Extracted |
| :--- | :--- | :--- |
| **`security.py`** | `Security.evtx` | Logon/Logoff events (4624/4625/4648), Logon Types, Special Privileges (4672), Process Creation (4688), Account/Group Manipulation (4720/4732), Log Clearing (1102). |
| **`sysmon.py`** | `Microsoft-Windows-Sysmon%4Operational.evtx` | Full Process Creation trees & command lines (ID 1), Network Connections (ID 3), File Creations (ID 11), Registry Modifications (ID 13), DNS Queries (ID 22). |
| **`powershell.py`** | `Microsoft-Windows-PowerShell%4Operational.evtx`<br>`Windows PowerShell.evtx` | De-obfuscated Script Block Logging (ID 4104), pipeline execution details, remote host invocation. |
| **`domain.py`** | `Directory Service.evtx`<br>Domain Controller `Security.evtx` | Kerberos TGT/TGS requests & encryption downgrades (4768/4769 - Kerberoasting), DCSync replication abuse (4662), AD Object/ACL changes (5136). |
| **`persistence.py`** | `TaskScheduler%4Operational.evtx`<br>`GroupPolicy%4Operational.evtx`<br>`AppLocker` logs | Scheduled task registrations/updates (106/140/4698), GPO policy applications, binary/script execution blocks. |
| **`defense_network.py`** | `Windows Defender%4Operational.evtx`<br>`Windows Firewall` logs<br>`Bits-Client%4Operational.evtx` | Malware detections, quarantine actions, firewall blocks/allows, background file transfer URLs (BITS abuse). |
| **`session_wmi.py`** | `TerminalServices` logs<br>`Winlogon%4Operational.evtx`<br>`WMI-Activity%4Operational.evtx` | RDP session connections/reconnections, interactive user sessions, WMI event consumer persistence and remote execution. |
| **`generic.py`** | All other unmapped `.evtx` files | Standardized baseline metadata (`Timestamp`, `EventID`, `Provider`, `Computer`) plus full `EventData` key-value extraction. |

---

## Project Architecture

```text
windows_evtx_analyzer/
├── pyproject.toml
├── README.md
├── rules/
│   ├── windows_dcsync_attack.yml        # Event ID 4662 replication GUID detection
│   └── windows_kerberoasting.yml        # Event ID 4769 RC4 service ticket detection
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── ingester.py                  # Low-level .evtx chunk & record iteration
│   │   ├── parser.py                    # BinXML extraction & XML-to-dict mapping
│   │   └── storage.py                   # WAL-mode SQLite storage & FTS5 full-text indexing
│   ├── normalizers/
│   │   ├── __init__.py
│   │   ├── base.py                      # Abstract base normalizer interface
│   │   ├── registry.py                  # Dynamic channel-to-normalizer router
│   │   ├── security.py                  # Security.evtx parser
│   │   ├── sysmon.py                    # Sysmon operational telemetry parser
│   │   ├── powershell.py                # PowerShell operational & admin parser
│   │   ├── domain.py                    # Active Directory / DC log parser
│   │   ├── persistence.py               # TaskScheduler, GPO, and AppLocker parser
│   │   ├── defense_network.py           # Defender, Firewall, and BITS parser
│   │   ├── session_wmi.py               # RDP, Winlogon, and WMI-Activity parser
│   │   └── generic.py                   # Universal fallback for unmapped channels
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── correlation.py               # Process tree & session pivoting state machine
│   │   └── timeline.py                  # Unified UTC timeline sorting & filtering
│   ├── hunting/
│   │   ├── __init__.py
│   │   └── sigma_engine.py              # YAML Sigma rule loader, modifier evaluator & matcher
│   ├── exporters/
│   │   ├── __init__.py
│   │   ├── json_exporter.py             # Structured JSON timeline & alert export
│   │   └── csv_exporter.py              # Flat CSV export for spreadsheet analysis
│   └── cli.py                           # Enterprise CLI entry point
└── tests/
    ├── __init__.py
    ├── test_ingester.py
    ├── test_parser.py
    └── test_normalizers.py
```

---

## Installation & Quick Start

Install the package in editable mode along with development dependencies:

```bash
pip install -e ".[dev]"
```

### CLI Usage Examples

```bash
# 1. Ingest a log directory into SQLite, run Sigma detection rules, and export timeline + alerts
evtx-analyzer -i ./collected_logs/ --db case01.db --rules rules/ -o timeline.json --alerts-out alerts.json

# 2. Query an existing indexed SQLite case database using FTS5 full-text search
evtx-analyzer --db case01.db --query "mimikatz OR sekurlsa OR psexec" -o search_results.json

# 3. Filter for specific high-risk Event IDs and export directly to CSV
evtx-analyzer -i ./collected_logs/Security.evtx --event-ids 4624 4625 4688 4769 -o auth_events.csv --format csv
```

---

## Forensic Investigation Workflow

1. **Ingest & Parse:** Raw binary XML chunks are extracted offline without relying on native Windows APIs, making the tool fully cross-platform (Linux/macOS/Windows).
2. **Normalize:** Cryptic Windows event codes (e.g., Logon Type `10`, Kerberos Encryption `0x17`) are translated into human-readable forensic context across all log channels.
3. **Index & Hunt:** Normalized records are persisted into a WAL-mode SQLite + FTS5 database while the Sigma engine evaluates YAML detection rules in-flight to flag MITRE ATT&CK techniques.
4. **Correlate & Export:** Events are linked across log channels using `ProcessGuid`, `TargetLogonId`, and `LogonGuid` to trace an attacker's exact path from initial foothold to domain dominance, exporting chronological UTC timelines and alerts.

---

## Author

* **Rashid Dewewe** 

---

## Acknowledgments

* **[Willi Ballenthin (`python-evtx`)](https://github.com/williballenthin/python-evtx):** For providing the foundational pure-Python binary XML and chunk parser that enables cross-platform offline `.evtx` analysis.
* **[SigmaHQ Project](https://github.com/SigmaHQ/sigma):** For establishing the open-source generic signature format and community threat detection rulesets used to standardize Windows event hunting.
* **[MITRE ATT&CK®](https://attack.mitre.org/):** For the adversarial tactics, techniques, and common knowledge framework used to categorize and map detection alerts.
* **Open-Source DFIR Community:** For continuous research into Windows Event Log telemetry, Active Directory attack paths, and Sysmon forensic artifacts.