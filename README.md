<p align="center">
  <img width="900" src="https://github.com/user-attachments/assets/46716778-34e5-475a-885a-34c16a880ef1" />
</p>

# 🛡️ Microsoft Sentinel Honeypot IR

> A controlled Azure honeypot case study documenting the full defensive lifecycle: build, telemetry engineering, detection, deliberate exposure, live compromise, threat hunting, containment, recovery, and validation.

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-SIEM-0078D4)
![Defender for Endpoint](https://img.shields.io/badge/Microsoft%20Defender-EDR-5C2D91)
![KQL](https://img.shields.io/badge/KQL-Threat%20Hunting-0067B8)
![Incident Response](https://img.shields.io/badge/Incident%20Response-NIST%20Lifecycle-C2410C)
![Status](https://img.shields.io/badge/Status-Contained%20%26%20Recovered-2EA44F)

**Analyst:** Alvin Turner Jr.  
**Host:** `corp-hr01-pe365`  
**Workspace:** `LAW-Cyber-Range`  
**Investigation window:** July 29–30, 2026  
**Classification:** Confirmed MySQL database-layer compromise with destructive impact; Windows-host compromise not established

---

## 📌 Executive Summary

A Windows honeypot running MySQL 8.0 was instrumented with Microsoft Defender for Endpoint (MDE), Azure Monitor Agent (AMA), a Data Collection Rule (DCR), Log Analytics, and Microsoft Sentinel. After analytics rules and a clean baseline were established, the lab intentionally exposed RDP and MySQL to the internet and weakened selected controls to observe real attacker behavior.

The MySQL audit evidence confirms repeated password guessing against `root`, `admin`, and `sa`, followed by successful external `root` authentication. A connection from `212.30.36.213` at `2026-07-29T06:10:23Z` immediately preceded database enumeration, ransom-note creation, and destructive SQL. Across the exported query set, the actor issued **30 `DROP TABLE` operations** against `cr_corp_01`, `sakila`, and `world`, and created `RECOVER_YOUR_DATA_info` tables containing extortion instructions.

MDE endpoint telemetry did **not** establish an external Windows takeover. The supplied `DeviceLogonEvents` contained one failed external `guest` network logon, while successful RDP sessions belonged to the expected `bobby` account from private `10.0.8.x` addresses. Process, file, and registry review found no clear attacker payload, malicious PowerShell, credential dumping, or persistence. The defensible conclusion is therefore a **confirmed database-service compromise**, not a proven compromise of the underlying Windows operating system.

The endpoint was isolated through MDE at approximately `2026-07-30T23:51:45Z`, evidence was preserved, exposed controls were hardened, a Defender full scan returned zero threats, and the database was restored from a known-good source.

---

## 🎯 Objectives

- Deploy a realistic internet-facing Azure honeypot.
- Ingest endpoint and MySQL telemetry into `LAW-Cyber-Range`.
- Build KQL detections before exposure and validate that they are quiet against a baseline.
- Detect and investigate real authentication and database activity.
- Correlate Sentinel, MDE, MySQL, and host evidence without overstating conclusions.
- Execute containment, eradication, recovery, and validation.
- Preserve pre- and post-incident investigation packages for DFIR comparison.
- Visualize authentication activity in a device-scoped Sentinel Workbook.

---

## 🧭 Environment

| Layer | Implementation |
|---|---|
| Cloud | Microsoft Azure resource group, VNet, public IP, NSG |
| Endpoint | Windows honeypot VM, `corp-hr01-pe365` |
| Database | MySQL Server 8.0 with synthetic `cr_corp_01` data |
| Endpoint security | Microsoft Defender for Endpoint |
| Collection | Azure Monitor Agent + custom-text-log DCR |
| Log storage | Azure Log Analytics, `LAW-Cyber-Range` |
| SIEM | Microsoft Sentinel |
| Custom table | `MySQLAudit_CL` |
| Endpoint tables | `DeviceInfo`, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` |
| Analysis | Kusto Query Language (KQL), Sentinel analytics, incidents, and Workbooks |

> **Safety boundary:** This was an authorized cyber-range exercise using synthetic data. The VM was intentionally weakened only after telemetry and detections were operational. Tenant-level egress restrictions limited outbound abuse paths.

---

## 📚 Contents
<a id="architecture-telemetry"></a>
- [Architecture & telemetry](#-architecture-telemetry)
- [Detection engineering](#-detection-engineering)
- [Controlled exposure](#-controlled-exposure)
- [Confirmed findings](#-confirmed-findings)
- [Attack timeline](#-attack-timeline)
- [Investigation](#-investigation)
- [MITRE ATT&CK](#-mitre-attck)
- [Containment & recovery](#-containment--recovery)
- [DFIR package comparison](#-dfir-package-comparison)
- [Sentinel Workbook](#-sentinel-workbook)
- [Detection improvements](#-detection-improvements)

---

# 🏗️ Architecture & Telemetry

The honeypot generated two complementary telemetry streams:

1. **Endpoint telemetry:** MDE sent device, authentication, process, file, and registry events to the connected Defender/Sentinel environment.
2. **MySQL telemetry:** MySQL general-query logging wrote connection and query records to `mysql_general.log`. AMA collected the file through a DCR and routed it into `MySQLAudit_CL`.

<p align="center">
<img width="800" src= "https://github.com/user-attachments/assets/eb84935e-6c2b-481c-b61a-ac8f8aa496b6" />
</p>

<details>
<summary><strong>Evidence: synthetic database and MySQL logging</strong></summary>

### Synthetic database

The `cr_corp_01` database was populated with fake customers, orders, payments, and credentials to provide realistic—but non-production—targets.

<img width="800" src= "https://github.com/user-attachments/assets/080ee7db-0e9f-44ca-9b8e-f6f72983e099" />

### General query logging

MySQL general logging was enabled so both authentication activity and SQL statements could be reconstructed.

<img width="800" src="https://github.com/user-attachments/assets/1dfb6e1c-5448-4cd2-a186-cd020defbd05" />

</details>

<details>
<summary><strong>Evidence: DCR, AMA, and MDE telemetry</strong></summary>

### Data Collection Rule

<img width="800" src= "https://github.com/user-attachments/assets/f42cc1d3-3db4-4bce-9f72-52524dfde6c8" />

### Azure Monitor Agent

<img width="800" src= "https://github.com/user-attachments/assets/170f2a77-6782-47f0-b6e0-4df274be3028" />

### MDE device telemetry

<img width="800" src= "https://github.com/user-attachments/assets/6343a732-710e-4f21-8680-9e07a14abaab" />

</details>

### Ingestion validation

```kql
MySQLAudit_CL
| project TimeGenerated, RawData, _ResourceId
| where _ResourceId endswith "corp-hr01-pe365"
| sort by TimeGenerated desc
```

<img width="800" src="https://github.com/user-attachments/assets/77dd4845-2f1c-4265-bba9-5177462e9646" />

---

# 🚨 Detection Engineering

Detections were created **before** internet exposure so the lab could demonstrate detection readiness rather than retrospective query writing.

## Rule 01 — Successful Windows logon to the honeypot

**Purpose:** Alert when a monitored local account successfully authenticates to the exposed device and retain host/IP entities for investigation.

```kql
let MyDevice = "corp-hr01-pe365";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName in~ ("bobby", "guest")
| where ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP, AccountName, DeviceName, ActionType, LogonType
```

**Entity mapping:**

- Host → `DeviceName`
- IP → `RemoteIP`

## Rule 02 — Successful MySQL authentication

**Purpose:** Parse raw MySQL connection records, remove failed connection IDs, and return successful logons with device, username, and source IP context.

<img width="800" alt="Image" src="https://github.com/user-attachments/assets/ad3add85-871a-41d2-a092-7016c3c51f9e" />

## Rule tuning notes

- Exclude known administrative sources only after validation.
- Keep successful public database authentication high-signal.
- Use thresholds for failures, but correlate failure bursts with a later success.
- Map host, IP, and account entities so the incident graph is useful.
- Preserve `RawData` during early tuning for parsing validation.
- Avoid labeling every success malicious; geographic novelty and asset context require analyst review.

  <img width="800" src= "https://github.com/user-attachments/assets/ad906220-d807-4de5-9ac1-3f48cee1c15b" />

---

# ⚠️ Controlled Exposure

After the baseline and detections were validated, the lab deliberately introduced the following weaknesses:

- A network-accessible MySQL `root@'%'` account with a weak password.
- Disabled Windows Defender Firewall profiles.
- An NSG rule allowing unrestricted inbound traffic.
- Weak or enabled local accounts for observation of authentication attempts.

<details>
<summary><strong>Evidence: intentionally weakened controls</strong></summary>

### Network-accessible MySQL root account

<img width="800" src="https://github.com/user-attachments/assets/6d77c55e-c643-4d52-b1be-3439e4ac35b9" />

### Windows Firewall disabled

<img width="800" src="https://github.com/user-attachments/assets/85d04459-2995-4a8e-858b-0974da42d69d" />

### NSG allow-all inbound rule

<img width="800" src="https://github.com/user-attachments/assets/f492c157-b122-40c8-be80-e42c9873b1d0" />

</details>

> These settings are unsafe outside an isolated and authorized lab. They are documented as the causal attack surface, not as recommended deployment guidance.

---

# 🔎 Confirmed Findings

## Evidence summary

| Finding | Evidence | Assessment |
|---|---|---|
| MySQL password guessing | Repeated failures for `root`, `admin`, and `sa` from external IPs | Confirmed |
| External MySQL `root` access | 20 successful `root` connection records across several external IPs in the export | Confirmed |
| Destructive SQL | 30 `DROP TABLE` statements in the supplied query export | Confirmed |
| Ransom/extortion objects | `RECOVER_YOUR_DATA_info` / `READ_ME` tables and messages | Confirmed |
| Database enumeration | `SHOW DATABASES`, `SHOW TABLES`, `SHOW CREATE TABLE`, and metadata queries | Confirmed |
| Data reads | `SELECT` and dump-like SQL against synthetic tables | Confirmed; outbound transfer volume not proven |
| External Windows `guest` access | One network logon failure from `45.156.128.76` | Attempt confirmed; access not achieved |
| Windows RDP compromise | No external `LogonSuccess` in the supplied endpoint export | Not established |
| Endpoint malware or persistence | No clear attacker payload, malicious PowerShell, credential dumping, or persistence in supplied MDE exports | Not established |

## Authentication metrics from the exported evidence

| Data source | Result |
|---|---:|
| MySQL authentication records | 58 |
| MySQL logon failures | 32 |
| MySQL logon successes | 26 |
| Successful MySQL `root` records | 20 |
| Windows endpoint logon records | 36 |
| Expected `bobby` logon successes | 28 |
| External Windows logon failures | 1 |
| External Windows logon successes | 0 |

## Why the distinction matters

MySQL can process remote SQL through the existing database service without launching a new attacker-controlled Windows process. Destructive activity inside MySQL therefore does not, by itself, prove execution on the operating system. This project preserves that boundary:

> **The database was compromised. The available endpoint evidence does not establish compromise of the underlying Windows host.**

---

# ⏱️ Attack Timeline

All canonical times below use UTC where the raw MySQL log provided a `Z` timestamp. Local screenshots rendered approximately four hours behind UTC.

| UTC time | Event | Evidence |
|---|---|---|
| `2026-07-29T06:02:18Z` | Password guessing begins from `77.90.185.30` against `root`, `admin`, and `sa` | `MySQLAudit_CL` auth export |
| `2026-07-29T06:02:20Z` | `root` authentication succeeds from `77.90.185.30` | MySQL auth log |
| `2026-07-29T06:10:23Z` | External `root` session begins from `212.30.36.213` | MySQL auth log |
| `2026-07-29T06:10:38Z` | `RECOVER_YOUR_DATA_info` created in `cr_corp_01` | MySQL query log |
| `2026-07-29T06:10:41Z` | Extortion text inserted | MySQL query log |
| `2026-07-29T06:10:43Z` | `customers`, `orders`, `credentials`, and `payments` dropped | MySQL query log |
| `2026-07-29T06:11:41Z`–`06:12:08Z` | `sakila` and `world` ransom objects created; multiple tables dropped | MySQL query log |
| `2026-07-29T06:33:10Z`* | External `guest` Windows network logon fails from `45.156.128.76` | `DeviceLogonEvents` |
| Jul 29–30 | Additional MySQL password guessing and successful `root` sessions observed | MySQL auth evidence |
| Jul 30 | Later screenshot evidence shows recurring destructive database activity | Sentinel/MySQL screenshot evidence |
| `2026-07-30T23:51:45Z`* | MDE device isolation completed/recorded | MDE containment evidence |
| Jul 30 | NSG, firewall, accounts, and MySQL access hardened; database restored | Recovery evidence |

\* Converted from EDT-rendered portal time; fractional seconds were not available.

---

# 🧪 Investigation

<details open>
<summary><strong>Investigation 01 — MySQL authentication</strong></summary>

### Objective

Determine whether the internet-facing database received password attacks and whether authentication succeeded.

### Finding

The authentication export contained 32 failures and 26 successes. External sources repeatedly cycled through `root`, `admin`, and `sa`. The pattern at `77.90.185.30`—failures followed seconds later by a `root` success—supports automated password guessing and use of valid database credentials.

<img width="800" src="https://github.com/user-attachments/assets/c27037e8-8d3e-4669-96bd-e0aa2bcabe08" />

### Analyst conclusion

**Confirmed:** the exposed MySQL service accepted external `root` authentication.

</details>

<details open>
<summary><strong>Investigation 02 — Destructive SQL and ransom-note creation</strong></summary>

### Objective

Reconstruct database activity after successful external authentication.

### Finding

The query evidence shows database/schema discovery followed by creation of `RECOVER_YOUR_DATA_info`, insertion of ransom instructions, and destructive drops across three databases. The supplied export contains 30 `DROP TABLE` statements.

<img width="800" src="https://github.com/user-attachments/assets/cd2cc829-819c-4a0f-9497-c7742017fba1" />

<img width="800" src="https://github.com/user-attachments/assets/8e6d7793-3746-4e1b-86b2-41323335c03d" />

### Analyst conclusion

**Confirmed:** stored data was manipulated and database availability was impacted. The evidence supports data destruction with extortion—not encryption for impact.

</details>

<details>
<summary><strong>Investigation 03 — Windows authentication</strong></summary>

### Objective

Determine whether the database compromise expanded into a Windows logon compromise.

### Finding

The endpoint export contains 28 successful `bobby` logons from expected private `10.0.8.x` sources, seven associated attempts, and one failed external `guest` network logon from `45.156.128.76`. It contains no successful external Windows logon.

<img width="800" src="https://github.com/user-attachments/assets/4fbeae81-65df-467e-a3d6-349c244a6175" />

### Analyst conclusion

**Not established:** successful external RDP/Windows authentication.

</details>

<details>
<summary><strong>Investigation 04 — Endpoint process, file, and registry review</strong></summary>

### Objective

Search for attacker execution, persistence, file staging, or registry modification after database access.

### Finding

The supplied MDE evidence was dominated by expected Windows, Azure Agent, Defender, RDP-session, and MySQL Workbench activity. `db_info_import.sql` was opened interactively by `bobby`; this aligns with the project build unless the analyst did not authorize the action. No clear encoded/bypassed attacker PowerShell, payload download, account creation, scheduled-task persistence, service persistence, shadow-copy deletion, log clearing, or credential dumping was identified.

<img width="800" src="https://github.com/user-attachments/assets/01e99d5f-7468-497c-9ce4-629ff7427d6a" />

<img width="800" src="https://github.com/user-attachments/assets/75af18d1-1a17-4599-b2b9-cedecb75284d" />

<img width="800" src="https://github.com/user-attachments/assets/b2d503ef-5d7c-40bc-940c-7f80216fc113" />

### Analyst conclusion

**Not established:** attacker-controlled execution or persistence on Windows.

</details>

<details>
<summary><strong>Investigation 05 — Sentinel incident correlation</strong></summary>

Sentinel analytics mapped device and IP entities and produced an incident graph for the monitored host.

<img width="800" src="https://github.com/user-attachments/assets/d5d14984-ff65-440a-9394-ed0f5270d599" />

</details>

---

# 🧬 MITRE ATT&CK

Only techniques supported by the available evidence—or clearly labeled inferences—are included.

| Tactic | Technique | ID | Support |
|---|---|---|---|
| Reconnaissance | Active Scanning | [`T1595`](https://attack.mitre.org/techniques/T1595/) | Inferred from rapid internet discovery and authentication attempts after exposure |
| Credential Access | Password Guessing | [`T1110.001`](https://attack.mitre.org/techniques/T1110/001/) | Multiple external sources attempted common database usernames before `root` successes |
| Initial Access / Persistence / Defense Evasion / Privilege Escalation | Valid Accounts | [`T1078`](https://attack.mitre.org/techniques/T1078/) | Successful external authentication with the MySQL `root` account |
| Collection | Data from Local System | [`T1005`](https://attack.mitre.org/techniques/T1005/) | SQL reads/dump-like queries accessed synthetic database contents; external transfer not proven |
| Impact | Data Destruction | [`T1485`](https://attack.mitre.org/techniques/T1485/) | 30 `DROP TABLE` statements across `cr_corp_01`, `sakila`, and `world` |
| Impact | Stored Data Manipulation | [`T1565.001`](https://attack.mitre.org/techniques/T1565/001/) | Attacker-created ransom tables and inserted extortion content |

## Techniques intentionally not claimed

- `T1021.001` Remote Desktop Protocol — no successful external Windows RDP logon in the supplied export.
- `T1059.001` PowerShell — no malicious PowerShell was established.
- `T1105` Ingress Tool Transfer — no payload download was established.
- `T1547` Boot or Logon Autostart Execution — no malicious autorun persistence was established.
- `T1003` OS Credential Dumping — no credential-dumping activity was established.
- `T1486` Data Encrypted for Impact — the database was dropped/manipulated; encryption was not observed.
  
---

# 🚧 Containment & Recovery

## Containment

Upon confirmation of destructive database activity, the endpoint was isolated through Microsoft Defender for Endpoint. The recorded portal time, converted from EDT, is approximately:

```text
2026-07-30T23:51:45.0000000Z
```
Completed MDE device isolation.

<img width="900" alt="Image" src="https://github.com/user-attachments/assets/9928a198-6e4d-4366-8d8b-7b4d8f58f8dc" />
</p>

Connectivity testing confirmed that the isolated VM was no longer externally reachable.

<img width="900" alt="Image" src="https://github.com/user-attachments/assets/b1e42124-1210-4ab8-bdb4-818d20b6c053" />

## Eradication and recovery

| Action | Validation |
|---|---|
| Removed unrestricted NSG inbound access | Hardened NSG showed only default inbound rules |
| Re-enabled Windows Defender Firewall | Domain, private, and public profiles shown on |
| Hardened local accounts | Unnecessary privileged account removed; Guest disabled |
| Ran full Defender Antivirus scan | 689,279 files scanned; zero threats found |
| Hardened MySQL network root access | Weak/public root configuration removed or rotated |
| Restored synthetic database | `cr_corp_01` tables and query results verified |

<details open>
<summary><strong>Recovery evidence</strong></summary>

### NSG hardened

<img width="800" src="https://github.com/user-attachments/assets/a436c8de-8d75-4589-aa4d-9c980bcbd67d" />

### Windows Firewall enabled

<img width="800" src="https://github.com/user-attachments/assets/83c1ea93-2a7d-456c-be1a-91b999bc54fc" />

### Local accounts hardened

<img width="800" src="https://github.com/user-attachments/assets/6ea2f5d6-3715-4dff-9213-5520e1672d6b" />

### Defender full scan

<img width="800" src="https://github.com/user-attachments/assets/4fdea508-bb50-4199-9309-09d317607bf8" />

### MySQL root hardened

<img width="800" src="https://github.com/user-attachments/assets/71f6f5ab-ed34-4d86-8a61-2e37f8406063" />

### Database restored

<img width="800" src="https://github.com/user-attachments/assets/fc8f96a3-b8d9-4557-a25e-27eeb41e0cfa" />

</details>

## Preferred production response

For a real compromised server, the stronger recovery decision would be to rebuild the VM from a trusted image, rotate all exposed secrets, restrict database reachability, and restore from a verified pre-incident backup. In-place hardening is documented here as the lab recovery path, not as universal production guidance.

---

# 🧰 DFIR Package Comparison

A baseline MDE investigation package was captured before the observed compromise, followed by a comparison package after the breach window. The packages were ordered using their filenames, internal file timestamps, and `SystemInformation.txt` boot times.

| Package role | Archive | Collection timestamp | Basis for ordering |
|---|---|---|---|
| Baseline / pre-breach | `Pre_Breach_MDE_Investigation_Package.zip` | 2026-07-29 04:18–04:37 UTC | Earlier internal timestamps; system boot time was 2026-07-28 17:43:23 |
| Post-breach comparison | `Post_Breach_MDE_Investigation_Package.zip` | 2026-07-30 23:34 UTC | Later internal timestamps; system boot time was 2026-07-30 08:12:04, confirming a reboot between collections |

---

# 📊 Sentinel Workbook

The workbook was scoped to `corp-hr01-pe365` rather than the full cyber range. That keeps the visualization tied to evidence from this project.

## Global RDP authentication activity

The map uses `DeviceLogonEvents`, `RemoteIP`, and `geo_info_from_ip_address()` to visualize inbound authentication activity. GeoIP is approximate and should be treated as regional context—not precise attribution.

<img width="1642" height="593" alt="Image" src="https://github.com/user-attachments/assets/ca34c0c9-0cb6-4311-8870-bd27f05b124b" />

## Source IP breakdown

The supporting table separates successes from failures and retains targeted accounts so the analyst can investigate suspicious authentication instead of relying on the map alone.

<img width="1636" height="493" alt="Image" src="https://github.com/user-attachments/assets/7feac782-0548-4948-9a7d-05596a6f7768" />

```kql
DeviceLogonEvents
| where DeviceName == "corp-hr01-pe365"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
        Longitude = toreal(geo.longitude),
        Country   = tostring(geo.country),
        City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Attempts        = count(),
           Successes       = countif(ActionType == "LogonSuccess"),
           Failures        = countif(ActionType == "LogonFailed"),
           TargetedDevices = dcount(DeviceName),
           Accounts        = make_set(AccountName, 25)
        by RemoteIP, Country, City, Latitude, Longitude
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

---
# 🛠️ Detection Improvements

## Observed gaps

- Successful public MySQL authentication requires immediate, high-signal alerting.
- A failure-only threshold misses the more important transition from failures to success.
- Raw custom logs require reliable parsing and schema validation.
- Database destructive commands need dedicated coverage.
- Database and endpoint evidence must be correlated without assuming host compromise.

## Recommended detections and controls

- Alert on external MySQL `root` success and any success after a failed-authentication burst.
- Detect `DROP DATABASE`, repeated `DROP TABLE`, and creation of ransom-themed objects.
- Alert on broad metadata enumeration followed by high-volume table reads.
- Restrict MySQL to private network paths; do not expose port 3306 publicly.
- Remove `root@'%'`; use named administrative accounts with least privilege and strong secrets.
- Restrict RDP through JIT access, VPN/Bastion, MFA, and source allowlists.
- Enable account lockout and monitor changes to Windows Firewall, NSGs, and database bindings.
- Add `DeviceNetworkEvents` and `NTANetAnalytics` to future collections for stronger network correlation.
- Preserve verified backups and test restoration before exposure exercises.
- Rebuild compromised production hosts from trusted images rather than relying solely on antivirus scans.

---

# 🧾 Final Assessment

This project demonstrates more than an exposed honeypot. It shows the complete security-operations workflow:

```text
Build → Instrument → Baseline → Detect → Expose → Investigate → Contain → Recover → Validate
```

The strongest professional outcome is the evidence-based scope decision. MySQL authentication and query logs confirm valid-account access, database enumeration, destructive SQL, and ransom-note manipulation. MDE does not corroborate attacker control of Windows. Maintaining that distinction prevents an analyst from turning a database incident into an unsupported endpoint-compromise claim.

## Key takeaways

- Detection engineering is strongest when completed before exposure.
- Database telemetry can reveal compromise that endpoint process telemetry cannot.
- A successful authentication deserves more attention than raw failure volume.
- Negative endpoint findings are valuable for defining scope.
- Containment and evidence preservation should precede recovery.
- Recovery is not complete until controls and restored data are validated.

---

## Evidence handling

The repository contains selected screenshots and sanitized findings rather than complete raw investigation artifacts. Original CSV exports and MDE investigation packages were retained separately from the public repository.

---

## 📚 References

- [Microsoft Sentinel documentation](https://learn.microsoft.com/azure/sentinel/)
- [Microsoft Defender XDR advanced hunting](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview)
- [Azure Monitor data collection rules](https://learn.microsoft.com/azure/azure-monitor/data-collection/data-collection-rule-overview)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

---

> Built for defensive education in an authorized cyber range. Do not reproduce the exposure configuration on production or personal systems.
