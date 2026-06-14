# AI junior SOC Analyst 

An AI-powered Security Operations Center (SOC) Analyst platform built using Python, TShark, MITRE ATT&CK mapping, automated incident reporting, and AI-assisted threat triage.

## Overview

AI SOC Analyst V2 automates the early stages of security operations by capturing network traffic, detecting suspicious behavior, generating structured alerts, mapping activity to MITRE ATT&CK techniques, calculating risk scores, and producing incident reports.

The platform can identify common network threats such as ICMP flood activity and port scanning, then enrich the findings with AI-driven analysis and recommendations.

---

## Features

* Real-time network traffic capture using TShark
* Automated ICMP Flood Detection
* Automated Port Scan Detection
* MITRE ATT&CK Technique Mapping
* Dynamic Risk Scoring
* Severity Classification
* JSON Alert Generation
* Automated Incident Report Generation
* AI-Powered Threat Triage
* SOC Workflow Automation

---

## Architecture

The following diagram illustrates the end-to-end workflow of the AI SOC Analyst V2 platform, from network traffic generation and packet capture to threat detection, MITRE ATT&CK mapping, AI-assisted triage, and incident reporting.

![AI SOC Analyst Architecture](screenshots/architecture.png)
---

## Detection Capabilities

### ICMP Flood Detection

Detects excessive ICMP traffic directed toward monitored hosts.

**MITRE ATT&CK**

* T1498 — Network Denial of Service

### Port Scan Detection

Detects hosts contacting an unusually large number of destination ports within a short time window.

**MITRE ATT&CK**

* T1046 — Network Service Discovery

---

## Technologies Used

* Python 3
* TShark
* Nmap
* JSON
* Requests
* MITRE ATT&CK Framework
* VirtualBox
* Kali Linux
* Ubuntu

---

## Screenshots

### Port Scan Detection

![Port Scan Detection](screenshots/port_scan_detection.png)

### ICMP Flood Detection

![ICMP Flood Detection](screenshots/icmp_flood_detection.png)

---

## Sample Outputs

### Alert JSON

Located in:

```text
sample_outputs/alerts.json
```

### Incident Report

Located in:

```text
sample_outputs/incident_report.png
```

---

## Installation

Install required Python packages:

```bash
pip install -r requirements.txt
```

Install TShark:

```bash
sudo apt install tshark
```

Install Nmap:

```bash
sudo apt install nmap
```

---

## Usage

Run the SOC Analyst:

```bash
python3 ai_soc_analyst_v2.py
```

Generate ICMP traffic:

```bash
ping <target-ip> -c 100
```

Generate a port scan:

```bash
nmap -p 1-1000 <target-ip>
```

---

## Future Improvements

* SSH Brute Force Detection
* Failed Login Detection
* VirusTotal Enrichment
* AbuseIPDB Integration
* PDF Incident Reports
* Wazuh Integration
* Threat Intelligence Enrichment
* Dashboard Visualization

---

## Disclaimer

This project was developed for educational and defensive cybersecurity purposes only. Use only in environments where you have authorization to perform testing.

---

## Author

Developed as a cybersecurity portfolio project focused on SOC automation, threat detection, and AI-assisted incident triage.
