#!/usr/bin/env python3
"""
AI SOC Analyst - Version 2
============================

Automated network traffic capture, analysis, and alerting pipeline for a
small SOC lab environment.

Workflow:
    1. Capture live traffic with tshark.
    2. Convert the capture to CSV for analysis.
    3. Load and normalize the CSV data.
    4. Detect ICMP floods (MITRE T1498 - Network Denial of Service).
    5. Detect port scans (MITRE T1046 - Network Service Discovery).
    6. Score each detection's severity / risk.
    7. Generate structured JSON alerts.
    8. Generate a human-readable incident report.
    9. Forward each alert to an Airia pipeline for further triage.
"""

import csv
import json
import os
import subprocess
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

import requests

# ==================================================================
# CONFIGURATION
# ==================================================================

# ---- Network capture settings ----
INTERFACE = "eth0"                 # Capture interface (check with: ip a)
CAPTURE_DURATION = 100             # Capture window, in seconds

# V2 captures all IP traffic (not just ICMP) so the same capture can be
# used for both ICMP flood detection AND port scan detection. If you need
# a narrower capture for performance reasons, adjust this filter.
CAPTURE_FILTER = "ip"

# ---- Detection thresholds ----
ICMP_THRESHOLD = 40                 # >= this many ICMP packets from one host = flood
PORT_SCAN_THRESHOLD = 20            # >= this many unique dest ports from one host = scan

# ---- File paths ----
PCAP_FILE = "traffic.pcap"
CSV_FILE = "traffic.csv"
ALERTS_FILE = "alerts.json"
INCIDENT_REPORT_FILE = "incident_report.txt"

# ---- Airia pipeline integration ----
AIRIA_API_URL = "YOUR URL HERE!"

# NOTE: For production use, set AIRIA_API_KEY as an environment variable
# (e.g. `export AIRIA_API_KEY="ak-..."`) instead of relying on the hardcoded
# fallback below. Keeping a key hardcoded in source control is a credential
# exposure risk.
AIRIA_API_KEY = os.environ.get(
    "AIRIA_API_KEY",
    "YOUR API KEY HERE"
)
AIRIA_TIMEOUT_SECONDS = 100

# ---- Lab topology / host metadata ----
# Used to enrich alerts with human-readable hostnames when an IP is known.
HOST_MAP = {
    "192.168.1.16": "Kali-Monitoring-VM",
    "192.168.1.9": "Ubuntu-Traffic-Generator-VM",
}

# Default "monitored" destination context (used when an alert has no clear
# observed destination IP of its own). Mirrors the V1 metadata fields.
DEFAULT_DESTINATION_HOST = "Ubuntu-Traffic-Generator-VM"
DEFAULT_DESTINATION_IP = "192.168.1.9"

# ---- MITRE ATT&CK mappings per alert type ----
MITRE_MAPPINGS = {
    "ICMP Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
    },
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
}

# IP protocol numbers relevant to this script (per IANA)
PROTO_ICMP = "1"
PROTO_TCP = "6"
PROTO_UDP = "17"


# ==================================================================
# HELPERS
# ==================================================================

def run_command(cmd, description):
    """Run a subprocess command, printing a status line first."""
    print(f"[+] {description}")
    subprocess.run(cmd, check=True)


def resolve_host(ip_address):
    """Map a known lab IP address to a human-readable hostname."""
    if not ip_address:
        return "Unknown"
    return HOST_MAP.get(ip_address, "Unknown")


# ==================================================================
# STEP 1 - Capture Traffic
# ==================================================================

def capture_traffic():
    """Capture live traffic on INTERFACE for CAPTURE_DURATION seconds."""
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", CAPTURE_FILTER,
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE,
    ]

    run_command(
        capture_cmd,
        f"Capturing on {INTERFACE} for {CAPTURE_DURATION}s (filter: '{CAPTURE_FILTER}')"
    )

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed: no output file was created.")

    print(f"[+] Capture saved to {PCAP_FILE}")


# ==================================================================
# STEP 2 - Convert to CSV
# ==================================================================

def convert_to_csv():
    """Convert the captured pcap into a CSV with the fields needed for analysis."""
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    if not os.path.exists(CSV_FILE):
        raise RuntimeError("CSV conversion failed: no output file was created.")

    print(f"[+] CSV created at {CSV_FILE}")


# ==================================================================
# STEP 3 - Load CSV Data
# ==================================================================

def load_csv_data():
    """
    Load the traffic CSV into a list of normalized dictionaries.

    Each record contains:
        {
            "time": float or None,
            "src_ip": str,
            "dst_ip": str,
            "proto": str,      # IP protocol number as a string ("1", "6", "17", ...)
            "dst_port": int or None,
            "length": int,
        }
    """
    records = []

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            dst_ip = (row.get("ip.dst") or "").strip().strip('"')
            proto = (row.get("ip.proto") or "").strip().strip('"')
            frame_len_raw = (row.get("frame.len") or "").strip().strip('"')
            time_raw = (row.get("frame.time_epoch") or "").strip().strip('"')

            tcp_port_raw = (row.get("tcp.dstport") or "").strip().strip('"')
            udp_port_raw = (row.get("udp.dstport") or "").strip().strip('"')

            # tshark can occasionally emit comma-separated values for a
            # field (e.g. tunneled/encapsulated packets). Take the first
            # value if that happens.
            dst_port_raw = tcp_port_raw or udp_port_raw
            if dst_port_raw:
                dst_port_raw = dst_port_raw.split(",")[0]

            try:
                dst_port = int(dst_port_raw) if dst_port_raw else None
            except ValueError:
                dst_port = None

            try:
                frame_len = int(frame_len_raw) if frame_len_raw else 0
            except ValueError:
                frame_len = 0

            try:
                timestamp = float(time_raw) if time_raw else None
            except ValueError:
                timestamp = None

            if not src_ip:
                # Skip malformed / non-IP rows
                continue

            records.append({
                "time": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto,
                "dst_port": dst_port,
                "length": frame_len,
            })

    print(f"[+] Loaded {len(records)} packet records from {CSV_FILE}")
    return records


# ==================================================================
# STEP 4 - ICMP Flood Detection (MITRE T1498)
# ==================================================================

def detect_icmp_flood(records):
    """
    Detect source IPs that have sent >= ICMP_THRESHOLD ICMP packets within
    the capture window.

    Returns a list of dicts:
        {"src_ip": ..., "packet_count": ..., "dst_ip": ...}
    """
    icmp_counter = Counter()
    icmp_dst_ips = defaultdict(Counter)

    for rec in records:
        if rec["proto"] == PROTO_ICMP:
            icmp_counter[rec["src_ip"]] += 1
            if rec["dst_ip"]:
                icmp_dst_ips[rec["src_ip"]][rec["dst_ip"]] += 1

    print("\n[+] ICMP packet volume per source IP:")
    if icmp_counter:
        for ip, count in icmp_counter.items():
            print(f"    {ip}: {count} ICMP packets")
    else:
        print("    (no ICMP traffic observed)")

    results = []
    for ip, count in icmp_counter.items():
        if count >= ICMP_THRESHOLD:
            # Most frequently targeted destination IP for this source's ICMP traffic
            dst_ip = None
            if icmp_dst_ips[ip]:
                dst_ip = icmp_dst_ips[ip].most_common(1)[0][0]

            print(f"[!] ICMP Flood detected from {ip} ({count} packets >= threshold {ICMP_THRESHOLD})")
            results.append({
                "src_ip": ip,
                "packet_count": count,
                "dst_ip": dst_ip,
            })

    if not results:
        print("[+] No ICMP flood activity detected.")

    return results


# ==================================================================
# STEP 5 - Port Scan Detection (MITRE T1046)
# ==================================================================

def detect_port_scan(records):
    """
    Detect source IPs that have contacted >= PORT_SCAN_THRESHOLD unique
    destination ports (TCP and/or UDP combined) within the capture window.

    Returns a list of dicts:
        {"src_ip": ..., "unique_port_count": ..., "ports": [...], "dst_ip": ...}
    """
    ports_by_src = defaultdict(set)
    dst_ips_by_src = defaultdict(Counter)

    for rec in records:
        if rec["proto"] in (PROTO_TCP, PROTO_UDP) and rec["dst_port"] is not None:
            ports_by_src[rec["src_ip"]].add(rec["dst_port"])
            if rec["dst_ip"]:
                dst_ips_by_src[rec["src_ip"]][rec["dst_ip"]] += 1

    print("\n[+] Unique TCP/UDP destination ports contacted per source IP:")
    if ports_by_src:
        for ip, ports in ports_by_src.items():
            print(f"    {ip}: {len(ports)} unique ports")
    else:
        print("    (no TCP/UDP traffic observed)")

    results = []
    for ip, ports in ports_by_src.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            dst_ip = None
            if dst_ips_by_src[ip]:
                dst_ip = dst_ips_by_src[ip].most_common(1)[0][0]

            print(f"[!] Port Scan detected from {ip} ({len(ports)} unique ports >= threshold {PORT_SCAN_THRESHOLD})")
            results.append({
                "src_ip": ip,
                "unique_port_count": len(ports),
                "ports": sorted(ports),
                "dst_ip": dst_ip,
            })

    if not results:
        print("[+] No port scan activity detected.")

    return results


# ==================================================================
# STEP 6 - Severity Scoring
# ==================================================================

def calculate_risk_score(alert_type, value, threshold):
    """
    Calculate a 0-100 risk score for an alert based on how far the observed
    value (ICMP packet count / unique port count) exceeds the configured
    detection threshold.

    Design:
        - Reaching the threshold exactly yields a "High" baseline score.
        - The score scales upward toward "Critical" (100) as the observed
          value grows relative to the threshold.

    Mapping (approx):
        ICMP Flood : threshold      -> 60 (High)
                     2x threshold   -> 100 (Critical)
        Port Scan  : threshold      -> 65 (High)
                     ~2x threshold  -> 100 (Critical)
    """
    if threshold <= 0:
        return 50

    ratio = value / threshold

    if alert_type == "ICMP Flood":
        score = 60 + (ratio - 1) * 40
    elif alert_type == "Port Scan":
        score = 65 + (ratio - 1) * 35
    else:
        score = 50

    return int(round(min(100, max(0, score))))


def calculate_severity(risk_score):
    """Map a numeric risk score (0-100) to a severity label."""
    if risk_score >= 80:
        return "Critical"
    elif risk_score >= 60:
        return "High"
    elif risk_score >= 30:
        return "Medium"
    else:
        return "Low"


# ==================================================================
# STEP 7 - Alert Generation
# ==================================================================

def generate_alert(alert_type, indicator_value, evidence, value, threshold,
                    dst_ip=None, protocol=None):
    """
    Build a fully-populated alert dictionary matching the V2 alert schema:

        {
            "alert_id": "",
            "alert_type": "",
            "indicator_type": "",
            "indicator_value": "",
            "source_host": "",
            "destination_host": "",
            "destination_ip": "",
            "protocol": "",
            "severity": "",
            "risk_score": 0,
            "mitre_mapping": {"technique_id": "", "technique_name": ""},
            "evidence": {}
        }

    Args:
        alert_type: e.g. "ICMP Flood" or "Port Scan"
        indicator_value: the suspicious source IP
        evidence: dict of supporting evidence for this alert
        value: the metric used for scoring (packet count / unique port count)
        threshold: the threshold that was exceeded
        dst_ip: the most relevant destination IP observed for this indicator
        protocol: human-readable protocol label (e.g. "ICMP", "TCP/UDP")
    """
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    risk_score = calculate_risk_score(alert_type, value, threshold)
    severity = calculate_severity(risk_score)

    mitre_mapping = MITRE_MAPPINGS.get(alert_type, {
        "technique_id": "Unknown",
        "technique_name": "Unknown",
    })

    if dst_ip:
        destination_ip = dst_ip
        destination_host = resolve_host(dst_ip)
    else:
        destination_ip = DEFAULT_DESTINATION_IP
        destination_host = DEFAULT_DESTINATION_HOST

    alert = {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "indicator_type": "ip",
        "indicator_value": indicator_value,
        "source_host": resolve_host(indicator_value),
        "destination_host": destination_host,
        "destination_ip": destination_ip,
        "protocol": protocol or "Unknown",
        "severity": severity,
        "risk_score": risk_score,
        "mitre_mapping": mitre_mapping,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst_question": "Is this expected activity or suspicious scanning/noise?",
    }

    print(
        f"[+] Generated alert {alert_id}: {alert_type} from {indicator_value} "
        f"(severity={severity}, risk_score={risk_score})"
    )

    return alert


def save_alerts(alerts):
    """Write all generated alerts to ALERTS_FILE as a JSON array."""
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"[+] {len(alerts)} alert(s) written to {ALERTS_FILE}")


# ==================================================================
# STEP 8 - Incident Report Generation
# ==================================================================

# Standard remediation guidance per alert type, used in incident_report.txt
RECOMMENDATIONS = {
    "ICMP Flood": (
        "Verify whether this ICMP volume is expected (e.g. monitoring or "
        "health-check traffic). If unexpected, consider rate-limiting or "
        "blocking ICMP from this source at the firewall, and investigate "
        "the source host for compromise, misconfiguration, or malware "
        "performing a denial-of-service attempt."
    ),
    "Port Scan": (
        "Verify whether this host is an authorized vulnerability scanner or "
        "asset-discovery tool. If unauthorized, isolate the source host, "
        "review firewall/IDS logs for follow-on exploitation attempts "
        "against the scanned ports, and block the source IP if confirmed "
        "malicious."
    ),
}


def generate_incident_report(alerts):
    """
    Write a human-readable incident report (INCIDENT_REPORT_FILE) summarizing
    every generated alert, including:
        - Alert ID
        - Alert Type
        - Source IP
        - Severity
        - Risk Score
        - MITRE Technique
        - Detection Summary
        - Recommendations
    """
    with open(INCIDENT_REPORT_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("AI SOC ANALYST - INCIDENT REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated         : {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"Capture Interface : {INTERFACE}\n")
        f.write(f"Capture Duration  : {CAPTURE_DURATION}s\n")
        f.write(f"ICMP Threshold    : {ICMP_THRESHOLD} packets\n")
        f.write(f"Port Scan Threshold: {PORT_SCAN_THRESHOLD} unique ports\n")
        f.write(f"Total Alerts      : {len(alerts)}\n")
        f.write("=" * 60 + "\n\n")

        if not alerts:
            f.write("No suspicious activity was detected during this capture window.\n")
            print(f"[+] Incident report written to {INCIDENT_REPORT_FILE} (no alerts)")
            return

        for i, alert in enumerate(alerts, start=1):
            mitre = alert.get("mitre_mapping", {})
            evidence = alert.get("evidence", {})
            alert_type = alert.get("alert_type")

            f.write(f"--- Alert {i} ---\n")
            f.write(f"Alert ID         : {alert.get('alert_id')}\n")
            f.write(f"Alert Type       : {alert_type}\n")
            f.write(f"Source IP        : {alert.get('indicator_value')}\n")
            f.write(f"Source Host      : {alert.get('source_host')}\n")
            f.write(f"Destination IP   : {alert.get('destination_ip')}\n")
            f.write(f"Destination Host : {alert.get('destination_host')}\n")
            f.write(f"Protocol         : {alert.get('protocol')}\n")
            f.write(f"Severity         : {alert.get('severity')}\n")
            f.write(f"Risk Score       : {alert.get('risk_score')}\n")
            f.write(
                f"MITRE Technique  : {mitre.get('technique_id')} - "
                f"{mitre.get('technique_name')}\n"
            )

            # Detection summary, tailored per alert type
            if alert_type == "ICMP Flood":
                f.write(
                    f"Detection Summary: Source IP {alert.get('indicator_value')} sent "
                    f"{evidence.get('packet_count')} ICMP packets within a "
                    f"{evidence.get('time_window_seconds')}-second window "
                    f"(threshold: {evidence.get('threshold')}).\n"
                )
            elif alert_type == "Port Scan":
                f.write(
                    f"Detection Summary: Source IP {alert.get('indicator_value')} contacted "
                    f"{evidence.get('unique_port_count')} unique destination ports within a "
                    f"{evidence.get('time_window_seconds')}-second window "
                    f"(threshold: {evidence.get('threshold')}).\n"
                )
            else:
                f.write("Detection Summary: See evidence field for details.\n")

            recommendation = RECOMMENDATIONS.get(
                alert_type,
                "Review the evidence and escalate per standard SOC procedures."
            )
            f.write(f"Recommendations  : {recommendation}\n")
            f.write("\n")

    print(f"[+] Incident report written to {INCIDENT_REPORT_FILE}")


# ==================================================================
# STEP 9 - Airia Integration
# ==================================================================

def send_to_airia(alert):
    """
    Send a single alert to the Airia pipeline for further triage.

    Gracefully handles:
        - HTTP errors (4xx/5xx)
        - Timeouts
        - Connection failures
        - Invalid / non-JSON responses

    Returns True on a successful send (HTTP 2xx), False otherwise. A failed
    send does NOT raise - it logs and allows the workflow to continue with
    the remaining alerts.
    """
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": AIRIA_API_KEY,
    }

    payload = {
        "userInput": json.dumps(alert),  # Convert alert dict into a JSON string
        "asyncOutput": False,
    }

    alert_id = alert.get("alert_id", "UNKNOWN")
    print(f"[+] Sending alert {alert_id} to Airia Agent Execution API...")

    try:
        response = requests.post(
            AIRIA_API_URL,
            headers=headers,
            json=payload,
            timeout=AIRIA_TIMEOUT_SECONDS,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        print(f"[!] Airia request timed out after {AIRIA_TIMEOUT_SECONDS}s for alert {alert_id}.")
        return False

    except requests.exceptions.HTTPError as http_err:
        status = http_err.response.status_code if http_err.response is not None else "unknown"
        print(f"[!] Airia returned an HTTP error ({status}) for alert {alert_id}: {http_err}")
        return False

    except requests.exceptions.ConnectionError as conn_err:
        print(f"[!] Could not connect to Airia for alert {alert_id}: {conn_err}")
        return False

    except requests.exceptions.RequestException as req_err:
        print(f"[!] Unexpected request error sending alert {alert_id} to Airia: {req_err}")
        return False

    print(f"[+] Airia responded with status {response.status_code} for alert {alert_id}")

    try:
        data = response.json()
        print("[+] Airia Response JSON:")
        print(json.dumps(data, indent=2))
    except (ValueError, json.JSONDecodeError):
        print("[+] Airia response (raw text, not valid JSON):")
        print(response.text)

    return True


# ==================================================================
# MAIN WORKFLOW
# ==================================================================

def main():
    try:
        # ---- Steps 1-3: Capture, convert, load ----
        capture_traffic()
        convert_to_csv()
        records = load_csv_data()

        alerts = []

        # ---- Step 4: ICMP flood detection (T1498) ----
        icmp_hits = detect_icmp_flood(records)
        for hit in icmp_hits:
            evidence = {
                "packet_count": hit["packet_count"],
                "threshold": ICMP_THRESHOLD,
                "time_window_seconds": CAPTURE_DURATION,
                "data_source": os.path.basename(PCAP_FILE),
            }
            alert = generate_alert(
                alert_type="ICMP Flood",
                indicator_value=hit["src_ip"],
                evidence=evidence,
                value=hit["packet_count"],
                threshold=ICMP_THRESHOLD,
                dst_ip=hit["dst_ip"],
                protocol="ICMP",
            )
            alerts.append(alert)

        # ---- Step 5: Port scan detection (T1046) ----
        portscan_hits = detect_port_scan(records)
        for hit in portscan_hits:
            evidence = {
                "unique_port_count": hit["unique_port_count"],
                "threshold": PORT_SCAN_THRESHOLD,
                "ports_observed": hit["ports"][:50],  # capped for readability
                "time_window_seconds": CAPTURE_DURATION,
                "data_source": os.path.basename(PCAP_FILE),
            }
            alert = generate_alert(
                alert_type="Port Scan",
                indicator_value=hit["src_ip"],
                evidence=evidence,
                value=hit["unique_port_count"],
                threshold=PORT_SCAN_THRESHOLD,
                dst_ip=hit["dst_ip"],
                protocol="TCP/UDP",
            )
            alerts.append(alert)

        # ---- Steps 6-8: Persist alerts + incident report ----
        if alerts:
            save_alerts(alerts)
        else:
            print("\n[+] No alerts generated this run.")

        generate_incident_report(alerts)

        # ---- Step 9: Forward alerts to Airia ----
        if alerts:
            for alert in alerts:
                send_to_airia(alert)
        else:
            print("[+] Nothing to send to Airia.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()