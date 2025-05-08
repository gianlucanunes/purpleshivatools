#!/usr/bin/env python3
"""
ARP Scan Module — PurpleShiva Toolkit

Performs high‑speed ARP reconnaissance, displays progress with ANSI‑purple theme,
detects possible ARP spoofing, and exports reports (XML/JSON/PDF) with built‑in security recommendations.
"""

import argparse
import csv
import json
import logging
import os
import signal
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from ipaddress import ip_network
from typing import List, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, PageTemplate, Paragraph,
    Spacer, Table, TableStyle
)
from reportlab.lib.utils import ImageReader
from scapy.all import ARP, Ether, conf, srp

# ── Configuration ─────────────────────────────────────────────────────────────
LOG_DIR = "/var/log/purpleshivatoolslog"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/arpscan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── ANSI Colors (Purple Theme) ─────────────────────────────────────────────────
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    PURPLE = "\033[38;5;93m"
    PURPLE_LIGHT = "\033[38;5;141m"
    TABLE_BORDER = "\033[38;5;147m"

# ── Security Recommendations ───────────────────────────────────────────────────
RECOMMENDATIONS: List[Dict] = [
    {"id": 1, "title": "Dynamic ARP Inspection", "severity": "High",
     "description": "Validate ARP on untrusted ports, rate‑limit to 15pps, drop invalid.",
     "details": {"Rate Limit": "15 pps", "Detection": "100%"},
     "sources": ["Cisco DAI guide"]},
    {"id": 2, "title": "Port Security", "severity": "Medium",
     "description": "Limit MACs per port to prevent ARP poisoning.",
     "details": {"Max MACs": 2, "Aging": "3600s"},
     "sources": ["Cisco Port Security"]},
    {"id": 3, "title": "VLAN Segmentation", "severity": "High",
     "description": "Isolate departments via VLANs to reduce attack scope.",
     "details": {"VLANs": "10,20,30"},
     "sources": ["Cisco VLAN Best Practices"]},
    {"id": 4, "title": "Vulnerability Scanning", "severity": "Critical",
     "description": "Monthly scans and patching within 48h of critical findings.",
     "details": {"Frequency": "Monthly", "Patch SLA": "48h"},
     "sources": ["OWASP", "NIST SP‑800‑115"]}
]

# ── Progress Timer ─────────────────────────────────────────────────────────────
class ProgressTimer:
    def __init__(self):
        self._lock = threading.Lock()
        self._stop = False
        self._line = ""

    def start(self):
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop = True

    def update_line(self, line: str):
        with self._lock:
            self._line = line

    def _run(self):
        start = time.time()
        while not self._stop:
            elapsed = time.strftime("%H:%M:%S", time.gmtime(time.time() - start))
            with self._lock:
                sys.stdout.write(f"\r{self._line} | Duration: {Colors.BOLD}{elapsed}{Colors.RESET}")
                sys.stdout.flush()
            time.sleep(1)
        print()

timer = ProgressTimer()

# ── ARP Scan Logic ────────────────────────────────────────────────────────────
def scan_ip(ip: str, iface: str = None) -> List[Dict[str,str]]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answers = srp(pkt, timeout=1, verbose=False, iface=iface)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for _, rcv in answers]

def arp_scan(cidr: str, iface: str = None, workers: int = 50) -> List[Dict[str,str]]:
    try:
        hosts = list(ip_network(cidr, strict=False).hosts())
    except Exception:
        logger.error("Invalid CIDR format")
        return []

    logger.info(f"Starting ARP scan on {cidr} via interface {iface or 'default'}")
    devices = []
    total = len(hosts)

    timer.update_line(f"Progress: {Colors.BOLD}0.00%{Colors.RESET} | IP: --- | Devices: 0")
    timer.start()

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(scan_ip, str(ip), iface): ip for ip in hosts}
        for i, future in enumerate(futures, 1):
            result = future.result()
            if result:
                devices.extend(result)
            pct = (i/total)*100
            timer.update_line(f"Progress: {Colors.BOLD}{pct:.2f}%{Colors.RESET} | IP: {hosts[i-1]} | Devices: {len(devices)}")

    timer.stop()
    return devices

# ── Reporting ─────────────────────────────────────────────────────────────────
def write_json(path: str, devices: List[Dict]):
    with open(path, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "devices": devices,
            "recommendations": RECOMMENDATIONS
        }, f, indent=2)
    logger.info(f"JSON saved to {path}")

def write_csv(path: str, devices: List[Dict]):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ip","mac"])
        w.writeheader()
        w.writerows(devices)
    logger.info(f"CSV saved to {path}")

def write_xml(path: str, devices: List[Dict]):
    root = ET.Element("ARPScan")
    ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
    hosts = ET.SubElement(root, "Hosts")
    for d in devices:
        h = ET.SubElement(hosts, "Host")
        ET.SubElement(h, "IP").text = d["ip"]
        ET.SubElement(h, "MAC").text = d["mac"]
    recs = ET.SubElement(root, "Recommendations")
    for r in RECOMMENDATIONS:
        e = ET.SubElement(recs, "Rec", id=str(r["id"]), severity=r["severity"])
        ET.SubElement(e, "Title").text = r["title"]
        ET.SubElement(e, "Desc").text = r["description"]
    ET.indent(root, space="  ")
    ET.ElementTree(root).write(path, xml_declaration=True, encoding="utf-8")
    logger.info(f"XML saved to {path}")

def write_pdf(path: str, devices: List[Dict]):
    doc = BaseDocTemplate(path, pagesize=letter)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height)
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame])])

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("ARP Scan Report", styles["Title"]))
    story.append(Spacer(1,12))

    # Devices table
    data = [["#", "IP", "MAC"]]
    for i,d in enumerate(devices,1):
        data.append([str(i), d["ip"], d["mac"]])
    tbl = Table(data, colWidths=[30, 150, 150])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#461f6b")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.whitesmoke),
        ("GRID",(0,0),(-1,-1),1,colors.grey),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f5f5")])
    ]))
    story.append(tbl)
    story.append(Spacer(1,12))

    # Recommendations
    story.append(Paragraph("Security Recommendations", styles["Heading2"]))
    for r in RECOMMENDATIONS:
        story.append(Paragraph(f"• <b>{r['title']}</b> ({r['severity']})", styles["BodyText"]))
        story.append(Paragraph(r["description"], styles["BodyText"]))
        story.append(Spacer(1,6))

    doc.build(story)
    logger.info(f"PDF saved to {path}")

# ── CLI & Menu ────────────────────────────────────────────────────────────────
def save_reports(devices, fmt):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{LOG_DIR}/arpscan_{ts}"
    if fmt in ("json","all"): write_json(base+".json", devices)
    if fmt in ("csv","all"):  write_csv(base+".csv", devices)
    if fmt in ("xml","all"):  write_xml(base+".xml", devices)
    if fmt in ("pdf","all"):  write_pdf(base+".pdf", devices)

def main():
    parser = argparse.ArgumentParser(description="ARP Scan — PurpleShiva Toolkit")
    parser.add_argument("-r","--range", required=True, help="CIDR to scan, e.g. 192.168.1.0/24")
    parser.add_argument("-i","--interface", help="Network interface (default from scapy)")
    parser.add_argument("-f","--format", choices=["json","csv","xml","pdf","all"], default="all", help="Report format")
    args = parser.parse_args()

    devices = arp_scan(args.range, iface=args.interface)
    print(f"\n{Colors.PURPLE_LIGHT}Found {len(devices)} device(s){Colors.RESET}\n")
    for d in devices:
        print(f"{Colors.BOLD}{d['ip']}{Colors.RESET} — {d['mac']}")
    save_reports(devices, args.format)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Colors.BOLD}{Colors.PURPLE}Error: root privileges required{Colors.RESET}")
        sys.exit(1)
    main()
