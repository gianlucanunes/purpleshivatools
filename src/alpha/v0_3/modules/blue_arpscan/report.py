import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from modules import config as conf
import subprocess
from .recommendations import recommendations


def generate_metadata(tool_name="Purple Shiva Tools - ArpScan"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(ip_range, total_ips, alive_hosts, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Failed to create directory '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arpscan_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    report_data = {
        "metadata": metadata,
        "scan_info": {
            "target_range": ip_range,
            "total_ips_scanned": total_ips,
            "alive_hosts": alive_hosts,
            "alive_hosts_count": len(alive_hosts),
            "duration_seconds": round(duration, 2)
        },
        "summary": {
            "hosts_found": len(alive_hosts),
        },
        "recommendations": recommendations  # Security recommendations
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"\n{conf.GREEN}[✓] JSON report saved to: {filepath}{conf.RESET}")
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Failed to save JSON report: {e}{conf.RESET}")
        raise

def write_xml_log(ip_range, total_ips, alive_hosts, duration, output_dir=None):
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Failed to create directory '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"arpscan_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("arpscan_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Scan Info
    scan_info = ET.SubElement(root, "scan_info")
    ET.SubElement(scan_info, "target_range").text = ip_range
    ET.SubElement(scan_info, "total_ips_scanned").text = str(total_ips)
    ET.SubElement(scan_info, "alive_hosts_count").text = str(len(alive_hosts))
    ET.SubElement(scan_info, "duration_seconds").text = str(round(duration, 2))
    
    # Alive hosts
    hosts_elem = ET.SubElement(scan_info, "alive_hosts")
    for host in alive_hosts:
        host_elem = ET.SubElement(hosts_elem, "host")
        ET.SubElement(host_elem, "ip").text = host['ip']
        ET.SubElement(host_elem, "mac").text = host['mac']
        ET.SubElement(host_elem, "hostname").text = host['hostname']
        ET.SubElement(host_elem, "vendor").text = host['vendor']
        ET.SubElement(host_elem, "status").text = host['status']

    # Summary
    summary_elem = ET.SubElement(root, "summary")
    ET.SubElement(summary_elem, "hosts_found").text = str(len(alive_hosts))
    efficiency = f"{(len(alive_hosts)/total_ips)*100:.2f}%" if total_ips > 0 else "0%"
    ET.SubElement(summary_elem, "scan_efficiency").text = efficiency

    # Recommendations
    recs_elem = ET.SubElement(root, "recommendations")
    for rec in recommendations:
        rec_elem = ET.SubElement(recs_elem, "recommendation")
        ET.SubElement(rec_elem, "id").text = rec['id']
        ET.SubElement(rec_elem, "title").text = rec['title']
        ET.SubElement(rec_elem, "description").text = rec['description']
        
        mitre_elem = ET.SubElement(rec_elem, "mitre_techniques")
        for technique in rec['mitre']:
            ET.SubElement(mitre_elem, "technique").text = technique
        
        cve_elem = ET.SubElement(rec_elem, "cves")
        for cve in rec['cve']:
            ET.SubElement(cve_elem, "cve").text = cve
            
        ET.SubElement(rec_elem, "recommendation_text").text = rec['recommendation']

    tree = ET.ElementTree(root)
    try:
        with open(filepath, "wb") as f:
            tree.write(f, encoding="utf-8", xml_declaration=True)
        print(f"\n{conf.GREEN}[✓] XML report saved to: {filepath}{conf.RESET}")
    except Exception as e:
        print(f"{conf.RED}[!] Failed to save XML report: {e}{conf.RESET}")
        raise
