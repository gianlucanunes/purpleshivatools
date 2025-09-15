import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from modules import config as conf
import subprocess
from fpdf import FPDF
from .recommendations import recommendations


def generate_metadata(tool_name="Purple Shiva Tools - DNS Flood"):
    return {
        "timestamp": datetime.now().isoformat(),
        "tool": tool_name,
        "version": "1.0.0"
    }

def write_json_log(attack_type, dns_servers, duration, packets_sent, failures, output_dir=None, **kwargs):
    """Write DNS Flood attack results to JSON format"""
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Failed to create directory '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dnsflood_{timestamp_file}.json"
    filepath = os.path.join(output_dir, filename)

    metadata = generate_metadata()

    # Calculate attack statistics
    average_rate = packets_sent / duration if duration > 0 else 0
    success_rate = ((packets_sent - len(failures)) / packets_sent * 100) if packets_sent > 0 else 0

    report_data = {
        "metadata": metadata,
        "attack_info": {
            "attack_type": attack_type,
            "target_dns_servers": dns_servers,
            "duration_seconds": duration,
            "total_packets_sent": packets_sent,
            "total_failures": len(failures),
            "success_rate_percent": round(success_rate, 2),
            "average_packets_per_second": round(average_rate, 2),
            "query_rate": kwargs.get('query_rate', 'N/A'),
            "threads_used": kwargs.get('threads', 'N/A')
        },
        "statistics": {
            "packets_sent": packets_sent,
            "packets_failed": len(failures),
            "packets_successful": packets_sent - len(failures),
            "failure_rate_percent": round((len(failures) / packets_sent * 100) if packets_sent > 0 else 0, 2),
            "attack_intensity": "High" if average_rate > 1000 else "Medium" if average_rate > 100 else "Low"
        },
        "failure_details": {
            "total_failures": len(failures),
            "failure_samples": failures[:10] if failures else [],  # First 10 failures as samples
            "failure_types": list(set([f.split(':')[0] for f in failures[:50]]))  # Unique failure types
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

def write_xml_log(attack_type, dns_servers, duration, packets_sent, failures, output_dir=None, **kwargs):
    """Write DNS Flood attack results to XML format"""
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Failed to create directory '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dnsflood_{timestamp_file}.xml"
    filepath = os.path.join(output_dir, filename)

    root = ET.Element("dnsflood_report")

    # Metadata
    metadata_dict = generate_metadata()
    metadata_elem = ET.SubElement(root, "metadata")
    for key, value in metadata_dict.items():
        ET.SubElement(metadata_elem, key).text = str(value)

    # Attack Info
    attack_info = ET.SubElement(root, "attack_info")
    ET.SubElement(attack_info, "attack_type").text = attack_type
    ET.SubElement(attack_info, "duration_seconds").text = str(duration)
    ET.SubElement(attack_info, "total_packets_sent").text = str(packets_sent)
    ET.SubElement(attack_info, "total_failures").text = str(len(failures))
    ET.SubElement(attack_info, "query_rate").text = str(kwargs.get('query_rate', 'N/A'))
    ET.SubElement(attack_info, "threads_used").text = str(kwargs.get('threads', 'N/A'))
    
    # DNS Servers
    servers_elem = ET.SubElement(attack_info, "target_dns_servers")
    for server in dns_servers:
        ET.SubElement(servers_elem, "server").text = server

    # Statistics
    average_rate = packets_sent / duration if duration > 0 else 0
    success_rate = ((packets_sent - len(failures)) / packets_sent * 100) if packets_sent > 0 else 0
    
    stats_elem = ET.SubElement(root, "statistics")
    ET.SubElement(stats_elem, "packets_sent").text = str(packets_sent)
    ET.SubElement(stats_elem, "packets_failed").text = str(len(failures))
    ET.SubElement(stats_elem, "packets_successful").text = str(packets_sent - len(failures))
    ET.SubElement(stats_elem, "success_rate_percent").text = str(round(success_rate, 2))
    ET.SubElement(stats_elem, "average_packets_per_second").text = str(round(average_rate, 2))
    ET.SubElement(stats_elem, "failure_rate_percent").text = str(round((len(failures) / packets_sent * 100) if packets_sent > 0 else 0, 2))

    # Failure Details
    failures_elem = ET.SubElement(root, "failure_details")
    ET.SubElement(failures_elem, "total_failures").text = str(len(failures))
    
    # Failure samples (first 10)
    samples_elem = ET.SubElement(failures_elem, "failure_samples")
    for failure in failures[:10]:
        ET.SubElement(samples_elem, "failure").text = failure

    # Failure types
    failure_types = list(set([f.split(':')[0] for f in failures[:50]]))
    types_elem = ET.SubElement(failures_elem, "failure_types")
    for failure_type in failure_types:
        ET.SubElement(types_elem, "type").text = failure_type

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
        return filepath
    except Exception as e:
        print(f"{conf.RED}[!] Failed to save XML report: {e}{conf.RESET}")
        raise

def write_pdf_log(attack_type, dns_servers, duration, packets_sent, failures, output_dir=None, **kwargs):
    """Write DNS Flood attack results to PDF format"""
    if output_dir is None:
        output_dir = conf.logDir

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"{conf.RED}[!] Failed to create directory '{output_dir}': {e}{conf.RESET}")
        raise

    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dnsflood_{timestamp_file}.pdf"
    filepath = os.path.join(output_dir, filename)

    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "DNS Flood Attack Report", ln=True, align="C")
        pdf.ln(10)
        
        # Metadata
        metadata = generate_metadata()
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Report Information", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 8, f"Generated: {metadata['timestamp']}", ln=True)
        pdf.cell(0, 8, f"Tool: {metadata['tool']}", ln=True)
        pdf.cell(0, 8, f"Version: {metadata['version']}", ln=True)
        pdf.ln(5)
        
        # Attack Information
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Attack Information", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 8, f"Attack Type: {attack_type}", ln=True)
        pdf.cell(0, 8, f"Target DNS Servers: {', '.join(dns_servers)}", ln=True)
        pdf.cell(0, 8, f"Duration: {duration} seconds", ln=True)
        pdf.cell(0, 8, f"Query Rate: {kwargs.get('query_rate', 'N/A')} qps/thread", ln=True)
        pdf.cell(0, 8, f"Threads Used: {kwargs.get('threads', 'N/A')}", ln=True)
        pdf.ln(5)
        
        # Statistics
        average_rate = packets_sent / duration if duration > 0 else 0
        success_rate = ((packets_sent - len(failures)) / packets_sent * 100) if packets_sent > 0 else 0
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Attack Statistics", ln=True)
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 8, f"Total Packets Sent: {packets_sent:,}", ln=True)
        pdf.cell(0, 8, f"Successful Packets: {packets_sent - len(failures):,}", ln=True)
        pdf.cell(0, 8, f"Failed Packets: {len(failures):,}", ln=True)
        pdf.cell(0, 8, f"Success Rate: {success_rate:.2f}%", ln=True)
        pdf.cell(0, 8, f"Average Rate: {average_rate:.2f} packets/second", ln=True)
        pdf.ln(5)
        
        # Failure Analysis (if any failures)
        if failures:
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Failure Analysis", ln=True)
            pdf.set_font("Arial", size=10)
            
            # Failure types
            failure_types = list(set([f.split(':')[0] for f in failures[:20]]))
            pdf.cell(0, 8, f"Failure Types: {', '.join(failure_types)}", ln=True)
            
            # Sample failures
            pdf.cell(0, 8, "Sample Failures:", ln=True)
            for i, failure in enumerate(failures[:5]):
                if len(failure) > 80:
                    failure = failure[:77] + "..."
                pdf.cell(0, 6, f"  {i+1}. {failure}", ln=True)
            pdf.ln(5)
        
        # Recommendations
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Security Recommendations", ln=True)
        pdf.set_font("Arial", size=10)
        
        for i, rec in enumerate(recommendations[:3]):  # First 3 recommendations
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 8, f"{i+1}. {rec['title']}", ln=True)
            pdf.set_font("Arial", size=9)
            
            # Description (wrap text)
            desc = rec['description']
            if len(desc) > 90:
                desc = desc[:87] + "..."
            pdf.multi_cell(0, 6, f"   {desc}")
            
            # Recommendation
            recommendation = rec['recommendation']
            if len(recommendation) > 90:
                recommendation = recommendation[:87] + "..."
            pdf.multi_cell(0, 6, f"   Recommendation: {recommendation}")
            pdf.ln(2)
        
        pdf.output(filepath)
        print(f"\n{conf.GREEN}[✓] PDF report saved to: {filepath}{conf.RESET}")
        return filepath
        
    except Exception as e:
        print(f"{conf.RED}[!] Failed to save PDF report: {e}{conf.RESET}")
        raise