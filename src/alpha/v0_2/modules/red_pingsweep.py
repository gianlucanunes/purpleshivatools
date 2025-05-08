#!/usr/bin/env python3
# ICMP PING SWEEP


#IMPORTS -----------------------------------------------------------------------------------------------------------------
import logging
import os
import sys
import time
import threading
import json
import csv
import ipaddress
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Tuple, Any, Optional  # Adicionado tipagem
from scapy.all import IP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from reportlab.lib.pagesizes import letter
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing, Line



#COLORS -----------------------------------------------------------------------------------------------------------------
class Colors:
    #Classe para organizar cores ANSI em tons de roxo
    RESET = "\033[0m"
    BOLD = "\033[1m"
    PURPLE_DARK = "\033[38;5;54m"  # Roxo escuro
    PURPLE = "\033[38;5;93m"      # Roxo médio
    PURPLE_LIGHT = "\033[38;5;141m"  # Roxo claro
    LAVENDER = "\033[38;5;183m"    # Lavanda
    RED = "\033[31m"               # Vermelho para erros
    YELLOW = "\033[33m"            # Amarelo para avisos
    
    # Cores para bordas de tabelas
    TABLE_BORDER = "\033[38;5;147m"  # Lavanda mais claro para bordas
    TABLE_HEADER_BG = "\033[48;5;54m"  # Fundo roxo escuro para cabeçalhos
    TABLE_HEADER_FG = "\033[38;5;255m"  # Texto branco para cabeçalhos

# SETUP LOGGIN -----------------------------------------------------------------------------------------------------------------
def setup_logging():
    # Configura o sistema de logging com níveis apropriados
    log_dir = "/var/log/purpleshivatoolslog"
    os.makedirs(log_dir, exist_ok=True)
    
    # Configurar logging para arquivo e console
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"{log_dir}/pingsweep.log"),
            logging.StreamHandler()
        ]
    )
    # Suprimir avisos do scapy
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    return log_dir

# START LOGGIN -----------------------------------------------------------------------------------------------------------------
LOG_DIR = setup_logging()
logger = logging.getLogger(__name__)

# GLOBALS FOR PROGRESS -----------------------------------------------------------------------------------------------------------------
class ScanProgress:
    # Gerencia o progresso e temporizador da varredura
    def __init__(self):
        self.stop_timer = False
        self.timer_thread = None
        self.stdout_lock = threading.Lock()
        self.progress_line = ""
        self.scan_info = {}

    def update_timer(self, start_time: float) -> None:
        # Thread de atualização do timer de progresso
        while not self.stop_timer:
            elapsed = time.time() - start_time
            elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            with self.stdout_lock:
                sys.stdout.write(f"\r{self.progress_line} | Duration: {Colors.BOLD}{elapsed_str}{Colors.RESET}{' ' * 20}")
                sys.stdout.flush()
            time.sleep(1)
        with self.stdout_lock:
            sys.stdout.write("\r" + " " * 100 + "\r")
            sys.stdout.flush()

# Instância global do progresso
scan_progress = ScanProgress()

# Security recommendations -----------------------------------------------------------------------------------------------------------------
class SecurityRecommendations:
    
    RECOMMENDATIONS = [
        {
            "id": 1,
            "title": "Validate Host Reachability",
            "severity": "Medium",
            "description": "Use host‑based firewalls to restrict ICMP Echo‑Reply responses only to trusted sources.",
            "specificDetails": {
                "Firewall": "Enabled",
                "Policy": "Allow Echo‑Reply only from trusted subnets"
            },
            "sources": [
                "CIS Benchmarks – https://www.cisecurity.org/cis-benchmarks/"
            ]
        },
        {
            "id": 2,
            "title": "Network Segmentation",
            "severity": "High",
            "description": "Segment your network into VLANs or security zones to limit the scope of ICMP scanning.",
            "specificDetails": {
                "VLANs": "Configured",
                "VRF": "Applied on sensitive segments"
            },
            "sources": [
                "NIST SP 800‑125 – https://doi.org/10.6028/NIST.SP.800-125"
            ]
        },
        {
            "id": 3,
            "title": "ICMP Rate Limiting",
            "severity": "High",
            "description": "Implement rate‑limiting (CAR, policers) on ICMP traffic to mitigate ping‑flood attacks.",
            "specificDetails": {
                "Method": "Token bucket",
                "Max Rate": "500 Kbps per interface",
                "Burst Size": "10 packets"
            },
            "sources": [
                "Cisco ICMP Rate Limiting – https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_ip6-icmp-rate-lmt-xe.pdf"
            ]
        },
        {
            "id": 4,
            "title": "ICMP Message‑Type Filtering",
            "severity": "Medium",
            "description": "Allow only necessary ICMP types (Echo‑Reply, Destination‑Unreachable) and block others.",
            "specificDetails": {
                "Allowed": ["Type 0 (Echo Reply)", "Type 3 (Destination Unreachable)"],
                "Blocked": ["Type 5 (Redirect)", "Types 13/14 (Timestamp)"]
            },
            "sources": [
                "Cisco ICMP Filtering Guidelines – https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_ip6-icmp-rate-lmt-xe.pdf"
            ]
        },
        {
            "id": 5,
            "title": "Ingress/Egress Filtering (BCP 38)",
            "severity": "High",
            "description": "Apply edge filtering to block ICMP with spoofed source addresses (BCP 38).",
            "specificDetails": {
                "ACLs": "Deny spoofed source IPs",
                "BCP‑38": "Enabled"
            },
            "sources": [
                "BCP 38 – https://www.rfc-editor.org/info/bcp38"
            ]
        },
        {
            "id": 6,
            "title": "Detect ICMP Tunneling",
            "severity": "High",
            "description": "Use IDS/IPS signatures to detect anomalous ICMP payload patterns indicative of tunneling.",
            "specificDetails": {
                "IDS Signature": "ET ICMP TUNNEL",
                "Threshold": "> 10 ICMP packets/min per host"
            },
            "sources": [
                "ExtraHop on ICMP Tunneling – https://www.extrahop.com/company/blog/2017/detect-icmp-tunneling/"
            ]
        },
        {
            "id": 7,
            "title": "ICMP Monitoring & Logging",
            "severity": "Medium",
            "description": "Log all ICMP messages and configure alerts for abnormal spikes.",
            "specificDetails": {
                "Syslog": "Enabled for ICMP events",
                "Alert Threshold": "> 100 pings/min"
            },
            "sources": [
                "CIS Controls – https://www.cisecurity.org/controls/"
            ]
        },
        {
            "id": 8,
            "title": "Mitigate Smurf Attacks",
            "severity": "Critical",
            "description": "Disable responses to ICMP directed at broadcast addresses and ensure hosts do not forward such packets.",
            "specificDetails": {
                "Router(config‑if)": "no ip directed-broadcast",
                "Host Setting": "Ignore broadcast ping"
            },
            "sources": [
                "Smurf attack – https://en.wikipedia.org/wiki/Smurf_attack"
            ]
        },
        {
            "id": 9,
            "title": "Regular Penetration Testing",
            "severity": "Medium",
            "description": "Perform quarterly penetration tests focused on ICMP types and response behaviors to identify misconfigurations.",
            "specificDetails": {
                "Frequency": "Quarterly",
                "Scope": ["Echo", "Timestamp", "Redirect"]
            },
            "sources": [
                "NIST SP 800‑115 – https://www.nist.gov/privacy-framework/nist-sp-800-115"
            ]
        },
        {
            "id": 10,
            "title": "Document ICMP Policy",
            "severity": "Low",
            "description": "Maintain a formal ICMP policy, approved by risk management and reviewed annually.",
            "specificDetails": {
                "Review Cycle": "12 months",
                "Policy Owner": "Network Security Team"
            },
            "sources": [
                "CIS Policy Framework – https://www.cisecurity.org/controls/"
            ]
        }
    ]

    @classmethod
    def get_recommendations(cls, severity: str = None) -> List[Dict[str, Any]]:
        """
        Retorna todas as recomendações, ou filtra por severidade se fornecido.
        
        Args:
            severity: opcional, 'Low'|'Medium'|'High'|'Critical'
        """
        if severity:
            return [r for r in cls.RECOMMENDATIONS if r["severity"].lower() == severity.lower()]
        return cls.RECOMMENDATIONS
    
# VALIDATE -----------------------------------------------------------------------------------------------------------------
def ValidateIpRange(inputRange: str) -> Tuple[bool, str]:
    
    # Valida o formato do range de IP fornecido
    
    # Args: inputRange: String contendo IPs, CIDRs ou ranges
        
    # Returns: Tupla com status de validação (bool) e mensagem de erro (str)
    
    if not inputRange or not inputRange.strip():
        return False, "O range de IP não pode estar vazio."
    
    # Validando cada parte do input
    for part in inputRange.split(','):
        part = part.strip()
        if not part:
            return False, "Formato inválido. Remova vírgulas consecutivas."
            
        if '-' in part and '/' not in part:
            # Validação de range (ex: 192.168.1.1-192.168.1.10)
            try:
                start, end = part.split('-', 1)
                start_ip = ipaddress.IPv4Address(start.strip())
                end_ip = ipaddress.IPv4Address(end.strip())
                
                if end_ip < start_ip:
                    return False, f"IP final ({end_ip}) é menor que IP inicial ({start_ip}) no range: {part}"
            except ValueError:
                return False, f"O range '{part}' não está no formato correto (ex: 192.168.1.1-192.168.1.10)"
            except ipaddress.AddressValueError:
                return False, f"Endereço IP inválido no range: {part}"
        else:
            # Validação de IP único ou CIDR
            try:
                if '/' in part:
                    # Validação de CIDR
                    try:
                        network = ipaddress.ip_network(part, strict=False)
                        prefix = int(part.split('/')[1])
                        if prefix < 0 or prefix > 32:
                            return False, f"Prefixo CIDR inválido em '{part}'. Deve estar entre 0 e 32."
                    except ValueError:
                        return False, f"CIDR inválido: {part}"
                else:
                    # Validação de IP único
                    ipaddress.IPv4Address(part)
            except ipaddress.AddressValueError:
                return False, f"Endereço IP inválido: {part}"
                
    return True, ""

# Função de validação para formatos de relatório
def ValidateReportFormat(formatStr: str) -> Tuple[bool, str]:
    
    # Valida os formatos de relatório solicitados
    
    # Args: formatStr: String contendo formatos separados por vírgula
        
    # Returns: Tupla com status de validação (bool) e mensagem de erro (str)
    
    if not formatStr or not formatStr.strip():
        return True, ""  # Formato vazio é permitido (nenhum relatório será gerado)
    
    validFormats = ['xml', 'json', 'csv', 'pdf', 'all']
    formats = [fmt.strip().lower() for fmt in formatStr.split(',')]
    
    # Verificar se todos os formatos são válidos
    invalidFormats = [fmt for fmt in formats if fmt not in validFormats]
    if invalidFormats:
        return False, f"Formato(s) inválido(s): {', '.join(invalidFormats)}. Escolha entre: {', '.join(validFormats)}"
    
    return True, ""


# HELPTEXT -----------------------------------------------------------------------------------------------------------------

# Texto de ajuda para menu interativo - agora como constante de classe
class HelpText:
    #Textos de ajuda do programa
    
    MENU = f"""
{Colors.BOLD}{Colors.PURPLE}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.BOLD}{Colors.PURPLE}║                  {Colors.LAVENDER}ICMP PING SWEEP TOOL - HELP  {Colors.PURPLE}                   ║{Colors.RESET}
{Colors.BOLD}{Colors.PURPLE}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.BOLD}{Colors.PURPLE_LIGHT}BASIC USAGE:{Colors.RESET}
  This tool allows you to scan networks for active hosts using ICMP ping requests.
  Results can be exported in multiple formats for documentation and analysis.

{Colors.BOLD}{Colors.PURPLE_LIGHT}INTERACTIVE MENU OPTIONS:{Colors.RESET}
  {Colors.BOLD}1){Colors.RESET} Set IP Range       - Define which IPs to scan
  {Colors.BOLD}2){Colors.RESET} Set Report Format  - Choose output format(s)
  {Colors.BOLD}run{Colors.RESET} Start scan        - Command to start scan
  {Colors.BOLD}help){Colors.RESET} Help            - Show this help screen
  {Colors.BOLD}exit){Colors.RESET} Exit            - Close the application

  
  {Colors.BOLD}exit{Colors.RESET} - Exit the application

{Colors.BOLD}{Colors.PURPLE_LIGHT}COMMAND LINE USAGE:{Colors.RESET}
  python purple_pingsweep.py --range <ip-range> [options]

{Colors.BOLD}{Colors.PURPLE_LIGHT}OPTIONS:{Colors.RESET}
  {Colors.BOLD}--range, -r{Colors.RESET}    Target IP range/CIDR/list to scan
  {Colors.BOLD}--format, -f{Colors.RESET}   Report format(s): xml,json,csv,pdf,all
  {Colors.BOLD}--threads, -t{Colors.RESET}  Number of parallel scans (default: 100)
  {Colors.BOLD}--timeout{Colors.RESET}      ICMP timeout in seconds (default: 1.0)
  {Colors.BOLD}--help, -h{Colors.RESET}     Show this help message

{Colors.BOLD}{Colors.PURPLE_LIGHT}IP RANGE EXAMPLES:{Colors.RESET}
  • Single IP:        {Colors.PURPLE}192.168.1.1{Colors.RESET}
  • Multiple IPs:     {Colors.PURPLE}192.168.1.1,192.168.1.5,10.0.0.1{Colors.RESET}
  • IP Range:         {Colors.PURPLE}192.168.1.1-192.168.1.25{Colors.RESET}
  • CIDR Notation:    {Colors.PURPLE}192.168.1.0/24{Colors.RESET}
  • Mixed:            {Colors.PURPLE}10.0.0.1,192.168.1.0/24,172.16.1.1-172.16.1.10{Colors.RESET}

{Colors.BOLD}{Colors.PURPLE_LIGHT}INPUT VALIDATION:{Colors.RESET}
  • IP addresses must be in correct IPv4 format (e.g., 192.168.1.1)
  • CIDR notation requires valid prefix (0-32)
  • IP ranges must have start IP less than or equal to end IP
  • No spaces are allowed in IP addresses (commas only between entries)
  • Format options must be one of: xml, json, csv, pdf, all

{Colors.BOLD}{Colors.PURPLE_LIGHT}REPORT FORMATS:{Colors.RESET}
  • {Colors.PURPLE}csv{Colors.RESET}  - Simple IP list in CSV format
  • {Colors.PURPLE}json{Colors.RESET} - Detailed scan info in JSON format
  • {Colors.PURPLE}xml{Colors.RESET}  - Structured report in XML format
  • {Colors.PURPLE}pdf{Colors.RESET}  - Professional report in PDF format
  • {Colors.PURPLE}all{Colors.RESET}  - Generate all format types

{Colors.BOLD}{Colors.PURPLE_LIGHT}EXAMPLES:{Colors.RESET}
  # Scan a subnet and export as JSON
  {Colors.LAVENDER}python purple_pingsweep.py --range 192.168.1.0/24 --format json{Colors.RESET}

  # Scan multiple targets with custom thread count
  {Colors.LAVENDER}python purple_pingsweep.py --range "10.0.0.1-10.0.0.50,192.168.1.1" --format all --threads 50{Colors.RESET}
    """


# PARSE TARGETS -----------------------------------------------------------------------------------------------------------------

def parse_targets(input_str: str) -> List[ipaddress.IPv4Address]:
    # Parse comma-separated IPs, CIDRs or ranges (e.g. 192.168.0.1-192.168.0.20).
    
    # Args: input_str: String contendo IPs, CIDRs ou ranges
        
    # Returns: Lista de endereços IPv4 para varredura
    
    targets = []
    for part in input_str.split(','):
        part = part.strip()
        if '-' in part and '/' not in part:
            try:
                start, end = part.split('-', 1)
                start_ip = ipaddress.IPv4Address(start)
                end_ip = ipaddress.IPv4Address(end)
                
                if end_ip < start_ip:
                    logger.warning(f"IP final menor que inicial no range: {part}")
                    continue
                    
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    targets.append(ipaddress.IPv4Address(ip_int))
            except ipaddress.AddressValueError as e:
                logger.error(f"Formato de IP inválido no range: {part} - {str(e)}")
                print(f"{Colors.PURPLE_DARK}Formato de IP inválido no range: {part}{Colors.RESET}")
                continue
        else:
            try:
                if '/' in part:
                    net = ipaddress.ip_network(part, strict=False)
                    targets.extend(net.hosts())
                else:
                    targets.append(ipaddress.IPv4Address(part))
            except ValueError as e:
                logger.error(f"Formato de IP/CIDR inválido: {part} - {str(e)}")
                print(f"{Colors.PURPLE_DARK}Formato de IP/CIDR inválido: {part}{Colors.RESET}")
    
    return targets

# SCAN HOST -----------------------------------------------------------------------------------------------------------------

def scan_host(ip_address: ipaddress.IPv4Address) -> Tuple[str, bool]:
    
    #ICMP ping de um único host
    
    #Args: ip_address: Endereço IP a ser verificado
        
    #Returns: Tupla com endereço IP (str) e status (bool - ativo ou não)

    try:
        packet = IP(dst=str(ip_address)) / ICMP()
        response = sr1(packet, timeout=1, verbose=False)
        return str(ip_address), bool(response)
    except Exception as e:
        logger.error(f"Erro ao escanear {ip_address}: {str(e)}")
        return str(ip_address), False
    
# PING SWEEP -----------------------------------------------------------------------------------------------------------------

def ping_sweep(ip_range_str: str) -> List[Dict[str, str]]:
    
    # Executa varredura ICMP em todos os hosts do range especificado
    
    # Args: ip_range_str: String contendo range de IPs para varredura
        
    # Returns: Lista de dicionários com IPs ativos
    
    global scan_progress
    
    hosts = parse_targets(ip_range_str)
    total = len(hosts)
    
    if total == 0:
        msg = "Nenhum alvo válido para varredura."
        logger.warning(msg)
        print(f"{Colors.LAVENDER}{msg}{Colors.RESET}")
        return []

    active = []
    start = time.time()
    scan_progress.progress_line = f"Progress: {Colors.BOLD}0.00%{Colors.RESET} | Host: {Colors.BOLD}---{Colors.RESET} | Active: {Colors.BOLD}0{Colors.RESET}"
    scan_progress.stop_timer = False
    scan_progress.timer_thread = threading.Thread(target=scan_progress.update_timer, args=(start,))
    scan_progress.timer_thread.daemon = True
    scan_progress.timer_thread.start()

    with ThreadPoolExecutor(max_workers=100) as exe:
        futures = {exe.submit(scan_host, ip): ip for ip in hosts}
        for count, fut in enumerate(futures, start=1):
            try:
                addr, alive = fut.result()
                if alive:
                    active.append({'ip': addr})
                pct = (count / total) * 100
                scan_progress.progress_line = f"Progress: {Colors.BOLD}{pct:.2f}%{Colors.RESET} | Host: {Colors.BOLD}{addr}{Colors.RESET} | Active: {Colors.BOLD}{len(active)}{Colors.RESET}"
                with scan_progress.stdout_lock:
                    sys.stdout.write(f"\r{scan_progress.progress_line}{' ' * 20}")
                    sys.stdout.flush()
            except Exception as e:
                logger.error(f"Erro ao processar resultado do scan: {str(e)}")

    scan_progress.stop_timer = True
    scan_progress.timer_thread.join()
    duration = time.time() - start
    scan_progress.scan_info = {'ipRange': ip_range_str, 'duration': duration, 'total': total, 'active': len(active)}
    logger.info(f"Scan completo: {len(active)}/{total} hosts ativos em {duration:.2f}s")
    print()
    return active

# PRINT HOSTS -----------------------------------------------------------------------------------------------------------------
def print_hosts(hosts: List[Dict[str, str]]) -> None:
    
    # Imprime lista de hosts ativos com formatação em tabela 
    
    # Args: hosts: Lista de dicionários com dados dos hosts
    
    if not hosts:
        print(f"\n{Colors.LAVENDER}Nenhum host ativo encontrado.{Colors.RESET}\n")
        return
    
    # Dimensões e caracteres para tabela mais elegante
    col_widths = [6, 20]  # Largura para colunas # e IP
    table_width = sum(col_widths) + 3  # +3 para as bordas
    
    # Caracteres para bordas em estilo unicode mais elegante
    borders = {
        "top_left": "╔", "top_right": "╗", "bottom_left": "╚", "bottom_right": "╝",
        "horizontal": "═", "vertical": "║", "t_down": "╦", "t_up": "╩", 
        "t_right": "╠", "t_left": "╣", "cross": "╬"
    }
    
    # Borda superior da tabela
    top_border = f"{Colors.TABLE_BORDER}{borders['top_left']}"
    top_border += f"{borders['horizontal'] * col_widths[0]}{borders['t_down']}"
    top_border += f"{borders['horizontal'] * col_widths[1]}{borders['top_right']}{Colors.RESET}"
    
    # Linha divisória entre cabeçalho e corpo
    mid_border = f"{Colors.TABLE_BORDER}{borders['t_right']}"
    mid_border += f"{borders['horizontal'] * col_widths[0]}{borders['cross']}"
    mid_border += f"{borders['horizontal'] * col_widths[1]}{borders['t_left']}{Colors.RESET}"
    
    # Borda inferior da tabela
    bottom_border = f"{Colors.TABLE_BORDER}{borders['bottom_left']}"
    bottom_border += f"{borders['horizontal'] * col_widths[0]}{borders['t_up']}"
    bottom_border += f"{borders['horizontal'] * col_widths[1]}{borders['bottom_right']}{Colors.RESET}"
    
    # Header da tabela com larguras fixas e consistentes
    heading = f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
    heading += f"{Colors.TABLE_HEADER_BG}{Colors.TABLE_HEADER_FG} {'#':<{col_widths[0]-2}} {Colors.RESET}"
    heading += f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
    heading += f"{Colors.TABLE_HEADER_BG}{Colors.TABLE_HEADER_FG} {'Active IP Address':<{col_widths[1]-2}} {Colors.RESET}"
    heading += f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
    
    # Título centrado acima da tabela
    title = "ACTIVE HOSTS"
    padding = (table_width - len(title) - 2) // 2
    print(f"\n{Colors.BOLD}{Colors.PURPLE_LIGHT}{' ' * padding}{title}{Colors.RESET}\n")
    
    # Desenha a tabela
    print(top_border)
    print(heading)
    print(mid_border)
    
    # Linhas de dados consistentes
    for i, host in enumerate(hosts, 1):
        # Alternância de cores para linhas pares/ímpares
        bg_color = Colors.RESET if i % 2 == 0 else "\033[48;5;238m"  # Background cinza escuro para linhas ímpares
        
        row = f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
        # Garantindo que o número tenha largura fixa
        row += f"{bg_color} {i:^{col_widths[0]-2}} {Colors.RESET}"
        row += f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
        # O endereço IP precisa ser truncado se muito longo ou expandido se curto
        ip_str = host['ip']
        if len(ip_str) > col_widths[1]-2:
            ip_str = ip_str[:col_widths[1]-5] + "..."
        row += f"{bg_color} {Colors.PURPLE_LIGHT}{ip_str:<{col_widths[1]-2}}{Colors.RESET} "
        row += f"{Colors.TABLE_BORDER}{borders['vertical']}{Colors.RESET}"
        print(row)
    
    # Borda inferior
    print(bottom_border)
    
    # Estatísticas abaixo da tabela
    print(f"\n{Colors.PURPLE}Total hosts found: {Colors.BOLD}{len(hosts)}{Colors.RESET}\n")
    
    
# WRITE CSV -----------------------------------------------------------------------------------------------------------------

def write_csv(filepath: str, hosts: List[Dict[str, str]]) -> None:
    
    # Exporta resultado para CSV
    
    # Args: filepath: Caminho do arquivo para gravação , hosts: Lista de dicionários com dados dos hosts
    
    try:
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP Address'])
            for h in hosts:
                writer.writerow([h['ip']])
        logger.info(f"CSV log escrito em: {filepath}")
        print(f"{Colors.PURPLE}CSV log written to: {filepath}{Colors.RESET}")
    except Exception as e:
        logger.error(f"Erro ao escrever CSV: {str(e)}")
        print(f"{Colors.PURPLE_DARK}Erro ao escrever CSV: {str(e)}{Colors.RESET}")
        
# WRITE JSON -----------------------------------------------------------------------------------------------------------------

def write_json(filepath: str, hosts: List[Dict[str, str]]) -> None:
    
    # Exporta resultado para JSON
    
    # Args: filepath: Caminho do arquivo para gravação , hosts: Lista de dicionários com dados dos hosts
    
    try:
        data = {
            "scanInfo": scan_progress.scan_info,
            "timestamp": datetime.now().isoformat(),
            "recommendations": SecurityRecommendations.get_recommendations(),
            "hosts": hosts
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"JSON log escrito em: {filepath}")
        print(f"{Colors.PURPLE}JSON log written to: {filepath}{Colors.RESET}")
    except Exception as e:
        logger.error(f"Erro ao escrever JSON: {str(e)}")
        print(f"{Colors.PURPLE_DARK}Erro ao escrever JSON: {str(e)}{Colors.RESET}")

def write_xml(filepath: str, hosts: List[Dict[str, str]]) -> None:
    
    # Exporta resultado para XML
    
    # Args: filepath: Caminho do arquivo para gravação , hosts: Lista de dicionários com dados dos hosts
    
    try:
        root = ET.Element("ScanResults")
        
        # Adiciona informações do scan
        info = ET.SubElement(root, "ScanInfo")
        for key, value in scan_progress.scan_info.items():
            ET.SubElement(info, key).text = str(value)
        
        # Adiciona timestamp
        ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
        
        # Adiciona recomendações
        recs = ET.SubElement(root, "SecurityRecommendations")
        for rec in SecurityRecommendations.get_recommendations():
            rec_elem = ET.SubElement(recs, "Recommendation")
            for key, value in rec.items():
                if key == "specificDetails" or key == "sources":
                    details = ET.SubElement(rec_elem, key)
                    for k, v in rec[key].items() if key == "specificDetails" else enumerate(rec[key]):
                        if key == "specificDetails":
                            ET.SubElement(details, k).text = v
                        else:  # sources
                            ET.SubElement(details, "source").text = v
                else:
                    ET.SubElement(rec_elem, key).text = str(value)
        
        # Adiciona hosts
        hosts_elem = ET.SubElement(root, "Hosts")
        for host in hosts:
            host_elem = ET.SubElement(hosts_elem, "Host")
            ET.SubElement(host_elem, "IP").text = host['ip']
        
        # Escreve XML formatado
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")  # Disponível a partir do Python 3.9
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        
        logger.info(f"XML log escrito em: {filepath}")
        print(f"{Colors.PURPLE}XML log written to: {filepath}{Colors.RESET}")
    except Exception as e:
        logger.error(f"Erro ao escrever XML: {str(e)}")
        print(f"{Colors.PURPLE_DARK}Erro ao escrever XML: {str(e)}{Colors.RESET}")

def write_pdf(filepath: str, hosts: List[Dict[str, str]]) -> None:
    
    # Exporta resultado para PDF com tabelas visualmente aprimoradas
    
    # Args: filepath: Caminho do arquivo para gravação , hosts: Lista de dicionários com dados dos hosts
   
    try:
        # Configure estilos
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            textColor=colors.purple,
            spaceAfter=12,
            fontSize=16,
            alignment=1  # Centralizado
        )
        subtitle_style = ParagraphStyle(
            name='CustomSubtitle',
            parent=styles['Heading2'],
            textColor=colors.Color(0.4, 0.0, 0.6),  # Roxo mais escuro
            fontSize=14,
            spaceBefore=12,
            spaceAfter=6
        )
        normal_style = styles['Normal']
        
        # Crie documento
        doc = BaseDocTemplate(filepath, pagesize=letter)
        
        # Defina o frame
        frame = Frame(doc.leftMargin, doc.bottomMargin, 
                     doc.width, doc.height, id='normal')
        
        template = PageTemplate(id='test', frames=frame)
        doc.addPageTemplates([template])
        
        # Conteúdo do documento
        story = []
        
        # Cabeçalho decorativo
        story.append(Spacer(1, 10))
        drawing = Drawing(doc.width, 3)
        line = Line(0, 0, doc.width, 0)
        line.strokeColor = colors.Color(0.5, 0.0, 0.7)  # Roxo
        line.strokeWidth = 3
        drawing.add(line)
        story.append(drawing)
        story.append(Spacer(1, 10))
        
        # Título
        story.append(Paragraph("ICMP Ping Sweep Report", title_style))
        story.append(Spacer(1, 12))
        
        # Informações do scan
        story.append(Paragraph("Scan Information", subtitle_style))
        story.append(Spacer(1, 6))
        info_data = [["Parameter", "Value"]]
        
        for key, value in scan_progress.scan_info.items():
            formatted_key = key[0].upper() + key[1:]
            if key == 'duration':
                formatted_value = f"{value:.2f} seconds"
            else:
                formatted_value = str(value)
            info_data.append([formatted_key, formatted_value])
        
        # Cores personalizadas em tons de roxo
        purple_header = colors.Color(0.5, 0.0, 0.7)  # Roxo mais vibrante
        purple_light = colors.Color(0.9, 0.8, 1.0)   # Roxo claro para linhas alternadas
        purple_border = colors.Color(0.4, 0.0, 0.6)  # Roxo mais escuro para bordas
        
        info_table = Table(info_data, colWidths=[doc.width/3, 2*doc.width/3])
        info_table.setStyle(TableStyle([
            # Estilo do cabeçalho
            ('BACKGROUND', (0, 0), (1, 0), purple_header),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (1, 0), 8),
            ('TOPPADDING', (0, 0), (1, 0), 8),
            
            # Estilo das células
            ('BACKGROUND', (0, 1), (1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (0, -1), purple_header),  # Cor roxa para a primeira coluna
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 1), (0, -1), 'LEFT'),
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('FONTNAME', (1, 1), (1, -1), 'Helvetica'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            
            # Bordas e espaçamento
            ('GRID', (0, 0), (-1, -1), 1, purple_border),
            ('LINEABOVE', (0, 0), (1, 0), 2, purple_border),
            ('LINEBELOW', (0, 0), (1, 0), 2, purple_border),
            ('LINEBELOW', (0, -1), (1, -1), 2, purple_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, purple_light]),
            
            # Padding para todas as células
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 16))
        
        # Hosts ativos
        story.append(Paragraph("Active Hosts", subtitle_style))
        story.append(Spacer(1, 6))
        
        if hosts:
            host_data = [["#", "IP Address"]]
            for i, host in enumerate(hosts, 1):
                host_data.append([str(i), host['ip']])
            
            host_table = Table(host_data, colWidths=[doc.width/8, 7*doc.width/8])
            host_table.setStyle(TableStyle([
                # Estilo do cabeçalho
                ('BACKGROUND', (0, 0), (1, 0), purple_header),
                ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (1, 0), 8),
                ('TOPPADDING', (0, 0), (1, 0), 8),
                
                # Estilo das células
                ('BACKGROUND', (0, 1), (1, -1), colors.white),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # Números centrados
                ('ALIGN', (1, 1), (1, -1), 'LEFT'),    # IPs alinhados à esquerda
                ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                
                # Bordas e espaçamento
                ('GRID', (0, 0), (-1, -1), 1, purple_border),
                ('LINEABOVE', (0, 0), (1, 0), 2, purple_border),
                ('LINEBELOW', (0, 0), (1, 0), 2, purple_border),
                ('LINEBELOW', (0, -1), (1, -1), 2, purple_border),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, purple_light]),
                
                # Padding para todas as células
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            story.append(host_table)
        else:
            story.append(Paragraph("No active hosts found.", normal_style))
        
        story.append(Spacer(1, 16))
        
        # Recomendações de segurança
        story.append(Paragraph("Security Recommendations", subtitle_style))
        story.append(Spacer(1, 6))
        
        # Tabela para recomendações
        rec_data = [["ID", "Severity", "Title", "Description"]]
        for rec in SecurityRecommendations.get_recommendations():
            rec_data.append([
                str(rec['id']), 
                rec['severity'], 
                rec['title'], 
                rec['description']
            ])
        
        rec_table = Table(rec_data, colWidths=[doc.width/16, 2*doc.width/16, 5*doc.width/16, 8*doc.width/16])
        rec_table.setStyle(TableStyle([
            # Estilo do cabeçalho
            ('BACKGROUND', (0, 0), (-1, 0), purple_header),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Estilo das células
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),  # ID centrado
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),  # Severidade centrada
            ('ALIGN', (2, 1), (3, -1), 'LEFT'),    # Título e descrição à esquerda
            ('FONTNAME', (0, 1), (2, -1), 'Helvetica-Bold'),  # ID, Severidade e Título em negrito
            ('FONTNAME', (3, 1), (3, -1), 'Helvetica'),       # Descrição em fonte normal
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            
            # Cores de severidade
            ('TEXTCOLOR', (1, 1), (1, -1), colors.red if rec['severity'] == 'High' else colors.orange),
            
            # Bordas e espaçamento
            ('GRID', (0, 0), (-1, -1), 1, purple_border),
            ('LINEABOVE', (0, 0), (-1, 0), 2, purple_border),
            ('LINEBELOW', (0, 0), (-1, 0), 2, purple_border),
            ('LINEBELOW', (0, -1), (-1, -1), 2, purple_border),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, purple_light]),
            
            # Padding para todas as células
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 12))
        
        # Detalhes específicos e fontes em formato de tabela
        for rec in SecurityRecommendations.get_recommendations():
            # Título da recomendação
            rec_title_style = ParagraphStyle(
                name='RecTitle',
                parent=styles['Heading3'],
                textColor=colors.Color(0.4, 0.0, 0.6),
                fontSize=12,
                spaceBefore=10,
                spaceAfter=6
            )
            story.append(Paragraph(f"Details for Recommendation #{rec['id']}: {rec['title']}", rec_title_style))
            
            # Detalhes específicos
            if rec['specificDetails']:
                story.append(Spacer(1, 4))
                details_data = [["Parameter", "Value"]]
                for k, v in rec['specificDetails'].items():
                    details_data.append([k, v])
                
                details_table = Table(details_data, colWidths=[doc.width/3, 2*doc.width/3])
                details_table.setStyle(TableStyle([
                    # Estilo do cabeçalho
                    ('BACKGROUND', (0, 0), (1, 0), colors.Color(0.7, 0.6, 0.8)),  # Roxo mais claro
                    ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
                    ('ALIGN', (0, 0), (1, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
                    
                    # Estilo das células
                    ('BACKGROUND', (0, 1), (1, -1), colors.white),
                    ('ALIGN', (0, 1), (0, -1), 'LEFT'),
                    ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    
                    # Bordas e espaçamento
                    ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.6, 0.8)),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.9, 1.0)]),
                    
                    # Padding
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(details_table)
            
            # Fontes
            if rec['sources']:
                story.append(Spacer(1, 8))
                sources_data = [["Source"]]
                for source in rec['sources']:
                    sources_data.append([source])
                
                sources_table = Table(sources_data, colWidths=[doc.width])
                sources_table.setStyle(TableStyle([
                    # Estilo do cabeçalho
                    ('BACKGROUND', (0, 0), (0, 0), colors.Color(0.7, 0.6, 0.8)),  # Roxo mais claro
                    ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
                    ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                    ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                    
                    # Estilo das células
                    ('BACKGROUND', (0, 1), (0, -1), colors.white),
                    ('ALIGN', (0, 1), (0, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    
                    # Bordas e espaçamento
                    ('GRID', (0, 0), (-1, -1), 1, colors.Color(0.7, 0.6, 0.8)),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.9, 1.0)]),
                    
                    # Padding
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(sources_table)
            
            story.append(Spacer(1, 8))
        
        # Rodapé decorativo
        story.append(Spacer(1, 10))
        drawing = Drawing(doc.width, 3)
        line = Line(0, 0, doc.width, 0)
        line.strokeColor = colors.Color(0.5, 0.0, 0.7)  # Roxo
        line.strokeWidth = 2
        drawing.add(line)
        story.append(drawing)
        story.append(Spacer(1, 6))
        
        # Texto do rodapé
        footer_style = ParagraphStyle(
            name='Footer',
            parent=styles['Normal'],
            textColor=colors.Color(0.4, 0.0, 0.6),
            fontSize=8,
            alignment=1  # Centralizado
        )
        footer_text = f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Purple Ping Sweep Tool"
        story.append(Paragraph(footer_text, footer_style))
        
        # Construir documento
        doc.build(story)
        
        logger.info(f"PDF log escrito em: {filepath}")
        print(f"{Colors.PURPLE}PDF log written to: {filepath}{Colors.RESET}")
    except Exception as e:
        logger.error(f"Erro ao escrever PDF: {str(e)}")
        print(f"{Colors.PURPLE_DARK}Erro ao escrever PDF: {str(e)}{Colors.RESET}")
        
        
        
# WRITE LOGS -----------------------------------------------------------------------------------------------------------------

def write_logs(hosts: List[Dict[str, str]], fmt: str) -> None:
    
    # Exporta logs nos formatos solicitados
    
    # Args: hosts: Lista de dicionários com dados dos hosts , fmt: Formatos solicitados (csv,json,xml,pdf,all)
    
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    formats = [f.strip().lower() for f in fmt.split(',')]
    
    if 'all' in formats:
        formats = ['xml', 'json', 'pdf', 'csv']
    
    logger.info(f"Exportando logs nos formatos: {formats}")
    
    # Só escreve logs para formatos explicitamente solicitados
    for format_type in formats:
        if format_type == 'xml':
            write_xml(os.path.join(LOG_DIR, f"pingsweep_{ts}.xml"), hosts)
        elif format_type == 'json':
            write_json(os.path.join(LOG_DIR, f"pingsweep_{ts}.json"), hosts)
        elif format_type == 'pdf':
            write_pdf(os.path.join(LOG_DIR, f"pingsweep_{ts}.pdf"), hosts)
        elif format_type == 'csv':
            write_csv(os.path.join(LOG_DIR, f"pingsweep_{ts}.csv"), hosts)
        else:
            logger.warning(f"Formato desconhecido: {format_type}")
            print(f"{Colors.LAVENDER}Formato desconhecido: {format_type}{Colors.RESET}")

# MENU-----------------------------------------------------------------------------------------------------------------

class Menu:
    # Classe de menu interativo e CLI
    
    def __init__(self, args=None):
        
        # Inicializa o menu
        
        # Args: args: Argumentos da linha de comando (opcional)
        
        self.config = {
            "IP RANGE": {"value": None, "required": True},
            "REPORT FORMAT": {"value": None, "required": False}
        }
        self.running = True
        
        if args:
            if args.range:
                isValid, errorMsg = ValidateIpRange(args.range)
                if isValid:
                    self.config["IP RANGE"]["value"] = args.range
                else:
                    logger.error(f"IP range inválido: {errorMsg}")
                    print(f"{Colors.RED}Erro: {errorMsg}{Colors.RESET}")
                    sys.exit(1)
                    
            if args.format:
                isValid, errorMsg = ValidateReportFormat(args.format)
                if isValid:
                    self.config["REPORT FORMAT"]["value"] = args.format
                else:
                    logger.error(f"Formato de relatório inválido: {errorMsg}")
                    print(f"{Colors.RED}Erro: {errorMsg}{Colors.RESET}")
                    sys.exit(1)
                    
            if args.help:
                print(HelpText.MENU)
                sys.exit(0)
                
                
# DISPLAY ERROR -----------------------------------------------------------------------------------------------------------------
    def displayInputError(self, message: str) -> None:
        
        # Exibe mensagem de erro formatada
        
        # Args: message: Mensagem de erro para exibir
        
        print(f"\n{Colors.RED}⚠ Erro de validação: {message}{Colors.RESET}\n")
        time.sleep(1)  # Pequena pausa para o usuário ler a mensagem
        
# DISPLAY MENU -----------------------------------------------------------------------------------------------------------------
    def display(self) -> None:
        # Exibe o menu interativo
        
        # Banner do aplicativo com texto centralizado e bordas aprimoradas
        title = "ICMP PING SWEEP TOOL"
        banner_width = 67
        padding = (banner_width - len(title)) // 2
        
        # Caracteres de borda aprimorados
        top_border = f"{Colors.PURPLE}╔{'═' * (banner_width - 2)}╗{Colors.RESET}"
        mid_border = f"{Colors.PURPLE}╠{'═' * (banner_width - 2)}╣{Colors.RESET}"
        bot_border = f"{Colors.PURPLE}╚{'═' * (banner_width - 2)}╝{Colors.RESET}"
        
        # Caracteres para separadores de colunas
        h_sep = '═'  # Separador horizontal
        v_sep = '║'  # Borda vertical
        c_sep = '│'  # Separador de coluna
        
        # Título com borda superior
        print(f"\n{top_border}")
        print(f"{Colors.PURPLE}{v_sep}{Colors.RESET}{' ' * padding}{Colors.BOLD}{Colors.PURPLE_LIGHT}{title}{Colors.RESET}{' ' * (banner_width - padding - len(title) - 2)}{Colors.PURPLE}{v_sep}{Colors.RESET}")
        
        # Borda central após título
        print(f"{Colors.PURPLE}╠{'═' * 9}╦{'═' * 19}╦{'═' * 24}╦{'═' * 10}╣{Colors.RESET}")
        
        # Definição de colunas com tamanhos consistentes
        col_widths = [9, 19, 24, 10]
        
        # Cabeçalho da tabela
        headers = ["Number", "Parameter", "Value", "Required"]
        header_line = f"{Colors.PURPLE}{v_sep}{Colors.RESET}"
        
        for i, (h, w) in enumerate(zip(headers, col_widths)):
            header_text = f" {Colors.BOLD}{Colors.PURPLE_LIGHT}{h}{Colors.RESET}"
            header_line += f"{header_text}{' ' * (w - len(h) - 1)}"
            if i < len(headers) - 1:
                header_line += f"{Colors.PURPLE}{c_sep}{Colors.RESET}"
            else:
                header_line += f"{Colors.PURPLE}{v_sep}{Colors.RESET}"
                
        print(header_line)
        
        # Borda horizontal após cabeçalho
        print(f"{Colors.PURPLE}╠{'═' * 9}╬{'═' * 19}╬{'═' * 24}╬{'═' * 10}╣{Colors.RESET}")
        
        # Valores dos parâmetros
        for idx, (key, entry) in enumerate(self.config.items(), 1):
            val = entry['value'] or "NOT SET"
            req = "Yes" if entry['required'] else "No"
            
            # Limitar tamanho de valor se for muito grande
            if len(val) > col_widths[2] - 3:
                val = val[:col_widths[2] - 6] + "..."
            
            # Coloração condicional
            val_col = f"{Colors.PURPLE_LIGHT}{val}{Colors.RESET}" if entry['value'] else f"{Colors.LAVENDER}{val}{Colors.RESET}"
            req_col = f"{Colors.PURPLE_LIGHT}{req}{Colors.RESET}" if entry['required'] else f"{Colors.PURPLE}{req}{Colors.RESET}"
            
            # Construir linha com alinhamento adequado
            line = f"{Colors.PURPLE}{v_sep}{Colors.RESET}"
            
            # Coluna 1: Número
            line += f" {Colors.BOLD}{str(idx)}{Colors.RESET}{' ' * (col_widths[0] - len(str(idx)) - 1)}"
            line += f"{Colors.PURPLE}{c_sep}{Colors.RESET}"
            
            # Coluna 2: Parâmetro
            line += f" {key}{' ' * (col_widths[1] - len(key) - 1)}"
            line += f"{Colors.PURPLE}{c_sep}{Colors.RESET}"
            
            # Coluna 3: Valor
            # Calcula o espaço considerando as cores ANSI
            val_space = col_widths[2] - len(val) - 1
            line += f" {val_col}{' ' * val_space}"
            line += f"{Colors.PURPLE}{c_sep}{Colors.RESET}"
            
            # Coluna 4: Required
            req_space = col_widths[3] - len(req) - 1
            line += f" {req_col}{' ' * req_space}"
            line += f"{Colors.PURPLE}{v_sep}{Colors.RESET}"
            
            print(line)
        
        # Borda horizontal final
        print(bot_border)
        
        # Texto de ajuda da prompt
        print(f"\n{Colors.PURPLE_LIGHT}Selecione uma opção:{Colors.RESET}")
        print(f"  {Colors.BOLD}1-2{Colors.RESET} - Opção do menu")
        print(f"  {Colors.BOLD}run{Colors.RESET}  - Iniciar varredura")
        print(f"  {Colors.BOLD}exit{Colors.RESET} - Sair do programa")
        print(f"  {Colors.BOLD}help{Colors.RESET} - Exibir ajuda\n")
        
# START SCAN -----------------------------------------------------------------------------------------------------------------

    def start_scan(self) -> None:
        # Inicia a varredura de ping sweep
        ipr = self.config["IP RANGE"]["value"]
        if not ipr:
            logger.warning("IP RANGE é obrigatório")
            print(f"{Colors.RED}IP RANGE é obrigatório.{Colors.RESET}")
            return
        
        fmt = self.config["REPORT FORMAT"]["value"]
        hosts = ping_sweep(ipr)
        print_hosts(hosts)
        
        if fmt:
            write_logs(hosts, fmt)
            
# RUN -----------------------------------------------------------------------------------------------------------------
    def run(self) -> None:
        # Executa o menu interativo
        while self.running:
            try:
                self.display()
                choice = input(f"{Colors.PURPLE}ping sweep tool>{Colors.RESET} ").strip().lower()
                
                if choice == '1':
                    ipRange = input(f"{Colors.PURPLE_LIGHT}Digite IP/CIDR ou range:{Colors.RESET} ").strip()
                    isValid, errorMsg = ValidateIpRange(ipRange)
                    
                    if isValid:
                        self.config["IP RANGE"]["value"] = ipRange
                    else:
                        self.displayInputError(errorMsg)
                        
                elif choice == '2':
                    fmt = input(f"{Colors.PURPLE_LIGHT}Formato (xml/json/csv/pdf/all):{Colors.RESET} ").strip().lower()
                    
                    if not fmt:
                        self.config["REPORT FORMAT"]["value"] = None
                    else:
                        isValid, errorMsg = ValidateReportFormat(fmt)
                        
                        if isValid:
                            self.config["REPORT FORMAT"]["value"] = fmt
                        else:
                            self.displayInputError(errorMsg)
                            
                elif choice == 'run':
                    # Verificando se o IP range está configurado antes de iniciar
                    if not self.config["IP RANGE"]["value"]:
                        self.displayInputError("IP RANGE é obrigatório para iniciar a varredura.")
                    else:
                        self.start_scan()
                elif choice == 'help':
                    print(HelpText.MENU)
                    input(f"\n{Colors.BOLD}Pressione Enter para voltar...{Colors.RESET}")
                elif choice == 'exit':
                    self.running = False
                    logger.info("Saindo do programa")
                    print(f"\n{Colors.PURPLE_LIGHT}Encerrando aplicação. {Colors.RESET}")
                else:
                    self.displayInputError(f"Opção inválida: '{choice}'. Digite um número de 1-2 ou um comando válido.")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Operação cancelada pelo usuário.{Colors.RESET}")
                continue
            except Exception as e:
                logger.error(f"Erro no menu: {str(e)}")
                print(f"{Colors.RED}Erro: {str(e)}{Colors.RESET}")

# MAIN -----------------------------------------------------------------------------------------------------------------
def main():
    # Função principal
    parser = argparse.ArgumentParser(add_help=False, description="ICMP Ping Sweep Tool")
    parser.add_argument('--range', '-r', help='IP, CIDR or range to scan')
    parser.add_argument('--format', '-f', help='Comma-separated report formats: xml,json,csv,pdf,all')
    parser.add_argument('--help', '-h', action='store_true', help='Show help')
    parser.add_argument('--threads', '-t', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds (default: 1.0)')
    args = parser.parse_args()

    logger.info("Iniciando aplicação")
    
    # Se executado com argumentos de linha de comando
    if args.range:
        logger.info(f"Modo CLI: varredura no range {args.range}")
        
        # Validar o range IP
        isValid, errorMsg = ValidateIpRange(args.range)
        if not isValid:
            logger.error(f"IP range inválido: {errorMsg}")
            print(f"{Colors.RED}Erro: {errorMsg}{Colors.RESET}")
            sys.exit(1)
        
        # Validar o formato de relatório, se especificado
        if args.format:
            isValid, errorMsg = ValidateReportFormat(args.format)
            if not isValid:
                logger.error(f"Formato de relatório inválido: {errorMsg}")
                print(f"{Colors.RED}Erro: {errorMsg}{Colors.RESET}")
                sys.exit(1)
        
        hosts = ping_sweep(args.range)
        print_hosts(hosts)
        if args.format:
            write_logs(hosts, args.format)
        sys.exit(0)

    # Modo interativo
    try:
        print(f"\n{Colors.BOLD}{Colors.PURPLE_LIGHT}╔═══════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.PURPLE_LIGHT}║  PURPLE PING SWEEP TOOL v1.3 - Initializing...            ║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.PURPLE_LIGHT}╚═══════════════════════════════════════════════════════════╝{Colors.RESET}")
        logger.info("Iniciando modo interativo")
        Menu(args).run()
    except KeyboardInterrupt:
        logger.info("Interrompido pelo usuário")
        print(f"\n{Colors.YELLOW}Interrompido pelo usuário.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erro fatal: {str(e)}")
        print(f"{Colors.RED}Erro: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()