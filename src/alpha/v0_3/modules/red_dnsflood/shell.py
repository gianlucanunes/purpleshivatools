#!/usr/bin/env python3
import os
import sys
import readline
import subprocess
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.align import Align
from modules import config as conf
from .dnsflood import DnsFlood
from .report import write_json_log, write_xml_log, write_pdf_log

console = Console()

class DnsFloodCompleter:
    """Tab completion handler for the DnsFlood shell"""
    
    def __init__(self, params):
        self.params = params
        self.commands = [
            'help', 'manual', 'start', 'set', 'show', 'list', 
            'clear', 'status', 'quit', 'exit', 'back'
        ]
        # Add parameter indices for 'set' command
        self.commands.extend([str(i) for i in range(len(params))])
        # Add parameter keys
        self.commands.extend([p['key'] for p in params])
    
    def complete(self, text, state):
        """Handle tab completion"""
        try:
            line = readline.get_line_buffer()
            
            # Handle "set " completion with parameter indices and keys
            if line.lower().startswith('set '):
                set_term = line[4:].lower()
                matches = []
                # Add indices
                matches.extend([str(i) for i in range(len(self.params)) 
                              if str(i).startswith(set_term)])
                # Add parameter keys
                matches.extend([p['key'] for p in self.params 
                              if p['key'].lower().startswith(set_term)])
                if state < len(matches):
                    return matches[state]
                return None
            
            # Regular command completion
            matches = [cmd for cmd in self.commands if cmd.lower().startswith(text.lower())]
            if state < len(matches):
                return matches[state]
            return None
        except Exception:
            return None

def setup_readline(params):
    """Setup readline for better input handling"""
    try:
        # Setup history
        histfile = os.path.join(os.path.expanduser("~"), ".dnsflood_shell_history")
        try:
            readline.read_history_file(histfile)
        except FileNotFoundError:
            pass
        
        # Setup completion
        completer = DnsFloodCompleter(params)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        
        # Better editing
        readline.parse_and_bind("set editing-mode emacs")
        readline.parse_and_bind("set completion-ignore-case on")
        readline.parse_and_bind("set show-all-if-ambiguous on")
        
        return histfile
    except ImportError:
        console.print("[yellow]Warning: readline not available, tab completion disabled[/yellow]")
        return None

def save_history(histfile):
    """Save command history"""
    if histfile:
        try:
            readline.set_history_length(1000)
            readline.write_history_file(histfile)
        except Exception:
            pass

def safe_input(prompt: str) -> str:
    """Safe input function with cancellation support"""
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print()  # New line after ^C
        return ""
    except EOFError:
        console.print("\n[yellow]EOF received, exiting...[/yellow]")
        return "quit"

def clear_screen():
    """Clear the screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def parse_boolean(value):
    """Parse string to boolean"""
    if isinstance(value, bool):
        return value
    return value.lower() in ('true', 'yes', '1', 'y', 't')

def generate_params_table(params):
    """Generate the parameters configuration table with purple theme"""
    table = Table(
        title="🛰️  DNS FLOOD - Configuration Parameters",
        title_style="bold MAGENTA",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on MAGENTA",
        border_style="MAGENTA",
        padding=(0, 1)
    )
    
    table.add_column("ID", justify="center", style="bold cyan", width=4)
    table.add_column("Parameter", justify="left", style="bold white", min_width=20)
    table.add_column("Current Value", justify="left", min_width=25)
    table.add_column("Description", justify="left", style="dim white", min_width=30)
    table.add_column("Required", justify="center", width=10)
    
    for i, param in enumerate(params):
        param_id = f"[{i}]"
        param_name = param['name']
        
        # Format current value with colors
        if param['value']:
            if param['key'] in ['amplification', 'use_any_query', 'use_txt_query', 
                              'random_subdomains', 'spoof_source', 'silent', 'verbose']:
                bool_val = parse_boolean(param['value'])
                current_value = f"[bold green]{bool_val}[/bold green]" if bool_val else f"[bold red]{bool_val}[/bold red]"
            else:
                current_value = f"[bold green]{param['value']}[/bold green]"
        else:
            current_value = f"[yellow]not set[/yellow]"
        
        description = param['desc']
        if len(description) > 45:
            description = description[:42] + "..."
        
        required_status = "[bold red]YES[/bold red]" if param['required'] else "[dim]NO[/dim]"
        
        table.add_row(param_id, param_name, current_value, description, required_status)
    
    return table

def show_status(params):
    """Show current configuration status with purple theme"""
    required_set = sum(1 for p in params if p['required'] and p['value'])
    required_total = sum(1 for p in params if p['required'])
    optional_set = sum(1 for p in params if not p['required'] and p['value'])
    optional_total = sum(1 for p in params if not p['required'])
    
    status_text = Text()
    status_text.append("Configuration Status: ", style="bold white")
    
    if required_set == required_total:
        status_text.append("READY", style="bold green")
    else:
        status_text.append("INCOMPLETE", style="bold red")
    
    status_text.append(f" • Required: {required_set}/{required_total}", style="cyan")
    status_text.append(f" • Optional: {optional_set}/{optional_total}", style="dim cyan")
    
    # Count amplification settings
    amp_params = [p for p in params if p['key'] in ['amplification', 'use_any_query', 'use_txt_query', 'random_subdomains']]
    amp_enabled = sum(1 for p in amp_params if p['value'] and parse_boolean(p['value']))
    
    if amp_enabled > 0:
        status_text.append(f" • Amplification: {amp_enabled}/{len(amp_params)} enabled", style="MAGENTA")
    
    # Center the status panel
    console.print(Align.center(
        Panel(
            status_text,
            style="white",
            border_style="MAGENTA",
            box=box.ROUNDED,
            padding=(0, 1)
        )
    ))

def show_quick_help():
    """Show professional command reference using table format with purple theme"""
    HEADER_COLOR = "bold MAGENTA"
    BORDER_COLOR = "bright_white"
    ACCENT_COLOR = "MAGENTA"
    BODY_COLOR = "white"
    
    console.print(f"\n[{HEADER_COLOR}]🛰️  DNS Flood Shell Commands[/]")
    
    # Create command table
    table = Table(
        show_header=True,
        header_style=HEADER_COLOR,
        border_style=BORDER_COLOR,
        box=box.ROUNDED,
        padding=(0, 1)
    )
    
    table.add_column("Command", style=ACCENT_COLOR, min_width=12)
    table.add_column("Description", style=BODY_COLOR, min_width=40)
    table.add_column("Example", style="dim " + BODY_COLOR, min_width=25)
    
    # Configuration commands
    table.add_row("set", "Set parameter value by ID or key", "set 0 8.8.8.8,1.1.1.1")
    table.add_row("show/list", "Show current configuration parameters", "show")
    table.add_row("status", "Show configuration completeness status", "status")
    
    # Execution commands
    table.add_row("start", "Start DNS Flood with current config", "start")
    
    # Navigation commands
    table.add_row("help", "Show this command reference", "help")
    table.add_row("manual", "Show detailed documentation", "manual")
    table.add_row("clear", "Clear screen", "clear")
    table.add_row("quit/exit/back", "Return to main menu", "exit")
    
    console.print(table)
    
    # Professional tips
    console.print(f"\n[{ACCENT_COLOR}]💡 Tips:[/] Use TAB for autocompletion. Type 'manual' for complete documentation.")
    console.print(f"      Parameters can be set by ID (number) or key (name).")
    console.print(f"      Required parameters: [bold red]DNS Servers[/]")
    console.print(f"      Amplification settings can significantly increase attack impact\n")

def show_manual():
    from .manual import print_dnsflood_manual
    print_dnsflood_manual()

def validate_config(params):
    """Validate current configuration"""
    missing_required = []
    for param in params:
        if param['required'] and not param['value']:
            missing_required.append(param['name'])
    
    return len(missing_required) == 0, missing_required

def run_dnsflood(params):
    """Execute DNS Flood with current configuration"""
    is_valid, missing = validate_config(params)
    
    if not is_valid:
        console.print(f"[bold red]Cannot start: Missing required parameters: {', '.join(missing)}[/bold red]")
        return
    
    # Convert params to config dict
    config = {p['key']: p['value'] for p in params}
    
    try:
        duration = int(config['duration'])
        query_rate = int(config['query_rate'])
        threads = int(config['threads'])
        amplification = parse_boolean(config['amplification'])
        use_any_query = parse_boolean(config['use_any_query'])
        use_txt_query = parse_boolean(config['use_txt_query'])
        random_subdomains = parse_boolean(config['random_subdomains'])
        spoof_source = parse_boolean(config['spoof_source'])
        silent = parse_boolean(config['silent'])
        verbose = parse_boolean(config['verbose'])
        
        console.print(f"\n[bold MAGENTA]{'═'*60}[/bold MAGENTA]")
        console.print(f"[bold MAGENTA] STARTING DNS FLOOD ATTACK [/bold MAGENTA]")
        console.print(f"[bold MAGENTA]{'═'*60}[/bold MAGENTA]")
        
        console.print(f"\n[bold]Configuration:[/bold]")
        console.print(f"  DNS Servers: [green]{config['dns_servers']}[/green]")
        console.print(f"  Duration: [green]{duration}s[/green]")
        console.print(f"  Query Rate: [green]{query_rate} qps/thread[/green]")
        console.print(f"  Threads: [green]{threads}[/green]")
        console.print(f"  Amplification: [{'green' if amplification else 'red'}]{amplification}[/]")
        
        if amplification:
            console.print(f"  Use ANY Queries: [{'green' if use_any_query else 'red'}]{use_any_query}[/]")
            console.print(f"  Use TXT Queries: [{'green' if use_txt_query else 'red'}]{use_txt_query}[/]")
            console.print(f"  Random Subdomains: [{'green' if random_subdomains else 'red'}]{random_subdomains}[/]")
        
        console.print(f"  Spoof Source: [{'red' if spoof_source else 'green'}]{spoof_source}[/]")
        console.print(f"  Silent Mode: [{'green' if silent else 'red'}]{silent}[/]")
        console.print(f"  Verbose: [{'green' if verbose else 'red'}]{verbose}[/]")
        console.print(f"  Report Format: [green]{config['report_format']}[/green]")
        
        if spoof_source:
            time.sleep(3)
        
        # Execute attack
        attacker = DnsFlood(
            dns_servers=config['dns_servers'].split(','),
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
        fmt = config['report_format'].lower()
        if fmt == 'json':
            write_json_log(
                attack_type="DNS Flood",
                dns_servers=result['dns_servers'],
                duration=result['duration'],
                packets_sent=result['packets_sent'],
                failures=result['failures'],
                amplification=result.get('amplification', False),
                amplification_factor=result.get('estimated_amplification_factor', 1.0)
            )
        elif fmt == 'xml':
            write_xml_log(
                attack_type="DNS Flood",
                dns_servers=result['dns_servers'],
                duration=result['duration'],
                packets_sent=result['packets_sent'],
                failures=result['failures'],
                amplification=result.get('amplification', False),
                amplification_factor=result.get('estimated_amplification_factor', 1.0)
            )
        elif fmt == 'pdf':
            write_pdf_log(
                attack_type="DNS Flood",
                dns_servers=result['dns_servers'],
                duration=result['duration'],
                packets_sent=result['packets_sent'],
                failures=result['failures'],
                amplification=result.get('amplification', False),
                amplification_factor=result.get('estimated_amplification_factor', 1.0)
            )
        
        console.print(f"\n[bold green]✓ Attack completed successfully![/bold green]")
        console.print(f"[green]Results saved in {fmt.upper()} format[/green]")
        
        if result.get('amplification', False):
            amp_factor = result.get('estimated_amplification_factor', 1.0)
            console.print(f"[MAGENTA]Estimated Amplification Factor: {amp_factor:.1f}x[/MAGENTA]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Attack failed: {str(e)}[/bold red]")

def set_parameter(params, param_identifier, value):
    """Set parameter value by ID or key"""
    param_index = None
    
    # Try to find by index first
    if param_identifier.isdigit():
        index = int(param_identifier)
        if 0 <= index < len(params):
            param_index = index
    
    # Try to find by key
    if param_index is None:
        for i, param in enumerate(params):
            if param['key'] == param_identifier:
                param_index = i
                break
    
    if param_index is None:
        console.print(f"[bold red]Parameter '{param_identifier}' not found[/bold red]")
        return False
    
    param = params[param_index]
    
    # Validate the value based on parameter type
    if param['key'] in ['duration', 'query_rate', 'threads']:
        try:
            int_val = int(value)
            if param['key'] == 'threads' and int_val < 1:
                console.print(f"[bold red]Threads must be at least 1[/bold red]")
                return False
        except ValueError:
            console.print(f"[bold red]Invalid {param['key']} value. Use integers[/bold red]")
            return False
    elif param['key'] == 'report_format':
        if value.lower() not in ['json', 'xml', 'pdf']:
            console.print(f"[bold red]Invalid format. Use: json, xml, or pdf[/bold red]")
            return False
        value = value.lower()
    elif param['key'] == 'dns_servers':
        # Basic validation for DNS servers (comma-separated IPs)
        servers = [s.strip() for s in value.split(',')]
        if not servers or any(not s for s in servers):
            console.print(f"[bold red]Invalid DNS servers format. Use comma-separated IPs (e.g., 8.8.8.8,1.1.1.1)[/bold red]")
            return False
    elif param['key'] in ['amplification', 'use_any_query', 'use_txt_query', 
                         'random_subdomains', 'spoof_source', 'silent', 'verbose']:
        # Boolean parameters
        if value.lower() not in ['true', 'false', 'yes', 'no', '1', '0', 't', 'f', 'y', 'n']:
            console.print(f"[bold red]Invalid boolean value for {param['key']}. Use true/false[/bold red]")
            return False
        # Normalize to true/false strings
        value = 'true' if parse_boolean(value) else 'false'
    
    # Set the value
    params[param_index]['value'] = value
    console.print(f"[bold green]✓ Set {param['name']} = {value}[/bold green]")
    return True

def DnsFloodShell(params):
    """Main DNS Flood shell interface with purple theme"""
    # Setup readline
    histfile = setup_readline(params)
    
    def show_interface():
        """Show the main interface"""
        # Center the table like in base shell
        console.print(Align.center(generate_params_table(params)))
        console.print()
        show_status(params)
        console.print()
    
    # Initial display
    show_interface()
    
    try:
        while True:
            try:
                cmd = safe_input(f"{conf.MAGENTA}PurpleShell(dnsflood)${conf.RESET} ").strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                cmd_name = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                # Handle quit commands
                if cmd_name in ['quit', 'exit', 'back', 'q']:
                    console.print("[yellow]Returning to main menu...[/yellow]")
                    break
                
                # Handle clear command
                elif cmd_name == 'clear':
                    clear_screen()
                    show_interface()
                
                # Handle show/list commands
                elif cmd_name in ['show', 'list']:
                    show_interface()
                
                # Handle status command
                elif cmd_name == 'status':
                    show_status(params)
                
                # Handle help command
                elif cmd_name == 'help':
                    show_quick_help()
                
                # Handle manual command
                elif cmd_name == 'manual':
                    show_manual()
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle set command
                elif cmd_name == 'set':
                    if len(args) < 2:
                        console.print("[red]Usage: set <parameter_id|key> <value>[/red]")
                        console.print("[dim]Example: set 0 8.8.8.8,1.1.1.1 or set dns_servers 8.8.8.8,1.1.1.1[/dim]")
                    else:
                        param_id = args[0]
                        value = " ".join(args[1:])  # Support values with spaces
                        if set_parameter(params, param_id, value):
                            show_status(params)
                
                # Handle start command
                elif cmd_name == 'start':
                    run_dnsflood(params)
                    safe_input(f"{conf.YELLOW}Press Enter to continue...{conf.RESET}")
                    show_interface()
                
                # Handle unknown commands
                else:
                    console.print(f"[bold red]Unknown command: {cmd_name}[/bold red]")
                    console.print("[dim]Type 'help' for available commands or use TAB completion[/dim]")
                    
            except KeyboardInterrupt:
                print()  # New line after ^C
                continue
            except Exception as e:
                console.print(f"[bold red]Error: {str(e)}[/bold red]")
                continue
                
    finally:
        save_history(histfile)
        # Return to main menu
        try:
            bootstrap_path = conf.HomeDir
            if os.path.exists(bootstrap_path):
                console.print(f"\n[green][+] Redirecting to main menu...[/green]")
                subprocess.run(["python3", bootstrap_path])
        except Exception as e:
            console.print(f"[red]Error returning to main menu: {e}[/red]")