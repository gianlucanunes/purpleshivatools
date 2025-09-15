#!/usr/bin/env python3
import os
import sys
import signal
import importlib
import time
import traceback
import fnmatch
import queue
from contextlib import contextmanager
from purplest.manual import *
from purplest.shell import InteractiveMode

from modules import config as conf
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box
from rich.align import Align
from rich.live import Live
import keyboard

# Version info
VERSION = "0.3"
REPO_URL = "https://github.com/PurpleShivaTeam/purpleshivatools"

console = Console()

# Global flag for graceful shutdown
_shutdown_requested = False

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global _shutdown_requested
    _shutdown_requested = True
    console.print("\n[bold yellow]Interrupt signal received. Gracefully shutting down...[/bold yellow]")
    
    # Force exit on second Ctrl+C
    def force_exit(signum, frame):
        console.print("\n[bold red]Force exit requested. Terminating immediately.[/bold red]")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, force_exit)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    signal.signal(signal.SIGINT, signal_handler)
    
    # Handle SIGTERM on Unix-like systems
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

@contextmanager
def error_handler(operation_name="Operation", show_traceback=False):
    """Context manager for consistent error handling"""
    try:
        yield
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]⚠️  {operation_name} cancelled by user[/bold yellow]")
        raise
    except ImportError as e:
        console.print(f"[bold red]Import Error in {operation_name}: {str(e)}[/bold red]")
        if show_traceback:
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
    except FileNotFoundError as e:
        console.print(f"[bold red]File Not Found in {operation_name}: {str(e)}[/bold red]")
    except PermissionError as e:
        console.print(f"[bold red]Permission Error in {operation_name}: {str(e)}[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Unexpected error in {operation_name}: {str(e)}[/bold red]")
        if show_traceback:
            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")

def check_shutdown():
    """Check if shutdown was requested"""
    if _shutdown_requested:
        console.print("[yellow]Shutdown requested, stopping operation...[/yellow]")
        return True
    return False

def print_progress_rich(count, total, bar_length=40):
    if check_shutdown():
        return Text("Cancelling...", style="bold red")
    
    percent = count / total
    filled = int(percent * bar_length)
    bar = "█" * filled + "-" * (bar_length - filled)
    line = Text(f"Loading modules |{bar}| {count}/{total} ({percent:.0%})", style="bold purple")
    return Align.center(line)

def print_logo_centered(logo: str):
    try:
        cleaned = "\n".join(line.rstrip() for line in logo.strip("\n").splitlines())
        logo_text = Text(cleaned, style="bold purple")
        console.print(Align.center(logo_text))
    except Exception as e:
        console.print(f"[dim red]Error displaying logo: {str(e)}[/dim red]")

def PrintPhrase():
    try:
        console.print()
        phrase = Text(conf.GetRandomPhrase(), style="bold purple", justify="center")
        console.print(Align.center(phrase))
        console.print()
    except Exception as e:
        console.print(f"[dim red]Error displaying phrase: {str(e)}[/dim red]")

def print_banner():
    try:
        b = Text(justify="center")
        b.append("Version: ", style="bold cyan"); b.append(f"{VERSION}\n", style="bold green")
        b.append("Repo: ", style="bold cyan");    b.append(f"{REPO_URL}\n", style="bold blue")
        b.append("© 2025 - Developed by: ", style="bold cyan"); b.append("Gianluca Nunes", style="bold magenta")
        panel = Panel(
            b,
            title="[bold white] Purple Shiva Tools",
            subtitle="[cyan]Red & Blue Team Utilities",
            style="bold white",
            border_style="purple",
            box=box.ROUNDED,
            padding=(1,2)
        )
        console.print(panel)
    except Exception as e:
        console.print(f"[bold red]Error displaying banner: {str(e)}[/bold red]")

def get_tool_description(module_path):
    """Extract tool description with error handling"""
    try:
        if not os.path.exists(module_path):
            return "Security Tool (file not found)"
            
        with open(module_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') and not line.startswith('#!/'):
                    description = line[1:].strip()
                    if description:
                        return description
                elif line and not line.startswith('#'):
                    break
    except (IOError, UnicodeDecodeError, PermissionError) as e:
        return f"Security Tool (error reading: {str(e)[:50]})"
    except Exception:
        return "Security Tool (unknown error)"
    
    return "Security Tool"

def display_loading_results(total, failed):
    """Display loading results with appropriate styling"""
    if failed:
        # Red panel for failures
        error_details = []
        for name, error in failed:
            # Truncate long error messages
            truncated_error = error[:80] + "..." if len(error) > 80 else error
            error_details.append(f"• [bold]{name}[/bold]: [red]{truncated_error}[/red]")
        
        error_text = "\n".join(error_details)
        summary = f"[bold red]{len(failed)} of {total} modules failed to load[/bold red]\n\n{error_text}"
        
        panel = Panel(
            Align.left(summary),  # Left-align error details
            title="[bold red]Loading Errors",
            subtitle=f"[red]{total - len(failed)} modules loaded successfully",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        console.print(Align.center(panel))
    else:
        # Green panel for success
        success_text = f"[bold green]All {total} modules loaded successfully![/bold green]"
        
        panel = Panel(
            Align.center(success_text),  # Center-align success text
            title="[bold green]Loading Complete",
            subtitle="[green]All tools are ready to use.",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        console.print(Align.center(panel))

class ToolManager:
    def __init__(self):
        self.tools = []
        self.selected_tool = None
        self.selected_index = None
    
    def load_tools(self, tool_map, modules_dir):
        """Load tools with comprehensive error handling"""
        self.tools = []
        
        if not os.path.exists(modules_dir):
            console.print(f"[bold red]Modules directory not found: {modules_dir}[/bold red]")
            return
        
        with error_handler("Loading tools"):
            for i, (tool_name, module_name) in enumerate(tool_map.items()):
                if check_shutdown():
                    break
                
                tool_file_path = os.path.join(modules_dir, module_name, f"{tool_name}.py")
                description = get_tool_description(tool_file_path)
                
                category = "RED TEAM" if module_name.startswith("red_") else "BLUE TEAM"
                
                self.tools.append({
                    'index': i,
                    'name': tool_name,
                    'module': module_name,
                    'description': description,
                    'category': category,
                    'selected': False
                })
    
    def select_tool(self, index):
        """Select a tool with validation"""
        try:
            if not 0 <= index < len(self.tools):
                return False
            
            # Deselect all tools first
            for tool in self.tools:
                tool['selected'] = False
            
            # Select the chosen tool
            self.tools[index]['selected'] = True
            self.selected_tool = self.tools[index]['name']
            self.selected_index = index
            return True
        except (IndexError, TypeError):
            return False
    
    def get_selected_tool(self):
        """Get currently selected tool"""
        return self.selected_tool
    
    def find_tools(self, pattern):
        """Find tools matching a search pattern (case-insensitive)"""
        pattern = pattern.lower()
        return [tool for tool in self.tools if pattern in tool['name'].lower()]

def main(baseDir=None):
    """Main run function with comprehensive error handling"""
    # Setup signal handlers first
    setup_signal_handlers()
    
    try:
        # Initial display
        with error_handler("Displaying startup screen"):
            print_logo_centered(conf.GetRandomLogo())
            PrintPhrase()
            print_banner()
            console.print()
        
        if check_shutdown():
            return
        
        # Set up paths
        if baseDir is None:
            baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if baseDir not in sys.path:
            sys.path.insert(0, baseDir)
        
        # Load modules
        modulesDir = os.path.join(baseDir, "modules")
        
        if not os.path.exists(modulesDir):
            console.print(f"[bold red]Modules directory not found: {modulesDir}[/bold red]")
            return
        
        categories = {"RED TEAM TOOLS": "red_", "BLUE TEAM TOOLS": "blue_"}
        tools = []
        
        with error_handler("Scanning modules directory"):
            for pref in categories.values():
                try:
                    entries = os.listdir(modulesDir)
                except (OSError, PermissionError) as e:
                    console.print(f"[bold red]Cannot access modules directory: {str(e)}[/bold red]")
                    return
                
                for entry in sorted(entries):
                    if check_shutdown():
                        return
                    
                    if entry.startswith(pref):
                        td = os.path.join(modulesDir, entry)
                        tf = os.path.join(td, entry[len(pref):] + ".py")
                        if os.path.isdir(td) and os.path.isfile(tf):
                            tools.append((entry, tf))
        
        if not tools:
            console.print("[bold yellow]No tools found in modules directory[/bold yellow]")
            return
        
        total = len(tools)
        loaded, failed = 0, []
        
        # Load modules with progress display
        try:
            with Live(console=console, refresh_per_second=12) as live:
                for name, _ in tools:
                    if check_shutdown():
                        break
                    
                    try:
                        importlib.import_module(f"modules.{name}.{name.split('_',1)[1]}")
                    except Exception as e:
                        failed.append((name, str(e)))
                    finally:
                        loaded += 1
                        live.update(print_progress_rich(loaded, total))
                        time.sleep(0.1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Module loading interrupted[/yellow]")
        
        if check_shutdown():
            return
        
        # Clear the live display completely before continuing
        console.print()
        
        # Display loading results with improved panel
        display_loading_results(total, failed)
        console.print()  # Add some spacing
        
        # Create tool map
        tool_map = {e.split('_',1)[1]: e for e,_ in tools}
        
        if not tool_map:
            console.print("[bold red]No valid tools found[/bold red]")
            return
        
        # Create and initialize tool manager
        tool_manager = ToolManager()
        with error_handler("Loading tool manager"):
            tool_manager.load_tools(tool_map, modulesDir)
        
        # Start interactive mode
        InteractiveMode(tool_manager, tool_map, modulesDir)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Application interrupted by user[/bold yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {str(e)}[/bold red]")
        console.print(f"[dim red]Traceback: {traceback.format_exc()}[/dim red]")
    finally:
        console.print("[bold green]Purple Shiva Tools shutdown complete[/bold green]")

if __name__ == "__main__":
    main()