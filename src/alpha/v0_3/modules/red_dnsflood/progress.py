#!/usr/bin/env python3
"""
Progress updater for DNS Flood Attack
Modified to track total packets and show rate information
"""

import time
import threading
import shutil
import sys
from modules import config as conf

class DnsFloodProgressUpdater:
    """Progress updater specifically designed for DNS flood attacks"""
    
    def __init__(self, silent=False):
        """
        Initialize DNS flood progress updater
        
        Args:
            silent (bool): Enable silent mode (no display updates)
        """
        self.silent = silent
        
        # Progress tracking
        self._start_time = None
        self._stop_event = threading.Event()
        self._packets_sent = 0
        self._failures = 0
        self._lock = threading.Lock()
        self._thread = None
        
        # Rate calculation
        self._last_packet_count = 0
        self._last_rate_time = None
        self._current_rate = 0.0
    
    def start(self):
        """Start the progress updater"""
        self._start_time = time.time()
        self._last_rate_time = self._start_time
        
        if not self.silent:
            self._thread = threading.Thread(target=self._update_loop)
            self._thread.daemon = True
            self._thread.start()
    
    def stop(self):
        """Stop the progress updater"""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
    
    def update_counters(self, packets, failures):
        """
        Update packet and failure counts (thread-safe)
        
        Args:
            packets (int): Total packets sent
            failures (int): Total failures
        """
        with self._lock:
            self._packets_sent = packets
            self._failures = failures
            self._calculate_rate()
    
    def _calculate_rate(self):
        """Calculate current packet rate (packets per second)"""
        current_time = time.time()
        
        if self._last_rate_time is None:
            self._last_rate_time = current_time
            return
        
        time_diff = current_time - self._last_rate_time
        
        # Update rate every second
        if time_diff >= 1.0:
            packet_diff = self._packets_sent - self._last_packet_count
            self._current_rate = packet_diff / time_diff if time_diff > 0 else 0
            
            # Update tracking variables
            self._last_packet_count = self._packets_sent
            self._last_rate_time = current_time
    
    def get_progress_info(self):
        """
        Get current progress information without printing
        
        Returns:
            dict: Progress information
        """
        elapsed = time.time() - self._start_time if self._start_time else 0
        elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        
        with self._lock:
            packets = self._packets_sent
            failures = self._failures
            current_rate = self._current_rate
        
        progress_info = {
            'packets_sent': packets,
            'failures': failures,
            'elapsed': elapsed_formatted,
            'elapsed_seconds': elapsed,
            'current_rate': current_rate,
            'average_rate': packets / elapsed if elapsed > 0 else 0.0
        }
        
        return progress_info
    
    def _format_rate(self, rate):
        """Format packet rate for display"""
        if rate >= 1000000:
            return f"{rate/1000000:.1f}M pps"
        elif rate >= 1000:
            return f"{rate/1000:.1f}K pps"
        else:
            return f"{rate:.1f} pps"
    
    def _update_loop(self):
        """Main update loop for progress display"""
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                packets = self._packets_sent
                failures = self._failures
                current_rate = self._current_rate
                average_rate = packets / elapsed if elapsed > 0 else 0.0
            
            # Build progress display
            output = (
                f"DNS Flood | "
                f"Time: {conf.BOLD}{elapsed_formatted}{conf.RESET} | "
                f"Rate: {conf.BOLD}{self._format_rate(current_rate)}{conf.RESET} | "
                f"Avg: {self._format_rate(average_rate)} | "
                f"Total: {packets}"
            )
            
            # Add failure count if there are failures
            if failures > 0:
                output += f" | {conf.YELLOW}Failures: {failures}{conf.RESET}"
            
            # Clear line and write new output
            terminal_width = shutil.get_terminal_size().columns
            if len(output) > terminal_width:
                # Truncate if too long for terminal
                output = output[:terminal_width-3] + "..."
            
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            
            time.sleep(0.5)  # Update twice per second for smoother display
        
        # Clear the progress line when stopping
        terminal_width = shutil.get_terminal_size().columns
        sys.stdout.write("\r" + " " * terminal_width + "\r")
        sys.stdout.flush()
    
    def print_summary(self):
        """Print final attack summary"""
        if self.silent:
            return
            
        info = self.get_progress_info()
        
        print(f"\n{conf.GREEN}DNS Flood Attack Complete{conf.RESET}")
        print(f"{conf.BOLD}Duration:{conf.RESET} {info['elapsed']}")
        print(f"{conf.BOLD}Packets Sent:{conf.RESET} {info['packets_sent']}")
        print(f"{conf.BOLD}Average Rate:{conf.RESET} {self._format_rate(info['average_rate'])}")
        print(f"{conf.BOLD}Peak Rate:{conf.RESET} {self._format_rate(info['current_rate'])}")
        
        if info['failures'] > 0:
            print(f"{conf.BOLD}Failures:{conf.RESET} {info['failures']}")


# Compatibility class
class ProgressUpdater(DnsFloodProgressUpdater):
    """Alias for backward compatibility"""
    pass