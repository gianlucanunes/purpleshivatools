#!/usr/bin/env python3
"""
Progress updater for DNS Flood Attack
Displays real-time attack progress and statistics
"""

import time
import threading
import shutil
import sys
from modules import config as conf

class DnsFloodProgressUpdater:
    """Progress updater specifically designed for DNS flood attacks"""
    
    def __init__(self, duration=None, silent=False):
        """
        Initialize DNS flood progress updater
        
        Args:
            duration (int): Total attack duration in seconds
            silent (bool): Enable silent mode (no display updates)
        """
        self.duration = duration
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
        self._rate_history = []
        self._max_rate_history = 10  # Keep last 10 rate measurements
    
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
    
    def update_packets(self, packets_sent):
        """
        Update packet count
        
        Args:
            packets_sent (int): Total packets sent so far
        """
        with self._lock:
            self._packets_sent = packets_sent
            self._calculate_rate()
    
    def increment_packets(self, count=1):
        """
        Increment packet count
        
        Args:
            count (int): Number of packets to add
        """
        with self._lock:
            self._packets_sent += count
            self._calculate_rate()
    
    def update_failures(self, failures):
        """
        Update failure count
        
        Args:
            failures (int): Total failures so far
        """
        with self._lock:
            self._failures = failures
    
    def increment_failures(self, count=1):
        """
        Increment failure count
        
        Args:
            count (int): Number of failures to add
        """
        with self._lock:
            self._failures += count
    
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
            self._current_rate = packet_diff / time_diff
            
            # Store in history for smoothing
            self._rate_history.append(self._current_rate)
            if len(self._rate_history) > self._max_rate_history:
                self._rate_history.pop(0)
            
            # Update tracking variables
            self._last_packet_count = self._packets_sent
            self._last_rate_time = current_time
    
    def get_smoothed_rate(self):
        """Get smoothed packet rate from history"""
        if not self._rate_history:
            return 0.0
        
        # Use average of recent rates for smoother display
        return sum(self._rate_history) / len(self._rate_history)
    
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
            current_rate = self.get_smoothed_rate()
        
        # Calculate progress if duration is known
        progress_info = {
            'packets_sent': packets,
            'failures': failures,
            'elapsed': elapsed_formatted,
            'elapsed_seconds': elapsed,
            'current_rate': current_rate,
            'average_rate': packets / elapsed if elapsed > 0 else 0.0
        }
        
        if self.duration:
            remaining = max(0, self.duration - elapsed)
            remaining_formatted = time.strftime("%H:%M:%S", time.gmtime(remaining))
            percent = min(100, (elapsed / self.duration) * 100)
            
            progress_info.update({
                'duration': self.duration,
                'remaining': remaining_formatted,
                'remaining_seconds': remaining,
                'percent': percent
            })
        
        return progress_info
    
    def _format_rate(self, rate):
        """Format packet rate for display"""
        if rate >= 1000:
            return f"{rate/1000:.1f}K pps"
        else:
            return f"{rate:.1f} pps"
    
    def _format_number(self, num):
        """Format large numbers for display"""
        if num >= 1000000:
            return f"{num/1000000:.1f}M"
        elif num >= 1000:
            return f"{num/1000:.1f}K"
        else:
            return str(num)
    
    def _update_loop(self):
        """Main update loop for progress display"""
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                packets = self._packets_sent
                failures = self._failures
                current_rate = self.get_smoothed_rate()
                average_rate = packets / elapsed if elapsed > 0 else 0.0
            
            # Build progress display
            if self.duration:
                remaining = max(0, self.duration - elapsed)
                remaining_formatted = time.strftime("%H:%M:%S", time.gmtime(remaining))
                percent = min(100, (elapsed / self.duration) * 100)
                
                # Progress bar
                bar_width = 20
                filled = int(bar_width * percent / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                
                output = (
                    f"{conf.RED}DNS Flood{conf.RESET} "
                    f"[{conf.CYAN}{bar}{conf.RESET}] "
                    f"{conf.BOLD}{percent:.1f}%{conf.RESET} | "
                    f"Time: {conf.BOLD}{elapsed_formatted}{conf.RESET}/{remaining_formatted} | "
                    f"Packets: {conf.BOLD}{self._format_number(packets)}{conf.RESET} | "
                    f"Rate: {conf.BOLD}{self._format_rate(current_rate)}{conf.RESET} "
                    f"(avg: {self._format_rate(average_rate)})"
                )
            else:
                output = (
                    f"{conf.RED}DNS Flood{conf.RESET} | "
                    f"Time: {conf.BOLD}{elapsed_formatted}{conf.RESET} | "
                    f"Packets: {conf.BOLD}{self._format_number(packets)}{conf.RESET} | "
                    f"Rate: {conf.BOLD}{self._format_rate(current_rate)}{conf.RESET} "
                    f"(avg: {self._format_rate(average_rate)})"
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
        
        print(f"\n{conf.GREEN}═══ DNS Flood Attack Summary ═══{conf.RESET}")
        print(f"{conf.BOLD}Duration:{conf.RESET} {info['elapsed']}")
        print(f"{conf.BOLD}Packets Sent:{conf.RESET} {self._format_number(info['packets_sent'])}")
        print(f"{conf.BOLD}Average Rate:{conf.RESET} {self._format_rate(info['average_rate'])}")
        print(f"{conf.BOLD}Peak Rate:{conf.RESET} {self._format_rate(max(self._rate_history) if self._rate_history else 0)}")
        
        if info['failures'] > 0:
            success_rate = ((info['packets_sent'] - info['failures']) / info['packets_sent']) * 100 if info['packets_sent'] > 0 else 0
            print(f"{conf.BOLD}Failures:{conf.RESET} {info['failures']} ({conf.YELLOW}{100-success_rate:.1f}% failure rate{conf.RESET})")
        else:
            print(f"{conf.BOLD}Failures:{conf.RESET} {conf.GREEN}0 (100% success){conf.RESET}")


# Compatibility class for older code
class ProgressUpdater(DnsFloodProgressUpdater):
    """Alias for backward compatibility"""
    pass


if __name__ == "__main__":
    # Example usage
    import random
    
    print("Testing DNS Flood Progress Updater...")
    
    progress = DnsFloodProgressUpdater(duration=10)
    progress.start()
    
    # Simulate attack
    try:
        for i in range(100):
            time.sleep(0.1)
            progress.increment_packets(random.randint(10, 50))
            
            # Simulate occasional failures
            if random.random() < 0.05:
                progress.increment_failures(1)
                
    except KeyboardInterrupt:
        print("\nTest interrupted")
    
    progress.stop()
    progress.print_summary()