# progress.py
import time
import threading
import shutil
import sys
import config as conf

class ProgressUpdater:
    def __init__(self, total_tasks=None):
        self.total_tasks = total_tasks
        self._start_time = None
        self._stop_event = threading.Event()
        self._tasks_completed = 0
        self._lock = threading.Lock()
        self._current_task = ""

    def start(self):
        self._start_time = time.time()
        thread = threading.Thread(target=self._update_loop)
        thread.daemon = True
        thread.start()

    def stop(self):
        self._stop_event.set()

    def increment(self, task_name=""):
        with self._lock:
            self._tasks_completed += 1
            self._current_task = task_name

    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

            with self._lock:
                completed = self._tasks_completed
                current = self._current_task

            if self.total_tasks:
                percent = (completed / self.total_tasks) * 100
                output = f"Progress: {conf.BOLD}{percent:.1f}%{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET} | Steps: {completed}/{self.total_tasks}"
                if current:
                    output += f" | {conf.CYAN}{current}{conf.RESET}"
            else:
                output = f"Completed: {conf.BOLD}{completed} tasks{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET}"
                if current:
                    output += f" | {conf.CYAN}{current}{conf.RESET}"

            # Limpar linha e escrever novo output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * min(terminal_width, 120))
            sys.stdout.write("\r" + output[:terminal_width-1])
            sys.stdout.flush()
            time.sleep(1)

        sys.stdout.write("\n")
        sys.stdout.flush()