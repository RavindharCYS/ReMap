"""A simple Log Viewer window for the application."""

import tkinter as tk
from tkinter import scrolledtext
import ttkbootstrap as bttk
from pathlib import Path
from typing import Optional

from .styles import FONTS

class LogViewerWindow(tk.Toplevel):
    """A Toplevel window that displays the application's log file."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("ReMap Log Viewer")
        self.geometry("800x600")

        self.log_dir = Path.home() / ".remap" / "logs"
        self.log_file = self.get_latest_log_file()

        self._create_widgets()
        self.load_log_content()

    def get_latest_log_file(self) -> Optional[Path]:
        """Finds the most recently modified log file."""
        if not self.log_dir.exists():
            return None
        
        log_files = list(self.log_dir.glob("*.log"))
        if not log_files:
            return None
            
        return max(log_files, key=lambda f: f.stat().st_mtime)

    def _create_widgets(self):
        """Creates the widgets for the log viewer."""
        main_frame = bttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header_frame = bttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        log_path_str = str(self.log_file) if self.log_file else "No log file found."
        path_label = bttk.Label(header_frame, text=log_path_str, bootstyle="secondary")
        path_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        refresh_button = bttk.Button(header_frame, text="Refresh", command=self.load_log_content, bootstyle="outline-primary")
        refresh_button.pack(side=tk.RIGHT)

        style = bttk.Style()
        bg_color = style.colors.get('bg')
        fg_color = style.colors.get('fg')

        self.log_text = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            font=FONTS['code'],
            state=tk.DISABLED,
            bg=bg_color,
            fg=fg_color
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def load_log_content(self):
        """Loads or reloads content from the log file into the text widget."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete('1.0', tk.END)

        if not self.log_file or not self.log_file.exists():
            self.log_text.insert(tk.END, "Log file could not be found.")
        else:
            try:
                with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.log_text.insert(tk.END, content)
            except Exception as e:
                self.log_text.insert(tk.END, f"Error reading log file:\n{e}")
        
        self.log_text.config(state=tk.DISABLED)
        self.log_text.yview(tk.END)