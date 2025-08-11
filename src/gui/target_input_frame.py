"""Target input frame for entering scan targets."""

import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as bttk
from ttkbootstrap.tooltip import ToolTip
from typing import List
from pathlib import Path

# DND Imports are now removed
# from tkinterdnd2 import DND_FILES

from .styles import FONTS
from ..core.target_parser import TargetParser
from ..models.target import Target
from ..utils.logger import setup_logger

logger = setup_logger(__name__)


class TargetInputFrame(bttk.LabelFrame):
    """Frame for target input with text entry and file loading."""
    
    def __init__(self, parent):
        super().__init__(parent, text="Targets", padding=10, bootstyle="info")
        self._create_widgets()
        self._setup_tooltips()
        logger.debug("Target input frame initialized")

    def _create_widgets(self):
        # We use a standard tk.Text widget
        self.target_text = tk.Text(self, height=8, width=50, font=FONTS['code'], wrap=tk.WORD, bd=0, relief=tk.FLAT)
        
        text_scrollbar = bttk.Scrollbar(self, orient='vertical', command=self.target_text.yview, bootstyle="round")
        
        style = bttk.Style()
        bg_color = style.colors.get('inputbg')
        fg_color = style.colors.get('inputfg')
        insert_bg = style.colors.get('primary')
        self.target_text.config(
            background=bg_color, 
            foreground=fg_color,
            insertbackground=insert_bg,
            relief='solid',
            borderwidth=1,
            highlightcolor=style.colors.get('primary'),
            highlightbackground=style.colors.get('border'),
            highlightthickness=1,
            yscrollcommand=text_scrollbar.set
        )
        
        self.target_text.grid(row=0, column=0, sticky='nsew')
        text_scrollbar.grid(row=0, column=1, sticky='ns')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # Updated info label, removed drag-and-drop text
        info_label = bttk.Label(self, text="Enter targets manually or load from file", bootstyle="secondary")
        info_label.grid(row=1, column=0, sticky='w', pady=(5,0))

        buttons = bttk.Frame(self)
        buttons.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(10,0))
        bttk.Button(buttons, text="Load File...", command=self._browse_file, bootstyle="outline-primary").pack(side='left')
        bttk.Button(buttons, text="Clear", command=self.clear, bootstyle="outline-secondary").pack(side='left', padx=5)
            
    def _browse_file(self):
        file_path = filedialog.askopenfilename(title="Select Target File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self._load_from_file(file_path)
            
    def _load_from_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.clear()
            self.target_text.insert('1.0', content)
            messagebox.showinfo("File Loaded", f"{Path(file_path).name} has been loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load target file '{file_path}': {e}")
            messagebox.showerror("File Error", f"Could not read the file:\n{e}")
    
    def get_targets(self) -> List[Target]:
        text_content = self.target_text.get(1.0, tk.END).strip()
        if not text_content: return []
        return TargetParser.parse_target_string(text_content)

    def clear(self):
        self.target_text.delete(1.0, tk.END)

    def set_state(self, state: str):
        text_state = 'normal' if state == 'normal' else 'disabled'
        self.target_text.config(state=text_state)
        for child in self.winfo_children():
            if isinstance(child, (tk.Frame, bttk.Frame)):
                for sub_child in child.winfo_children():
                    try:
                        sub_child.configure(state=state)
                    except tk.TclError:
                        pass
            else:
                 try:
                    child.configure(state=state)
                 except tk.TclError:
                    pass
    
    def _setup_tooltips(self):
        ToolTip(self.target_text, text="Enter scan targets manually, one per line (IP, CIDR, range).", bootstyle="info")