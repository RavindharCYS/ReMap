"""Scan options frame for configuring scan parameters."""

import tkinter as tk
import ttkbootstrap as bttk
from ttkbootstrap.tooltip import ToolTip
from typing import Dict, Any

from ..utils.logger import setup_logger
from ..models.settings import ScanSettings

logger = setup_logger(__name__)

class ScanOptionsFrame(bttk.LabelFrame):
    """Frame for scan configuration options."""
    
    def __init__(self, parent):
        super().__init__(parent, text="Scan Configuration", padding=10, bootstyle="info")
        self.scan_options: Dict[str, tk.Variable] = {}
        
        self._create_widgets()
        self.set_defaults()
        self._setup_tooltips()
        logger.debug("Scan options frame initialized")

    def _create_widgets(self):
        # Scan Type Frame
        self.scan_type_frame = bttk.Frame(self)
        self.scan_type_frame.pack(fill='x', pady=(0, 10))
        bttk.Label(self.scan_type_frame, text="Type:").pack(side='left')
        self.scan_options['scan_type'] = tk.StringVar()
        types = ["Fast", "Top 1000", "All Ports"]
        values = ["fast", "1000", "all"]
        for i, text in enumerate(types):
            bttk.Radiobutton(self.scan_type_frame, text=text, variable=self.scan_options['scan_type'], value=values[i]).pack(side='left', padx=5)

        # Detection Options Frame
        self.detection_frame = bttk.Frame(self)
        self.detection_frame.pack(fill='x', pady=5)
        
        self.scan_options['enable_service_detection'] = tk.BooleanVar()
        bttk.Checkbutton(self.detection_frame, text="Service/Version", variable=self.scan_options['enable_service_detection'], bootstyle="primary-round-toggle").pack(side='left', padx=5)

        self.scan_options['enable_script_scan'] = tk.BooleanVar()
        bttk.Checkbutton(self.detection_frame, text="Scripts", variable=self.scan_options['enable_script_scan'], bootstyle="primary-round-toggle").pack(side='left', padx=5)
        
        self.scan_options['enable_aggressive_scan'] = tk.BooleanVar()
        bttk.Checkbutton(self.detection_frame, text="Aggressive", variable=self.scan_options['enable_aggressive_scan'], bootstyle="warning-round-toggle").pack(side='left', padx=5)

        # NEW: Host Discovery Checkbox
        self.scan_options['disable_host_discovery'] = tk.BooleanVar()
        bttk.Checkbutton(self.detection_frame, text="Scan if Down (-Pn)", variable=self.scan_options['disable_host_discovery'], bootstyle="info-round-toggle").pack(side='left', padx=5)


    def _setup_tooltips(self):
        ToolTip(self.scan_type_frame.winfo_children()[1], "Fast scan (~100 common ports).", bootstyle="info")
        ToolTip(self.scan_type_frame.winfo_children()[2], "Scan the 1000 most common ports.", bootstyle="info")
        ToolTip(self.scan_type_frame.winfo_children()[3], "Scan all 65,535 TCP ports (very slow).", bootstyle="info")
        ToolTip(self.detection_frame.winfo_children()[0], "Determine service and version info on open ports (-sV).", bootstyle="info")
        ToolTip(self.detection_frame.winfo_children()[1], "Run default Nmap scripts (-sC).", bootstyle="info")
        ToolTip(self.detection_frame.winfo_children()[2], "Aggressive scan (-A). Includes OS detection, version detection, script scanning, and traceroute.", bootstyle="info")
        ToolTip(self.detection_frame.winfo_children()[3], "Disable host discovery (ping). Force scans all targets even if they appear down.", bootstyle="info")

    def set_defaults(self):
        defaults = ScanSettings()
        self.set_options_from_settings(defaults)

    def set_options_from_settings(self, settings: ScanSettings):
        self.scan_options['scan_type'].set(settings.default_scan_type)
        self.scan_options['enable_service_detection'].set(settings.enable_service_detection)
        self.scan_options['enable_script_scan'].set(settings.enable_script_scan)
        self.scan_options['enable_aggressive_scan'].set(settings.enable_aggressive_scan)
        # Set default for our new option
        self.scan_options['disable_host_discovery'] = tk.BooleanVar(value=True) # Default to ON for better results
    
    def get_options(self) -> Dict[str, Any]:
        return {key: var.get() for key, var in self.scan_options.items()}

    def set_state(self, state: str):
        for child in self.winfo_children():
            try:
                for sub_child in child.winfo_children():
                    sub_child.configure(state=state)
            except tk.TclError:
                pass