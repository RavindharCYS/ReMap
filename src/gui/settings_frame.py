"""Settings frame for configuring application preferences."""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable, Dict
import os
from pathlib import Path

from .styles import ReMapTheme, ToolTip
from ..models.settings import ScanSettings
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SettingsFrame(ttk.Frame):
    """Frame for application settings and configuration."""

    def __init__(self, parent, settings: ScanSettings, settings_changed_callback: Callable[[ScanSettings], None]):
        super().__init__(parent)
        self.settings = settings
        self.settings_changed_callback = settings_changed_callback
        self.original_settings = settings.to_dict()

        self._vars: Dict[str, tk.Variable] = {}
        
        self._create_widgets()
        self._load_settings()
        logger.debug("Settings frame initialized.")

    def _create_widgets(self):
        self.pack(fill='both', expand=True, padx=5, pady=5)
        
        content_frame = ttk.Frame(self)
        content_frame.pack(fill='both', expand=True)

        # Configure the grid columns of the content_frame to expand equally
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)

        # Left Column
        left_col = ttk.Frame(content_frame)
        left_col.grid(row=0, column=0, sticky='new', padx=(0, 10))

        scan_frame = ttk.LabelFrame(left_col, text="Scan Defaults", padding=10)
        scan_frame.pack(fill='x', pady=5)
        self._create_check(scan_frame, 'enable_service_detection', "Service Detection (-sV)")
        self._create_check(scan_frame, 'enable_script_scan', "Script Scan (-sC)")
        self._create_check(scan_frame, 'enable_os_detection', "OS Detection (-O, needs sudo)")
        self._create_check(scan_frame, 'enable_aggressive_scan', "Aggressive Scan (-A, needs sudo)")
        self._create_check(scan_frame, 'verbose_output', "Verbose Nmap Output (-v)")
        self._create_check(scan_frame, 'save_xml', "Save XML Scan Results")
        
        timing_frame = ttk.LabelFrame(left_col, text="Performance", padding=10)
        timing_frame.pack(fill='x', pady=5)
        self._create_entry(timing_frame, 'timeout', "Scan Timeout (s)")
        self._create_check(timing_frame, 'enable_rate_limit', "Enable Rate Limit")
        self._create_entry(timing_frame, 'rate_limit_value', "Rate Limit (pps)")

        # Right Column
        right_col = ttk.Frame(content_frame)
        right_col.grid(row=0, column=1, sticky='new')

        analysis_frame = ttk.LabelFrame(right_col, text="Analysis Defaults", padding=10)
        analysis_frame.pack(fill='x', pady=5)
        self._create_check(analysis_frame, 'enable_tls_analysis', "TLS Analysis")
        self._create_check(analysis_frame, 'enable_ssl_analysis', "SSL Certificate Analysis")
        self._create_check(analysis_frame, 'enable_smb_analysis', "SMB Analysis")
        self._create_check(analysis_frame, 'enable_web_detection', "Web Service Detection")

        gui_frame = ttk.LabelFrame(right_col, text="Interface Settings", padding=10)
        gui_frame.pack(fill='x', pady=5)
        self._create_check(gui_frame, 'show_tooltips', "Show Tooltips")
        self._create_check(gui_frame, 'confirm_actions', "Confirm Risky Actions")
        self._create_check(gui_frame, 'remember_window', "Remember Window Geometry")
        
        # Action Buttons below columns, in the main 'self' frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill='x', pady=(20, 0), side='bottom', anchor='sw')
        self.save_button = ttk.Button(button_frame, text="Save Settings", command=self.save_settings, style="Success.TButton", state='disabled')
        self.save_button.pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_changes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Reset Defaults", command=self.reset_to_defaults, style="Warning.TButton").pack(side='left', padx=5)

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, style="Muted.TLabel").pack(side='bottom', fill='x', pady=5)

    def _create_check(self, parent, key: str, label: str):
        self._vars[key] = tk.BooleanVar()
        cb = ttk.Checkbutton(parent, text=label, variable=self._vars[key], command=self._on_setting_change)
        cb.pack(anchor='w', padx=5, pady=2)
    
    def _create_entry(self, parent, key: str, label: str):
        frame = ttk.Frame(parent)
        frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(frame, text=f"{label}:").pack(side='left', anchor='w')
        self._vars[key] = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=self._vars[key], width=8, justify='right')
        entry.pack(side='left', padx=5)
        # Use trace_add instead of bind for variable changes
        self._vars[key].trace_add("write", self._on_setting_change)
    
    def _on_setting_change(self, *args):
        self.save_button.config(state='normal')
        self.status_var.set("* Unsaved changes")

    def _load_settings(self):
        for key, var in self._vars.items():
            if hasattr(self.settings, key):
                var.set(getattr(self.settings, key))
        self.original_settings = self.settings.to_dict()
        self.status_var.set("")
        self.save_button.config(state='disabled')

    def save_settings(self):
        try:
            for key, var in self._vars.items():
                if hasattr(self.settings, key):
                    current_val = var.get()
                    target_type = type(getattr(self.settings, key, ''))
                    # Ensure correct type conversion
                    if target_type is bool: setattr(self.settings, key, bool(current_val))
                    elif target_type is int: setattr(self.settings, key, int(float(current_val)))
                    elif target_type is float: setattr(self.settings, key, float(current_val))
                    else: setattr(self.settings, key, str(current_val))
            
            self.settings_changed_callback(self.settings)
            self.original_settings = self.settings.to_dict()
            self.status_var.set("Settings saved successfully!")
            self.save_button.config(state='disabled')
            self.after(3000, lambda: self.status_var.set(""))
        except (ValueError, TypeError) as e:
            messagebox.showerror("Invalid Value", f"A setting has an invalid value: {e}")
        except Exception as e:
            logger.error(f"Error saving settings: {e}", exc_info=True)
            messagebox.showerror("Error", f"Could not save settings: {e}")

    def reset_to_defaults(self):
        if messagebox.askyesno("Reset Settings", "Are you sure? This will revert to default settings."):
            self.settings = ScanSettings() # Create fresh defaults
            self._load_settings()
            self._on_setting_change()

    def cancel_changes(self):
        self.settings = ScanSettings(**self.original_settings) # Restore from dict
        self._load_settings()

    def has_unsaved_changes(self) -> bool:
        """Check if there are unsaved changes."""
        return self.status_var.get().startswith("*")
        
    def get_analysis_options(self) -> Dict[str, bool]:
        """Gets analysis options directly from the settings model, not necessarily the UI vars."""
        return {
            'tls_check': self.settings.enable_tls_analysis,
            'ssl_check': self.settings.enable_ssl_analysis,
            'smb_check': self.settings.enable_smb_analysis,
            'web_detection': self.settings.enable_web_detection,
        }