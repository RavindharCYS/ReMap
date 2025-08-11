"""Settings frame for configuring application preferences."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, Callable, Optional
import os
from pathlib import Path

from .styles import ReMapTheme, ToolTip, icon_manager, create_scrollable_frame
from ..models.settings import ScanSettings
from ..utils.logger import setup_logger
from ..utils.file_handler import FileHandler

logger = setup_logger(__name__)

class SettingsFrame(ttk.Frame):
    """Frame for application settings and configuration."""
    
    def __init__(self, parent, settings: ScanSettings, settings_changed_callback: Callable[[ScanSettings], None]):
        super().__init__(parent)
        
        self.settings = settings
        self.settings_changed_callback = settings_changed_callback
        self.original_settings = None  # Store for reset functionality
        
        # Create scrollable container
        self.scrollable_main_frame = create_scrollable_frame(self)
        self.scrollable_main_frame.pack(fill='both', expand=True)
        self.main_frame = self.scrollable_main_frame.scrollable_frame
        
        self._create_widgets()
        self._setup_layout()
        self._setup_tooltips()
        self._load_current_settings()
        self._setup_bindings()
        
        logger.debug("Settings frame initialized")
    
    def _create_widgets(self):
        """Create settings widgets."""
        
        # General Settings Section
        self.general_frame = ttk.LabelFrame(self.main_frame, text="General Settings")
        
        # Nmap Path Configuration
        nmap_frame = ttk.Frame(self.general_frame)
        ttk.Label(nmap_frame, text="Nmap Executable:").pack(side='left')
        
        self.nmap_path_var = tk.StringVar()
        self.nmap_path_entry = ttk.Entry(nmap_frame, textvariable=self.nmap_path_var, 
                                        style='Custom.TEntry', width=40)
        self.nmap_path_entry.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        self.nmap_browse_btn = ttk.Button(nmap_frame, text="Browse...", 
                                         command=self._browse_nmap_path)
        self.nmap_browse_btn.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        self.nmap_test_btn = ttk.Button(nmap_frame, text="Test", 
                                       command=self._test_nmap_path)
        self.nmap_test_btn.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        # Default Scan Settings Section
        self.scan_defaults_frame = ttk.LabelFrame(self.main_frame, text="Default Scan Settings")
        
        # Service Detection
        self.service_detection_var = tk.BooleanVar()
        self.service_detection_cb = ttk.Checkbutton(
            self.scan_defaults_frame, text="Enable Service Detection (-sV)",
            variable=self.service_detection_var, command=self._on_setting_change
        )
        
        # Version Detection
        self.version_detection_var = tk.BooleanVar()
        self.version_detection_cb = ttk.Checkbutton(
            self.scan_defaults_frame, text="Enable Version Detection (-sC)",
            variable=self.version_detection_var, command=self._on_setting_change
        )
        
        # OS Detection
        self.os_detection_var = tk.BooleanVar()
        self.os_detection_cb = ttk.Checkbutton(
            self.scan_defaults_frame, text="Enable OS Detection (-O)",
            variable=self.os_detection_var, command=self._on_setting_change
        )
        
        # Script Scan
        self.script_scan_var = tk.BooleanVar()
        self.script_scan_cb = ttk.Checkbutton(
            self.scan_defaults_frame, text="Enable Script Scanning (-A)",
            variable=self.script_scan_var, command=self._on_setting_change
        )
        
        # Rate Limiting Section
        self.rate_limit_frame = ttk.LabelFrame(self.main_frame, text="Rate Limiting")
        
        # Enable Rate Limiting
        self.enable_rate_limit_var = tk.BooleanVar()
        self.enable_rate_limit_cb = ttk.Checkbutton(
            self.rate_limit_frame, text="Enable Rate Limiting",
            variable=self.enable_rate_limit_var, command=self._on_rate_limit_toggle
        )
        
        # Rate Limit Value
        rate_limit_value_frame = ttk.Frame(self.rate_limit_frame)
        ttk.Label(rate_limit_value_frame, text="Max Rate:").pack(side='left')
        
        self.rate_limit_value_var = tk.StringVar()
        self.rate_limit_spinbox = ttk.Spinbox(
            rate_limit_value_frame, from_=1, to=10000, width=10,
            textvariable=self.rate_limit_value_var, command=self._on_setting_change
        )
        self.rate_limit_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(rate_limit_value_frame, text="packets/sec").pack(side='left', 
                                                                  padx=(ReMapTheme.SPACING['xs'], 0))
        
        # Advanced Timing Section
        self.timing_frame = ttk.LabelFrame(self.main_frame, text="Timing & Performance")
        
        # Timeout
        timeout_frame = ttk.Frame(self.timing_frame)
        ttk.Label(timeout_frame, text="Scan Timeout:").pack(side='left')
        
        self.timeout_var = tk.StringVar()
        self.timeout_spinbox = ttk.Spinbox(
            timeout_frame, from_=60, to=3600, width=10, 
            textvariable=self.timeout_var, command=self._on_setting_change
        )
        self.timeout_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(timeout_frame, text="seconds").pack(side='left', 
                                                     padx=(ReMapTheme.SPACING['xs'], 0))
        
        # Max Retries
        retries_frame = ttk.Frame(self.timing_frame)
        ttk.Label(retries_frame, text="Max Retries:").pack(side='left')
        
        self.max_retries_var = tk.StringVar()
        self.max_retries_spinbox = ttk.Spinbox(
            retries_frame, from_=0, to=10, width=10,
            textvariable=self.max_retries_var, command=self._on_setting_change
        )
        self.max_retries_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        # Scan Delay
        delay_frame = ttk.Frame(self.timing_frame)
        ttk.Label(delay_frame, text="Scan Delay:").pack(side='left')
        
        self.scan_delay_var = tk.StringVar()
        self.scan_delay_spinbox = ttk.Spinbox(
            delay_frame, from_=0, to=60, increment=0.1, width=10,
            textvariable=self.scan_delay_var, command=self._on_setting_change
        )
        self.scan_delay_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(delay_frame, text="seconds").pack(side='left', 
                                                   padx=(ReMapTheme.SPACING['xs'], 0))
        
        # Analysis Settings Section
        self.analysis_frame = ttk.LabelFrame(self.main_frame, text="Security Analysis Settings")
        
        # TLS Analysis
        self.tls_analysis_var = tk.BooleanVar()
        self.tls_analysis_cb = ttk.Checkbutton(
            self.analysis_frame, text="Enable TLS Version Analysis",
            variable=self.tls_analysis_var, command=self._on_setting_change
        )
        
        # SSL Analysis
        self.ssl_analysis_var = tk.BooleanVar()
        self.ssl_analysis_cb = ttk.Checkbutton(
            self.analysis_frame, text="Enable SSL Certificate Analysis",
            variable=self.ssl_analysis_var, command=self._on_setting_change
        )
        
        # SMB Analysis
        self.smb_analysis_var = tk.BooleanVar()
        self.smb_analysis_cb = ttk.Checkbutton(
            self.analysis_frame, text="Enable SMB Signing Analysis",
            variable=self.smb_analysis_var, command=self._on_setting_change
        )
        
        # Web Detection
        self.web_detection_var = tk.BooleanVar()
        self.web_detection_cb = ttk.Checkbutton(
            self.analysis_frame, text="Enable Web Service Detection",
            variable=self.web_detection_var, command=self._on_setting_change
        )
        
        # Analysis Concurrency
        concurrency_frame = ttk.Frame(self.analysis_frame)
        ttk.Label(concurrency_frame, text="Max Concurrent Analysis:").pack(side='left')
        
        self.analysis_workers_var = tk.StringVar()
        self.analysis_workers_spinbox = ttk.Spinbox(
            concurrency_frame, from_=1, to=50, width=10,
            textvariable=self.analysis_workers_var, command=self._on_setting_change
        )
        self.analysis_workers_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(concurrency_frame, text="threads").pack(side='left', 
                                                          padx=(ReMapTheme.SPACING['xs'], 0))
        
        # Output Settings Section
        self.output_frame = ttk.LabelFrame(self.main_frame, text="Output Settings")
        
        # Verbose Output
        self.verbose_output_var = tk.BooleanVar()
        self.verbose_output_cb = ttk.Checkbutton(
            self.output_frame, text="Enable Verbose Output",
            variable=self.verbose_output_var, command=self._on_setting_change
        )
        
        # Save XML
        self.save_xml_var = tk.BooleanVar()
        self.save_xml_cb = ttk.Checkbutton(
            self.output_frame, text="Auto-save XML Results",
            variable=self.save_xml_var, command=self._on_setting_change
        )
        
        # Output Directory
        output_dir_frame = ttk.Frame(self.output_frame)
        ttk.Label(output_dir_frame, text="Output Directory:").pack(side='left')
        
        self.output_dir_var = tk.StringVar()
        self.output_dir_entry = ttk.Entry(output_dir_frame, textvariable=self.output_dir_var,
                                         style='Custom.TEntry', width=30)
        self.output_dir_entry.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        self.output_dir_browse_btn = ttk.Button(output_dir_frame, text="Browse...",
                                               command=self._browse_output_dir)
        self.output_dir_browse_btn.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        # Auto-cleanup Settings
        cleanup_frame = ttk.Frame(self.output_frame)
        ttk.Label(cleanup_frame, text="Keep scan files for:").pack(side='left')
        
        self.cleanup_days_var = tk.StringVar()
        self.cleanup_days_spinbox = ttk.Spinbox(
            cleanup_frame, from_=1, to=365, width=10,
            textvariable=self.cleanup_days_var, command=self._on_setting_change
        )
        self.cleanup_days_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(cleanup_frame, text="days").pack(side='left', 
                                                  padx=(ReMapTheme.SPACING['xs'], 0))
        
        # GUI Settings Section
        self.gui_frame = ttk.LabelFrame(self.main_frame, text="Interface Settings")
        
        # Theme Selection
        theme_frame = ttk.Frame(self.gui_frame)
        ttk.Label(theme_frame, text="Theme:").pack(side='left')
        
        self.theme_var = tk.StringVar()
        self.theme_combo = ttk.Combobox(
            theme_frame, textvariable=self.theme_var,
            values=["Default", "Dark", "Light", "High Contrast"],
            state="readonly", width=15
        )
        self.theme_combo.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        self.theme_combo.bind('<<ComboboxSelected>>', self._on_theme_change)
        
        # Auto-refresh Results
        self.auto_refresh_var = tk.BooleanVar()
        self.auto_refresh_cb = ttk.Checkbutton(
            self.gui_frame, text="Auto-refresh Results Display",
            variable=self.auto_refresh_var, command=self._on_setting_change
        )
        
        # Show Tooltips
        self.show_tooltips_var = tk.BooleanVar()
        self.show_tooltips_cb = ttk.Checkbutton(
            self.gui_frame, text="Show Tooltips",
            variable=self.show_tooltips_var, command=self._on_setting_change
        )
        
        # Confirmation Dialogs
        self.confirm_actions_var = tk.BooleanVar()
        self.confirm_actions_cb = ttk.Checkbutton(
            self.gui_frame, text="Show Confirmation Dialogs",
            variable=self.confirm_actions_var, command=self._on_setting_change
        )
        
        # Remember Window State
        self.remember_window_var = tk.BooleanVar()
        self.remember_window_cb = ttk.Checkbutton(
            self.gui_frame, text="Remember Window Size and Position",
            variable=self.remember_window_var, command=self._on_setting_change
        )
        
        # Logging Settings Section
        self.logging_frame = ttk.LabelFrame(self.main_frame, text="Logging Settings")
        
        # Log Level
        log_level_frame = ttk.Frame(self.logging_frame)
        ttk.Label(log_level_frame, text="Log Level:").pack(side='left')
        
        self.log_level_var = tk.StringVar()
        self.log_level_combo = ttk.Combobox(
            log_level_frame, textvariable=self.log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            state="readonly", width=12
        )
        self.log_level_combo.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        self.log_level_combo.bind('<<ComboboxSelected>>', self._on_setting_change)
        
        # Log to File
        self.log_to_file_var = tk.BooleanVar()
        self.log_to_file_cb = ttk.Checkbutton(
            self.logging_frame, text="Log to File",
            variable=self.log_to_file_var, command=self._on_setting_change
        )
        
        # Log File Size Limit
        log_size_frame = ttk.Frame(self.logging_frame)
        ttk.Label(log_size_frame, text="Max Log File Size:").pack(side='left')
        
        self.log_file_size_var = tk.StringVar()
        self.log_file_size_spinbox = ttk.Spinbox(
            log_size_frame, from_=1, to=100, width=10,
            textvariable=self.log_file_size_var, command=self._on_setting_change
        )
        self.log_file_size_spinbox.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        ttk.Label(log_size_frame, text="MB").pack(side='left', 
                                                 padx=(ReMapTheme.SPACING['xs'], 0))
        
        # Security Settings Section
        self.security_frame = ttk.LabelFrame(self.main_frame, text="Security Settings")
        
        # Require Confirmation for Destructive Actions
        self.confirm_destructive_var = tk.BooleanVar()
        self.confirm_destructive_cb = ttk.Checkbutton(
            self.security_frame, text="Confirm Destructive Scan Options",
            variable=self.confirm_destructive_var, command=self._on_setting_change
        )
        
        # Validate Targets
        self.validate_targets_var = tk.BooleanVar()
        self.validate_targets_cb = ttk.Checkbutton(
            self.security_frame, text="Auto-validate Target Lists",
            variable=self.validate_targets_var, command=self._on_setting_change
        )
        
        # Warn on Large Scans
        self.warn_large_scans_var = tk.BooleanVar()
        self.warn_large_scans_cb = ttk.Checkbutton(
            self.security_frame, text="Warn Before Large Scans (>100 targets)",
            variable=self.warn_large_scans_var, command=self._on_setting_change
        )
        
        # Network Interface Selection (Advanced)
        interface_frame = ttk.Frame(self.security_frame)
        ttk.Label(interface_frame, text="Network Interface:").pack(side='left')
        
        self.network_interface_var = tk.StringVar()
        self.network_interface_combo = ttk.Combobox(
            interface_frame, textvariable=self.network_interface_var,
            values=["Auto-detect", "eth0", "eth1", "wlan0", "lo"],
            state="readonly", width=15
        )
        self.network_interface_combo.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        self.network_interface_combo.bind('<<ComboboxSelected>>', self._on_setting_change)
        
        # Action Buttons Section
        self.buttons_frame = ttk.Frame(self.main_frame)
        
        # Save Settings
        self.save_btn = ttk.Button(self.buttons_frame, text="Save Settings",
                                  style='Primary.TButton', command=self._save_settings)
        
        # Reset to Defaults
        self.reset_btn = ttk.Button(self.buttons_frame, text="Reset to Defaults",
                                   style='Secondary.TButton', command=self._reset_to_defaults)
        
        # Cancel Changes
        self.cancel_btn = ttk.Button(self.buttons_frame, text="Cancel Changes",
                                    command=self._cancel_changes)
        
        # Export Settings
        self.export_btn = ttk.Button(self.buttons_frame, text="Export Settings",
                                    command=self._export_settings)
        
        # Import Settings
        self.import_btn = ttk.Button(self.buttons_frame, text="Import Settings",
                                    command=self._import_settings)
        
        # Status Label
        self.status_var = tk.StringVar(value="")
        self.status_label = ttk.Label(self.main_frame, textvariable=self.status_var,
                                     style='Muted.TLabel')
        
        # Store frame references for easy access
        self.nmap_frame = nmap_frame
        self.rate_limit_value_frame = rate_limit_value_frame
        self.timeout_frame = timeout_frame
        self.retries_frame = retries_frame
        self.delay_frame = delay_frame
        self.concurrency_frame = concurrency_frame
        self.output_dir_frame = output_dir_frame
        self.cleanup_frame = cleanup_frame
        self.theme_frame = theme_frame
        self.log_level_frame = log_level_frame
        self.log_size_frame = log_size_frame
        self.interface_frame = interface_frame
    
    def _setup_layout(self):
        """Set up widget layout."""
        # Main sections with spacing
        sections = [
            (self.general_frame, [self.nmap_frame]),
            (self.scan_defaults_frame, [
                self.service_detection_cb, self.version_detection_cb,
                self.os_detection_cb, self.script_scan_cb
            ]),
            (self.rate_limit_frame, [self.enable_rate_limit_cb, self.rate_limit_value_frame]),
            (self.timing_frame, [self.timeout_frame, self.retries_frame, self.delay_frame]),
            (self.analysis_frame, [
                self.tls_analysis_cb, self.ssl_analysis_cb, self.smb_analysis_cb,
                self.web_detection_cb, self.concurrency_frame
            ]),
            (self.output_frame, [
                self.verbose_output_cb, self.save_xml_cb, self.output_dir_frame,
                self.cleanup_frame
            ]),
            (self.gui_frame, [
                self.theme_frame, self.auto_refresh_cb, self.show_tooltips_cb,
                self.confirm_actions_cb, self.remember_window_cb
            ]),
            (self.logging_frame, [
                self.log_level_frame, self.log_to_file_cb, self.log_size_frame
            ]),
            (self.security_frame, [
                self.confirm_destructive_cb, self.validate_targets_cb,
                self.warn_large_scans_cb, self.interface_frame
            ])
        ]
        
        # Pack sections
        for section_frame, widgets in sections:
            section_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                             pady=(0, ReMapTheme.SPACING['md']))
            
            for widget in widgets:
                if isinstance(widget, ttk.Frame):
                    widget.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                               pady=ReMapTheme.SPACING['sm'])
                else:
                    widget.pack(anchor='w', padx=ReMapTheme.SPACING['md'], 
                               pady=ReMapTheme.SPACING['xs'])
        
        # Action buttons
        self.buttons_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                               pady=ReMapTheme.SPACING['lg'])
        
        # Pack buttons with proper spacing
        button_configs = [
            (self.save_btn, 'left'),
            (self.reset_btn, 'left'),
            (self.cancel_btn, 'left'),
            (self.export_btn, 'right'),
            (self.import_btn, 'right')
        ]
        
        for button, side in button_configs:
            padx = (0, ReMapTheme.SPACING['sm']) if side == 'left' else (ReMapTheme.SPACING['sm'], 0)
            button.pack(side=side, padx=padx)
        
        # Status label
        self.status_label.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                              pady=(ReMapTheme.SPACING['sm'], 0))
    
    def _setup_tooltips(self):
        """Set up tooltips for settings widgets."""
        tooltips = {
            self.nmap_path_entry: "Path to Nmap executable. Leave blank for auto-detection.",
            self.service_detection_cb: "Enable service version detection (-sV). Provides detailed service information.",
            self.version_detection_cb: "Enable version detection scripts (-sC). Runs default NSE scripts.",
            self.os_detection_cb: "Enable OS detection (-O). Attempts to identify target operating system.",
            self.script_scan_cb: "Enable aggressive scanning (-A). Includes OS detection, version detection, script scanning, and traceroute.",
            self.enable_rate_limit_cb: "Limit scan speed to avoid overwhelming targets or triggering IDS.",
            self.rate_limit_spinbox: "Maximum packets per second to send during scan.",
            self.timeout_spinbox: "Maximum time to wait for scan completion (seconds).",
            self.max_retries_spinbox: "Number of times to retry failed connections.",
            self.scan_delay_spinbox: "Delay between probes in seconds (helps avoid detection).",
            self.tls_analysis_cb: "Analyze TLS versions and cipher suites on HTTPS services.",
            self.ssl_analysis_cb: "Check SSL certificates for expiry and vulnerabilities.",
            self.smb_analysis_cb: "Check SMB signing configuration and versions.",
            self.web_detection_cb: "Detect web applications and technologies.",
            self.analysis_workers_spinbox: "Number of concurrent threads for analysis tasks.",
            self.verbose_output_cb: "Show detailed progress information during scans.",
            self.save_xml_cb: "Automatically save XML results for later analysis.",
            self.output_dir_entry: "Directory where scan results and reports are saved.",
            self.cleanup_days_spinbox: "Automatically delete old scan files after this many days.",
            self.theme_combo: "Choose the application color theme.",
            self.auto_refresh_cb: "Automatically refresh results display when new data is available.",
            self.show_tooltips_cb: "Show helpful tooltips on hover (requires restart).",
            self.confirm_actions_cb: "Show confirmation dialogs for important actions.",
            self.remember_window_cb: "Remember window size and position between sessions.",
            self.log_level_combo: "Set minimum logging level for console and file output.",
            self.log_to_file_cb: "Enable logging to file in addition to console.",
            self.log_file_size_spinbox: "Maximum size for log files before rotation (MB).",
            self.confirm_destructive_cb: "Require confirmation for potentially destructive scan options.",
            self.validate_targets_cb: "Automatically validate target IP addresses and ranges.",
            self.warn_large_scans_cb: "Show warning dialog before scanning many targets.",
            self.network_interface_combo: "Network interface to use for scanning (advanced)."
        }
        
        for widget, tooltip_text in tooltips.items():
            ToolTip(widget, tooltip_text)
    
    def _setup_bindings(self):
        """Set up event bindings."""
        # Bind Enter key to save settings
        self.bind('<Return>', lambda e: self._save_settings())
        self.focus_set()
        
        # Variable change bindings are handled in _on_setting_change
    
    def _load_current_settings(self):
        """Load current settings into the UI."""
        try:
            # Store original settings for reset
            self.original_settings = ScanSettings(
                enable_rate_limit=self.settings.enable_rate_limit,
                rate_limit_value=self.settings.rate_limit_value,
                enable_service_detection=self.settings.enable_service_detection,
                enable_version_detection=self.settings.enable_version_detection,
                enable_os_detection=self.settings.enable_os_detection,
                enable_script_scan=self.settings.enable_script_scan,
                timeout=self.settings.timeout,
                max_retries=self.settings.max_retries,
                scan_delay=self.settings.scan_delay,
                verbose_output=self.settings.verbose_output,
                save_xml=self.settings.save_xml
            )
            
            # Load scan defaults
            self.service_detection_var.set(self.settings.enable_service_detection)
            self.version_detection_var.set(self.settings.enable_version_detection)
            self.os_detection_var.set(self.settings.enable_os_detection)
            self.script_scan_var.set(self.settings.enable_script_scan)
            
            # Load rate limiting
            self.enable_rate_limit_var.set(self.settings.enable_rate_limit)
            self.rate_limit_value_var.set(str(self.settings.rate_limit_value))
            
            # Load timing settings
            self.timeout_var.set(str(self.settings.timeout))
            self.max_retries_var.set(str(self.settings.max_retries))
            self.scan_delay_var.set(str(self.settings.scan_delay))
            
            # Load analysis settings (defaults for new features)
            self.tls_analysis_var.set(getattr(self.settings, 'enable_tls_analysis', True))
            self.ssl_analysis_var.set(getattr(self.settings, 'enable_ssl_analysis', True))
            self.smb_analysis_var.set(getattr(self.settings, 'enable_smb_analysis', True))
            self.web_detection_var.set(getattr(self.settings, 'enable_web_detection', True))
            self.analysis_workers_var.set(str(getattr(self.settings, 'analysis_workers', 10)))
            
            # Load output settings
            self.verbose_output_var.set(self.settings.verbose_output)
            self.save_xml_var.set(self.settings.save_xml)
            self.output_dir_var.set(getattr(self.settings, 'output_directory', 
                                           str(Path.home() / ".remap" / "results")))
            self.cleanup_days_var.set(str(getattr(self.settings, 'cleanup_days', 30)))
            
            # Load GUI settings
            self.theme_var.set(getattr(self.settings, 'theme', 'Default'))
            self.auto_refresh_var.set(getattr(self.settings, 'auto_refresh', True))
            self.show_tooltips_var.set(getattr(self.settings, 'show_tooltips', True))
            self.confirm_actions_var.set(getattr(self.settings, 'confirm_actions', True))
            self.remember_window_var.set(getattr(self.settings, 'remember_window', True))
            
            # Load logging settings
            self.log_level_var.set(getattr(self.settings, 'log_level', 'INFO'))
            self.log_to_file_var.set(getattr(self.settings, 'log_to_file', True))
            self.log_file_size_var.set(str(getattr(self.settings, 'log_file_size_mb', 10)))
            
            # Load security settings
            self.confirm_destructive_var.set(getattr(self.settings, 'confirm_destructive', True))
            self.validate_targets_var.set(getattr(self.settings, 'validate_targets', True))
            self.warn_large_scans_var.set(getattr(self.settings, 'warn_large_scans', True))
            self.network_interface_var.set(getattr(self.settings, 'network_interface', 'Auto-detect'))
            
            # Load Nmap path
            self.nmap_path_var.set(getattr(self.settings, 'nmap_path', ''))
            
            # Update UI state
            self._on_rate_limit_toggle()
            
            logger.debug("Settings loaded into UI")
            
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            messagebox.showerror("Error", f"Failed to load settings: {e}")
    
    def _on_setting_change(self, *args):
        """Handle setting changes."""
        try:
            # Enable save button to indicate unsaved changes
            self.save_btn.configure(state='normal')
            self.status_var.set("Settings modified (unsaved)")
            
            # Auto-save certain critical settings
            self._auto_save_critical_settings()
            
        except Exception as e:
            logger.error(f"Error handling setting change: {e}")
    
    def _auto_save_critical_settings(self):
        """Auto-save critical settings that should take effect immediately."""
        try:
            # Update rate limiting in real-time
            if hasattr(self, 'settings'):
                self.settings.enable_rate_limit = self.enable_rate_limit_var.get()
                if self.rate_limit_value_var.get().isdigit():
                    self.settings.rate_limit_value = int(self.rate_limit_value_var.get())
                
                # Notify callback of critical changes
                if self.settings_changed_callback:
                    self.settings_changed_callback(self.settings)
                    
        except Exception as e:
            logger.error(f"Error auto-saving critical settings: {e}")
    
    def _on_rate_limit_toggle(self):
        """Handle rate limiting toggle."""
        try:
            enabled = self.enable_rate_limit_var.get()
            
            # Enable/disable rate limit value controls
            state = 'normal' if enabled else 'disabled'
            self.rate_limit_spinbox.configure(state=state)
            
            self._on_setting_change()
            
        except Exception as e:
            logger.error(f"Error handling rate limit toggle: {e}")
    
    def _on_theme_change(self, event=None):
        """Handle theme change."""
        try:
            new_theme = self.theme_var.get()
            
            # Show restart message for theme changes
            if hasattr(self, 'original_settings'):
                messagebox.showinfo("Theme Change", 
                                  "Theme changes will take effect after restarting the application.")
            
            self._on_setting_change()
            
        except Exception as e:
            logger.error(f"Error handling theme change: {e}")
    
    def _browse_nmap_path(self):
        """Browse for Nmap executable."""
        try:
            # Determine file types based on OS
            import platform
            if platform.system() == "Windows":
                filetypes = [("Executable files", "*.exe"), ("All files", "*.*")]
                initial_dir = "C:\\Program Files\\Nmap"
            else:
                filetypes = [("All files", "*.*")]
                initial_dir = "/usr/bin"
            
            file_path = filedialog.askopenfilename(
                title="Select Nmap Executable",
                filetypes=filetypes,
                initialdir=initial_dir if os.path.exists(initial_dir) else None
            )
            
            if file_path:
                self.nmap_path_var.set(file_path)
                self._on_setting_change()
                
                # Test the selected path
                self._test_nmap_path()
                
        except Exception as e:
            logger.error(f"Error browsing for Nmap path: {e}")
            messagebox.showerror("Error", f"Error selecting Nmap path: {e}")
    
    def _test_nmap_path(self):
        """Test the Nmap executable path."""
        try:
            nmap_path = self.nmap_path_var.get().strip()
            
            if not nmap_path:
                # Test auto-detection
                from ..core.nmap_wrapper import NmapWrapper
                wrapper = NmapWrapper(self.settings)
                if wrapper.test_nmap():
                    messagebox.showinfo("Nmap Test", "Nmap auto-detection successful!")
                    return
                else:
                    messagebox.showerror("Nmap Test", "Nmap auto-detection failed!")
                    return
            
            # Test specific path
            import subprocess
            try:
                result = subprocess.run([nmap_path, "--version"], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    version_info = result.stdout.strip().split('\n')[0] if result.stdout else "Unknown version"
                    messagebox.showinfo("Nmap Test", f"Nmap test successful!\n{version_info}")
                else:
                    messagebox.showerror("Nmap Test", f"Nmap test failed!\nError: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                messagebox.showerror("Nmap Test", "Nmap test timed out!")
            except FileNotFoundError:
                messagebox.showerror("Nmap Test", "Nmap executable not found at specified path!")
                
        except Exception as e:
            logger.error(f"Error testing Nmap path: {e}")
            messagebox.showerror("Error", f"Error testing Nmap: {e}")
    
    def _browse_output_dir(self):
        """Browse for output directory."""
        try:
            directory = filedialog.askdirectory(
                title="Select Output Directory",
                initialdir=self.output_dir_var.get() or str(Path.home())
            )
            
            if directory:
                self.output_dir_var.set(directory)
                self._on_setting_change()
                
                # Ensure directory is writable
                if not os.access(directory, os.W_OK):
                    messagebox.showwarning("Warning", 
                                         "Selected directory may not be writable. Please check permissions.")
                
        except Exception as e:
            logger.error(f"Error browsing for output directory: {e}")
            messagebox.showerror("Error", f"Error selecting output directory: {e}")
    
    def _save_settings(self):
        """Save current settings."""
        try:
            # Validate settings before saving
            validation_errors = self._validate_settings()
            if validation_errors:
                error_msg = "Please correct the following errors:\n\n" + "\n".join(validation_errors)
                messagebox.showerror("Validation Error", error_msg)
                return
            
            # Update settings object
            updated_settings = self._create_settings_from_ui()
            
            # Call settings changed callback
            if self.settings_changed_callback:
                self.settings_changed_callback(updated_settings)
            
            # Update internal settings reference
            self.settings = updated_settings
            
            # Update UI state
            self.save_btn.configure(state='disabled')
            self.status_var.set("Settings saved successfully")
            
            # Auto-clear status after delay
            self.after(3000, lambda: self.status_var.set(""))
            
            logger.info("Settings saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving settings: {e}")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            self.status_var.set("Error saving settings")
    
    def _create_settings_from_ui(self) -> ScanSettings:
        """Create ScanSettings object from current UI values."""
        try:
            settings = ScanSettings()
            
            # Basic scan settings
            settings.enable_service_detection = self.service_detection_var.get()
            settings.enable_version_detection = self.version_detection_var.get()
            settings.enable_os_detection = self.os_detection_var.get()
            settings.enable_script_scan = self.script_scan_var.get()
            
            # Rate limiting
            settings.enable_rate_limit = self.enable_rate_limit_var.get()
            settings.rate_limit_value = int(self.rate_limit_value_var.get() or 100)
            
            # Timing
            settings.timeout = int(self.timeout_var.get() or 300)
            settings.max_retries = int(self.max_retries_var.get() or 3)
            settings.scan_delay = float(self.scan_delay_var.get() or 0.0)
            
            # Output
            settings.verbose_output = self.verbose_output_var.get()
            settings.save_xml = self.save_xml_var.get()
            
            # Extended settings (add to ScanSettings model as needed)
            extended_attrs = {
                'enable_tls_analysis': self.tls_analysis_var.get(),
                'enable_ssl_analysis': self.ssl_analysis_var.get(),
                'enable_smb_analysis': self.smb_analysis_var.get(),
                'enable_web_detection': self.web_detection_var.get(),
                'analysis_workers': int(self.analysis_workers_var.get() or 10),
                'output_directory': self.output_dir_var.get(),
                'cleanup_days': int(self.cleanup_days_var.get() or 30),
                'theme': self.theme_var.get(),
                'auto_refresh': self.auto_refresh_var.get(),
                'show_tooltips': self.show_tooltips_var.get(),
                'confirm_actions': self.confirm_actions_var.get(),
                'remember_window': self.remember_window_var.get(),
                'log_level': self.log_level_var.get(),
                'log_to_file': self.log_to_file_var.get(),
                'log_file_size_mb': int(self.log_file_size_var.get() or 10),
                'confirm_destructive': self.confirm_destructive_var.get(),
                'validate_targets': self.validate_targets_var.get(),
                'warn_large_scans': self.warn_large_scans_var.get(),
                'network_interface': self.network_interface_var.get(),
                'nmap_path': self.nmap_path_var.get().strip()
            }
            
            # Add extended attributes to settings
            for attr, value in extended_attrs.items():
                setattr(settings, attr, value)
            
            return settings
            
        except Exception as e:
            logger.error(f"Error creating settings from UI: {e}")
            raise
    
    def _validate_settings(self) -> List[str]:
        """Validate current settings and return list of errors."""
        errors = []
        
        try:
            # Validate numeric fields
            numeric_validations = [
                (self.rate_limit_value_var.get(), "Rate limit value", 1, 10000),
                (self.timeout_var.get(), "Timeout", 60, 7200),
                (self.max_retries_var.get(), "Max retries", 0, 10),
                (self.analysis_workers_var.get(), "Analysis workers", 1, 50),
                (self.cleanup_days_var.get(), "Cleanup days", 1, 365),
                (self.log_file_size_var.get(), "Log file size", 1, 1000)
            ]
            
            for value, field_name, min_val, max_val in numeric_validations:
                try:
                    num_value = int(value)
                    if num_value < min_val or num_value > max_val:
                        errors.append(f"{field_name} must be between {min_val} and {max_val}")
                except ValueError:
                    errors.append(f"{field_name} must be a valid number")
            
            # Validate scan delay (float)
            try:
                delay_value = float(self.scan_delay_var.get())
                if delay_value < 0 or delay_value > 60:
                    errors.append("Scan delay must be between 0 and 60 seconds")
            except ValueError:
                errors.append("Scan delay must be a valid number")
            
            # Validate Nmap path if specified
            nmap_path = self.nmap_path_var.get().strip()
            if nmap_path and not os.path.exists(nmap_path):
                errors.append("Nmap executable path does not exist")
            
            # Validate output directory
            output_dir = self.output_dir_var.get().strip()
            if output_dir:
                if not os.path.exists(output_dir):
                    try:
                        os.makedirs(output_dir, exist_ok=True)
                    except OSError:
                        errors.append("Cannot create output directory")
                elif not os.access(output_dir, os.W_OK):
                    errors.append("Output directory is not writable")
            
            # Validate conflicting options
            if (self.script_scan_var.get() and 
                (self.service_detection_var.get() or self.version_detection_var.get())):
                # This is a warning, not an error
                pass
            
            return errors
            
        except Exception as e:
            logger.error(f"Error validating settings: {e}")
            return [f"Validation error: {e}"]
    
    def _reset_to_defaults(self):
        """Reset settings to default values."""
        try:
            result = messagebox.askyesno(
                "Reset Settings",
                "This will reset all settings to their default values. Continue?"
            )
            
            if result:
                # Create new default settings
                default_settings = ScanSettings()
                
                # Load defaults into UI
                self._load_settings_into_ui(default_settings)
                
                self._on_setting_change()
                self.status_var.set("Settings reset to defaults (unsaved)")
                
                logger.info("Settings reset to defaults")
                
        except Exception as e:
            logger.error(f"Error resetting settings: {e}")
            messagebox.showerror("Error", f"Failed to reset settings: {e}")
    
    def _load_settings_into_ui(self, settings: ScanSettings):
        """Load given settings into UI controls."""
        try:
            # Basic scan settings
            self.service_detection_var.set(settings.enable_service_detection)
            self.version_detection_var.set(settings.enable_version_detection)
            self.os_detection_var.set(settings.enable_os_detection)
            self.script_scan_var.set(settings.enable_script_scan)
            
            # Rate limiting
            self.enable_rate_limit_var.set(settings.enable_rate_limit)
            self.rate_limit_value_var.set(str(settings.rate_limit_value))
            
            # Timing
            self.timeout_var.set(str(settings.timeout))
            self.max_retries_var.set(str(settings.max_retries))
            self.scan_delay_var.set(str(settings.scan_delay))
            
            # Output
            self.verbose_output_var.set(settings.verbose_output)
            self.save_xml_var.set(settings.save_xml)
            
            # Extended settings with defaults
            self.tls_analysis_var.set(getattr(settings, 'enable_tls_analysis', True))
            self.ssl_analysis_var.set(getattr(settings, 'enable_ssl_analysis', True))
            self.smb_analysis_var.set(getattr(settings, 'enable_smb_analysis', True))
            self.web_detection_var.set(getattr(settings, 'enable_web_detection', True))
            self.analysis_workers_var.set(str(getattr(settings, 'analysis_workers', 10)))
            
            self.output_dir_var.set(getattr(settings, 'output_directory', 
                                           str(Path.home() / ".remap" / "results")))
            self.cleanup_days_var.set(str(getattr(settings, 'cleanup_days', 30)))
            
            self.theme_var.set(getattr(settings, 'theme', 'Default'))
            self.auto_refresh_var.set(getattr(settings, 'auto_refresh', True))
            self.show_tooltips_var.set(getattr(settings, 'show_tooltips', True))
            self.confirm_actions_var.set(getattr(settings, 'confirm_actions', True))
            self.remember_window_var.set(getattr(settings, 'remember_window', True))
            
            self.log_level_var.set(getattr(settings, 'log_level', 'INFO'))
            self.log_to_file_var.set(getattr(settings, 'log_to_file', True))
            self.log_file_size_var.set(str(getattr(settings, 'log_file_size_mb', 10)))
            
            self.confirm_destructive_var.set(getattr(settings, 'confirm_destructive', True))
            self.validate_targets_var.set(getattr(settings, 'validate_targets', True))
            self.warn_large_scans_var.set(getattr(settings, 'warn_large_scans', True))
            self.network_interface_var.set(getattr(settings, 'network_interface', 'Auto-detect'))
            
            self.nmap_path_var.set(getattr(settings, 'nmap_path', ''))
            
            # Update UI state
            self._on_rate_limit_toggle()
            
        except Exception as e:
            logger.error(f"Error loading settings into UI: {e}")
            raise
    
    def _cancel_changes(self):
        """Cancel changes and revert to original settings."""
        try:
            if self.original_settings:
                result = messagebox.askyesno(
                    "Cancel Changes",
                    "This will discard all unsaved changes. Continue?"
                )
                
                if result:
                    self._load_settings_into_ui(self.original_settings)
                    self.save_btn.configure(state='disabled')
                    self.status_var.set("Changes cancelled")
                    
                    logger.debug("Settings changes cancelled")
            
        except Exception as e:
            logger.error(f"Error cancelling changes: {e}")
            messagebox.showerror("Error", f"Failed to cancel changes: {e}")
    
    def _export_settings(self):
        """Export current settings to file."""
        try:
            file_path = filedialog.asksaveasfilename(
                title="Export Settings",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                # Create settings from current UI
                settings = self._create_settings_from_ui()
                
                # Convert to dictionary
                settings_dict = settings.to_dict()
                
                # Add metadata
                settings_dict['_metadata'] = {
                    'export_time': datetime.now().isoformat(),
                    'version': '1.0',
                    'application': 'ReMap'
                }
                
                # Write to file
                if FileHandler.write_json_file(file_path, settings_dict):
                    messagebox.showinfo("Export Success", f"Settings exported to:\n{file_path}")
                    self.status_var.set("Settings exported successfully")
                else:
                    messagebox.showerror("Export Error", "Failed to write settings file")
                    
        except Exception as e:
            logger.error(f"Error exporting settings: {e}")
            messagebox.showerror("Error", f"Failed to export settings: {e}")
    
    def _import_settings(self):
        """Import settings from file."""
        try:
            file_path = filedialog.askopenfilename(
                title="Import Settings",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                # Read settings file
                settings_dict = FileHandler.read_json_file(file_path)
                if not settings_dict:
                    messagebox.showerror("Import Error", "Failed to read settings file")
                    return
                
                # Remove metadata if present
                if '_metadata' in settings_dict:
                    del settings_dict['_metadata']
                
                # Create settings object
                try:
                    imported_settings = ScanSettings.from_dict(settings_dict)
                except Exception as e:
                    messagebox.showerror("Import Error", f"Invalid settings file format: {e}")
                    return
                
                # Confirm import
                result = messagebox.askyesno(
                    "Import Settings",
                    "This will replace all current settings with the imported ones. Continue?"
                )
                
                if result:
                    # Load imported settings into UI
                    self._load_settings_into_ui(imported_settings)
                    
                    # Mark as changed
                    self._on_setting_change()
                    self.status_var.set("Settings imported (unsaved)")
                    
                    messagebox.showinfo("Import Success", "Settings imported successfully")
                    logger.info(f"Settings imported from: {file_path}")
                    
        except Exception as e:
            logger.error(f"Error importing settings: {e}")
            messagebox.showerror("Error", f"Failed to import settings: {e}")
    
    def get_analysis_options(self) -> Dict[str, bool]:
        """Get current analysis options for security analyzer."""
        try:
            return {
                'tls_check': self.tls_analysis_var.get(),
                'ssl_check': self.ssl_analysis_var.get(),
                'smb_check': self.smb_analysis_var.get(),
                'web_detection': self.web_detection_var.get(),
                'vulnerability_scan': True  # Always enabled for now
            }
        except Exception as e:
            logger.error(f"Error getting analysis options: {e}")
            return {
                'tls_check': True,
                'ssl_check': True,
                'smb_check': True,
                'web_detection': True,
                'vulnerability_scan': True
            }
    
    def set_analysis_options(self, options: Dict[str, bool]):
        """Set analysis options in the UI."""
        try:
            if 'tls_check' in options:
                self.tls_analysis_var.set(options['tls_check'])
            
            if 'ssl_check' in options:
                self.ssl_analysis_var.set(options['ssl_check'])
            
            if 'smb_check' in options:
                self.smb_analysis_var.set(options['smb_check'])
            
            if 'web_detection' in options:
                self.web_detection_var.set(options['web_detection'])
            
            self._on_setting_change()
            
        except Exception as e:
            logger.error(f"Error setting analysis options: {e}")
    
    def get_scan_options(self) -> Dict[str, Any]:
        """Get current scan options."""
        try:
            return {
                'service_detection': self.service_detection_var.get(),
                'version_detection': self.version_detection_var.get(),
                'os_detection': self.os_detection_var.get(),
                'script_scan': self.script_scan_var.get(),
                'rate_limit_enabled': self.enable_rate_limit_var.get(),
                'rate_limit_value': int(self.rate_limit_value_var.get() or 100),
                'timeout': int(self.timeout_var.get() or 300),
                'max_retries': int(self.max_retries_var.get() or 3),
                'scan_delay': float(self.scan_delay_var.get() or 0.0),
                'verbose': self.verbose_output_var.get(),
                'save_xml': self.save_xml_var.get()
            }
        except Exception as e:
            logger.error(f"Error getting scan options: {e}")
            return {}
    
    def validate_nmap_installation(self) -> bool:
        """Validate Nmap installation and show results."""
        try:
            nmap_path = self.nmap_path_var.get().strip()
            
            from ..core.nmap_wrapper import NmapWrapper
            
            # Create temporary settings with current Nmap path
            temp_settings = ScanSettings()
            if nmap_path:
                setattr(temp_settings, 'nmap_path', nmap_path)
            
            wrapper = NmapWrapper(temp_settings)
            
            if wrapper.test_nmap():
                # Get version info
                import subprocess
                try:
                    result = subprocess.run([wrapper.nmap_path, "--version"], 
                                          capture_output=True, text=True, timeout=10)
                    version_info = result.stdout.strip() if result.stdout else "Version unknown"
                    
                    messagebox.showinfo("Nmap Validation", 
                                      f"✅ Nmap installation valid!\n\n{version_info}")
                    return True
                    
                except Exception:
                    messagebox.showinfo("Nmap Validation", "✅ Nmap installation valid!")
                    return True
            else:
                messagebox.showerror("Nmap Validation", 
                                   "❌ Nmap installation not found or invalid!\n\n"
                                   "Please install Nmap or specify correct path.")
                return False
                
        except Exception as e:
            logger.error(f"Error validating Nmap: {e}")
            messagebox.showerror("Error", f"Error validating Nmap installation: {e}")
            return False
    
    def show_advanced_settings(self):
        """Show advanced settings dialog."""
        try:
            # Create advanced settings dialog
            dialog = tk.Toplevel(self)
            dialog.title("Advanced Settings")
            dialog.geometry("500x400")
            dialog.transient(self.winfo_toplevel())
            dialog.grab_set()
            
            # Create notebook for advanced settings
            notebook = ttk.Notebook(dialog, style='Custom.TNotebook')
            notebook.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Network tab
            network_tab = ttk.Frame(notebook)
            notebook.add(network_tab, text="Network")
            
            # Add network-specific settings here
            ttk.Label(network_tab, text="Advanced network settings will be added here").pack(pady=20)
            
            # Performance tab
            performance_tab = ttk.Frame(notebook)
            notebook.add(performance_tab, text="Performance")
            
            # Add performance settings here
            ttk.Label(performance_tab, text="Advanced performance settings will be added here").pack(pady=20)
            
            # Close button
            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
            
            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
            y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
            dialog.geometry(f"+{x}+{y}")
            
        except Exception as e:
            logger.error(f"Error showing advanced settings: {e}")
            messagebox.showerror("Error", f"Failed to show advanced settings: {e}")
    
    def has_unsaved_changes(self) -> bool:
        """Check if there are unsaved changes."""
        try:
            if not self.original_settings:
                return False
            
            current_settings = self._create_settings_from_ui()
            
            # Compare with original settings
            # This is a simplified comparison - in production you'd want more thorough comparison
            return (
                current_settings.enable_rate_limit != self.original_settings.enable_rate_limit or
                current_settings.rate_limit_value != self.original_settings.rate_limit_value or
                current_settings.enable_service_detection != self.original_settings.enable_service_detection or
                current_settings.enable_version_detection != self.original_settings.enable_version_detection or
                current_settings.timeout != self.original_settings.timeout
                # Add more comparisons as needed
            )
            
        except Exception as e:
            logger.error(f"Error checking for unsaved changes: {e}")
            return False
    
    def apply_theme(self, theme_name: str):
        """Apply theme to settings frame."""
        try:
            # This would implement theme application
            # For now, just update the theme variable
            self.theme_var.set(theme_name)
            
            logger.info(f"Theme applied: {theme_name}")
            
        except Exception as e:
            logger.error(f"Error applying theme: {e}")
    
    def get_current_theme(self) -> str:
        """Get currently selected theme."""
        return self.theme_var.get()
    
    def refresh_network_interfaces(self):
        """Refresh the list of available network interfaces."""
        try:
            import psutil
            
            # Get network interfaces
            interfaces = ['Auto-detect']
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                if interface_name not in interfaces:
                    interfaces.append(interface_name)
            
            # Update combobox
            self.network_interface_combo['values'] = interfaces
            
            # Keep current selection if still valid
            current = self.network_interface_var.get()
            if current not in interfaces:
                self.network_interface_var.set('Auto-detect')
            
            logger.debug(f"Refreshed network interfaces: {interfaces}")
            
        except ImportError:
            logger.warning("psutil not available for network interface detection")
        except Exception as e:
            logger.error(f"Error refreshing network interfaces: {e}")