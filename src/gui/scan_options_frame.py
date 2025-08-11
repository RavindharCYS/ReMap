"""Scan options frame for configuring scan parameters."""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any

from .styles import ReMapTheme, ToolTip, icon_manager
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ScanOptionsFrame(ttk.LabelFrame):
    """Frame for scan configuration options."""
    
    def __init__(self, parent):
        super().__init__(parent, text="Scan Options", padding=ReMapTheme.SPACING['md'])
        
        self._create_widgets()
        self._setup_layout()
        self._setup_tooltips()
        self._set_defaults()
        
        logger.debug("Scan options frame initialized")
    
    def _create_widgets(self):
        """Create option widgets."""
        # Scan type selection
        self.scan_type_var = tk.StringVar()
        
        scan_type_frame = ttk.LabelFrame(self, text="Scan Type")
        
        self.fast_radio = ttk.Radiobutton(
            scan_type_frame, text="Fast Scan",
            variable=self.scan_type_var, value="fast"
        )
        
        self.port1000_radio = ttk.Radiobutton(
            scan_type_frame, text="Top 1000 Ports",
            variable=self.scan_type_var, value="1000"
        )
        
        self.all_ports_radio = ttk.Radiobutton(
            scan_type_frame, text="All Ports (1-65535)",
            variable=self.scan_type_var, value="all"
        )
        
        # Advanced options
        advanced_frame = ttk.LabelFrame(self, text="Advanced Options")
        
        # Service detection
        self.service_detection_var = tk.BooleanVar()
        self.service_detection_cb = ttk.Checkbutton(
            advanced_frame, text="Service Detection (-sV)",
            variable=self.service_detection_var
        )
        
        # Version detection
        self.version_detection_var = tk.BooleanVar()
        self.version_detection_cb = ttk.Checkbutton(
            advanced_frame, text="Version Detection (-sC)",
            variable=self.version_detection_var
        )
        
        # OS detection
        self.os_detection_var = tk.BooleanVar()
        self.os_detection_cb = ttk.Checkbutton(
            advanced_frame, text="OS Detection (-O)",
            variable=self.os_detection_var
        )
        
        # Script scan
        self.script_scan_var = tk.BooleanVar()
        self.script_scan_cb = ttk.Checkbutton(
            advanced_frame, text="Script Scan (-A)",
            variable=self.script_scan_var
        )
        
        # Timing options
        timing_frame = ttk.LabelFrame(self, text="Timing")
        
        # Timing template
        timing_label = ttk.Label(timing_frame, text="Timing Template:")
        self.timing_var = tk.StringVar()
        self.timing_combo = ttk.Combobox(
            timing_frame, textvariable=self.timing_var,
            values=["T0 (Paranoid)", "T1 (Sneaky)", "T2 (Polite)", 
                   "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"],
            state="readonly", width=15
        )
        
        # Rate limiting
        self.rate_limit_var = tk.BooleanVar()
        self.rate_limit_cb = ttk.Checkbutton(
            timing_frame, text="Enable Rate Limiting",
            variable=self.rate_limit_var,
            command=self._on_rate_limit_toggle
        )
        
        rate_limit_label = ttk.Label(timing_frame, text="Max Rate:")
        self.rate_limit_value_var = tk.StringVar()
        self.rate_limit_spin = ttk.Spinbox(
            timing_frame, from_=1, to=10000, 
            textvariable=self.rate_limit_value_var,
            width=10, state='disabled'
        )
        rate_limit_unit = ttk.Label(timing_frame, text="packets/sec")
        
        # Output options
        output_frame = ttk.LabelFrame(self, text="Output Options")
        
        # Verbose output
        self.verbose_var = tk.BooleanVar()
        self.verbose_cb = ttk.Checkbutton(
            output_frame, text="Verbose Output (-v)",
            variable=self.verbose_var
        )
        
        # Save XML
        self.save_xml_var = tk.BooleanVar()
        self.save_xml_cb = ttk.Checkbutton(
            output_frame, text="Save XML Results",
            variable=self.save_xml_var
        )
        
        # Store widgets in frames for easy access
        self.scan_type_frame = scan_type_frame
        self.advanced_frame = advanced_frame
        self.timing_frame = timing_frame
        self.output_frame = output_frame
        
        # Store timing widgets for layout
        self.timing_widgets = [
            (timing_label, self.timing_combo),
            (self.rate_limit_cb,),
            (rate_limit_label, self.rate_limit_spin, rate_limit_unit)
        ]
    
    def _setup_layout(self):
        """Set up widget layout."""
        # Scan type frame
        self.scan_type_frame.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
        
        self.fast_radio.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                            pady=ReMapTheme.SPACING['xs'])
        self.port1000_radio.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                pady=ReMapTheme.SPACING['xs'])
        self.all_ports_radio.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                 pady=ReMapTheme.SPACING['xs'])
        
        # Advanced options frame
        self.advanced_frame.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
        
        self.service_detection_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                      pady=ReMapTheme.SPACING['xs'])
        self.version_detection_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                      pady=ReMapTheme.SPACING['xs'])
        self.os_detection_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                 pady=ReMapTheme.SPACING['xs'])
        self.script_scan_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                                pady=ReMapTheme.SPACING['xs'])
        
        # Timing frame
        self.timing_frame.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
        
        # Layout timing widgets in grid
        row = 0
        for widget_group in self.timing_widgets:
            col = 0
            for widget in widget_group:
                widget.grid(row=row, column=col, sticky='w', 
                          padx=(ReMapTheme.SPACING['sm'], ReMapTheme.SPACING['xs']),
                          pady=ReMapTheme.SPACING['xs'])
                col += 1
            row += 1
        
        # Output options frame
        self.output_frame.pack(fill='x')
        
        self.verbose_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                            pady=ReMapTheme.SPACING['xs'])
        self.save_xml_cb.pack(anchor='w', padx=ReMapTheme.SPACING['sm'], 
                             pady=ReMapTheme.SPACING['xs'])
    
    def _setup_tooltips(self):
        """Set up tooltips for widgets."""
        ToolTip(self.fast_radio, "Fast scan of most common ports (~100 ports)")
        ToolTip(self.port1000_radio, "Scan top 1000 most common ports")
        ToolTip(self.all_ports_radio, "Comprehensive scan of all 65535 ports (slow)")
        
        ToolTip(self.service_detection_cb, "Detect service versions on open ports")
        ToolTip(self.version_detection_cb, "Enable default script scanning")
        ToolTip(self.os_detection_cb, "Attempt to detect target operating system")
        ToolTip(self.script_scan_cb, "Enable aggressive scanning (includes OS detection, version detection, script scanning, and traceroute)")
        
        ToolTip(self.timing_combo, "Timing template controls scan speed vs stealth")
        ToolTip(self.rate_limit_cb, "Limit scan rate to avoid overwhelming target")
        ToolTip(self.rate_limit_spin, "Maximum packets per second")
        
        ToolTip(self.verbose_cb, "Show detailed scan progress information")
        ToolTip(self.save_xml_cb, "Save scan results in XML format for later analysis")
    
    def _set_defaults(self):
        """Set default values."""
        self.scan_type_var.set("fast")
        self.service_detection_var.set(True)
        self.version_detection_var.set(True)
        self.os_detection_var.set(False)
        self.script_scan_var.set(False)
        self.timing_var.set("T4 (Aggressive)")
        self.rate_limit_var.set(False)
        self.rate_limit_value_var.set("100")
        self.verbose_var.set(False)
        self.save_xml_var.set(True)
    
    def _on_rate_limit_toggle(self):
        """Handle rate limiting toggle."""
        if self.rate_limit_var.get():
            self.rate_limit_spin.configure(state='normal')
        else:
            self.rate_limit_spin.configure(state='disabled')
    
    def get_options(self) -> Dict[str, Any]:
        """Get current scan options."""
        try:
            # Parse timing template
            timing_text = self.timing_var.get()
            timing_level = timing_text[1] if timing_text.startswith('T') else '4'
            
            options = {
                # Basic scan options
                'scan_type': self.scan_type_var.get(),
                
                # Detection options
                'service_detection': self.service_detection_var.get(),
                'version_detection': self.version_detection_var.get(),
                'os_detection': self.os_detection_var.get(),
                'script_scan': self.script_scan_var.get(),
                
                # Timing options
                'timing_template': int(timing_level),
                'rate_limit_enabled': self.rate_limit_var.get(),
                'rate_limit_value': int(self.rate_limit_value_var.get()) if self.rate_limit_var.get() else 0,
                
                # Output options
                'verbose': self.verbose_var.get(),
                'save_xml': self.save_xml_var.get()
            }
            
            logger.debug(f"Scan options: {options}")
            return options
            
        except Exception as e:
            logger.error(f"Error getting scan options: {e}")
            # Return safe defaults
            return {
                'scan_type': 'fast',
                'service_detection': True,
                'version_detection': True,
                'os_detection': False,
                'script_scan': False,
                'timing_template': 4,
                'rate_limit_enabled': False,
                'rate_limit_value': 0,
                'verbose': False,
                'save_xml': True
            }
    
    def set_options(self, options: Dict[str, Any]):
        """Set scan options."""
        try:
            # Basic scan options
            if 'scan_type' in options:
                self.scan_type_var.set(options['scan_type'])
            
            # Detection options
            if 'service_detection' in options:
                self.service_detection_var.set(options['service_detection'])
            
            if 'version_detection' in options:
                self.version_detection_var.set(options['version_detection'])
            
            if 'os_detection' in options:
                self.os_detection_var.set(options['os_detection'])
            
            if 'script_scan' in options:
                self.script_scan_var.set(options['script_scan'])
            
            # Timing options
            if 'timing_template' in options:
                timing_map = {
                    0: "T0 (Paranoid)",
                    1: "T1 (Sneaky)", 
                    2: "T2 (Polite)",
                    3: "T3 (Normal)",
                    4: "T4 (Aggressive)",
                    5: "T5 (Insane)"
                }
                timing_value = options['timing_template']
                if timing_value in timing_map:
                    self.timing_var.set(timing_map[timing_value])
            
            if 'rate_limit_enabled' in options:
                self.rate_limit_var.set(options['rate_limit_enabled'])
                self._on_rate_limit_toggle()  # Update UI state
            
            if 'rate_limit_value' in options:
                self.rate_limit_value_var.set(str(options['rate_limit_value']))
            
            # Output options
            if 'verbose' in options:
                self.verbose_var.set(options['verbose'])
            
            if 'save_xml' in options:
                self.save_xml_var.set(options['save_xml'])
            
            logger.debug("Scan options set successfully")
            
        except Exception as e:
            logger.error(f"Error setting scan options: {e}")
    
    def set_scan_type(self, scan_type: str):
        """Set scan type."""
        if scan_type in ['fast', '1000', 'all']:
            self.scan_type_var.set(scan_type)
        else:
            logger.warning(f"Invalid scan type: {scan_type}")
    
    def get_scan_type(self) -> str:
        """Get current scan type."""
        return self.scan_type_var.get()
    
    def reset_to_defaults(self):
        """Reset all options to defaults."""
        self._set_defaults()
        logger.debug("Scan options reset to defaults")
    
    def get_estimated_duration(self, target_count: int) -> str:
        """Get estimated scan duration based on options."""
        try:
            scan_type = self.scan_type_var.get()
            timing = int(self.timing_var.get()[1]) if self.timing_var.get().startswith('T') else 4
            
            # Base estimates (seconds per host)
            base_times = {
                'fast': 30,      # ~100 ports
                '1000': 120,     # 1000 ports  
                'all': 3600      # All ports
            }
            
            base_time = base_times.get(scan_type, 30)
            
            # Timing adjustments
            timing_multipliers = {
                0: 10.0,   # T0 - Very slow
                1: 5.0,    # T1 - Slow
                2: 2.0,    # T2 - Polite
                3: 1.0,    # T3 - Normal
                4: 0.7,    # T4 - Aggressive
                5: 0.5     # T5 - Insane
            }
            
            timing_mult = timing_multipliers.get(timing, 1.0)
            
            # Additional scan options
            option_multiplier = 1.0
            if self.service_detection_var.get():
                option_multiplier *= 1.5
            if self.version_detection_var.get():
                option_multiplier *= 1.3
            if self.os_detection_var.get():
                option_multiplier *= 1.2
            if self.script_scan_var.get():
                option_multiplier *= 2.0
            
            # Rate limiting
            if self.rate_limit_var.get():
                rate = int(self.rate_limit_value_var.get())
                if rate < 100:
                    option_multiplier *= 2.0
                elif rate < 50:
                    option_multiplier *= 4.0
            
            # Calculate total time
            total_seconds = int(base_time * timing_mult * option_multiplier * target_count)
            
            # Format duration
            if total_seconds < 60:
                return f"~{total_seconds}s"
            elif total_seconds < 3600:
                minutes = total_seconds // 60
                return f"~{minutes}m"
            else:
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                return f"~{hours}h {minutes}m"
                
        except Exception as e:
            logger.error(f"Error calculating duration estimate: {e}")
            return "Unknown"
    
    def validate_options(self) -> List[str]:
        """Validate current options and return any issues."""
        issues = []
        
        try:
            # Check rate limit value
            if self.rate_limit_var.get():
                try:
                    rate_value = int(self.rate_limit_value_var.get())
                    if rate_value <= 0:
                        issues.append("Rate limit must be greater than 0")
                    elif rate_value > 10000:
                        issues.append("Rate limit seems very high (>10000 pps)")
                except ValueError:
                    issues.append("Rate limit must be a valid number")
            
            # Check for conflicting options
            if self.script_scan_var.get():
                if self.service_detection_var.get() or self.version_detection_var.get():
                    issues.append("Script scan (-A) includes service and version detection")
            
            # Warning for slow scans
            scan_type = self.scan_type_var.get()
            timing = self.timing_var.get()
            
            if scan_type == 'all' and timing.startswith('T0'):
                issues.append("All ports with T0 timing will be extremely slow")
            
        except Exception as e:
            logger.error(f"Error validating options: {e}")
            issues.append(f"Validation error: {e}")
        
        return issues