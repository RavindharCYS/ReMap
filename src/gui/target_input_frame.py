"""Target input frame for entering scan targets."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Optional

from .styles import ReMapTheme, ToolTip, icon_manager
from ..core.target_parser import TargetParser
from ..models.target import Target
from ..utils.validators import ValidationError
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class TargetInputFrame(ttk.LabelFrame):
    """Frame for target input with text entry and file loading."""
    
    def __init__(self, parent):
        super().__init__(parent, text="Scan Targets", padding=ReMapTheme.SPACING['md'])
        
        self._create_widgets()
        self._setup_layout()
        self._setup_tooltips()
        
        logger.debug("Target input frame initialized")
    
    def _create_widgets(self):
        """Create input widgets."""
        # Input method selection
        self.input_method_var = tk.StringVar(value="manual")
        
        # Manual input radio button
        self.manual_radio = ttk.Radiobutton(
            self, text="Manual Input", 
            variable=self.input_method_var, 
            value="manual",
            command=self._on_input_method_change
        )
        
        # File input radio button
        self.file_radio = ttk.Radiobutton(
            self, text="Load from File", 
            variable=self.input_method_var, 
            value="file",
            command=self._on_input_method_change
        )
        
        # Manual input frame
        self.manual_frame = ttk.Frame(self)
        
        # Target text area with scrollbar
        self.text_frame = ttk.Frame(self.manual_frame)
        
        self.target_text = tk.Text(
            self.text_frame, 
            height=8, 
            width=50,
            font=ReMapTheme.FONTS['code'],
            wrap=tk.WORD
        )
        
        self.text_scrollbar = ttk.Scrollbar(
            self.text_frame, 
            orient='vertical',
            command=self.target_text.yview
        )
        
        self.target_text.configure(yscrollcommand=self.text_scrollbar.set)
        
        # Example label
        self.example_label = ttk.Label(
            self.manual_frame,
            text="Examples: 192.168.1.1, 10.0.0.1-50, 172.16.1.100:80,443",
            style='Muted.TLabel',
            font=ReMapTheme.FONTS['small']
        )
        
        # File input frame
        self.file_frame = ttk.Frame(self)
        
        # File selection
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(
            self.file_frame,
            textvariable=self.file_path_var,
            style='Custom.TEntry',
            state='readonly'
        )
        
        self.browse_button = ttk.Button(
            self.file_frame,
            text=f"{icon_manager.get_icon('folder')} Browse...",
            command=self._browse_file
        )
        
        # File info label
        self.file_info_var = tk.StringVar()
        self.file_info_label = ttk.Label(
            self.file_frame,
            textvariable=self.file_info_var,
            style='Muted.TLabel',
            font=ReMapTheme.FONTS['small']
        )
        
        # Action buttons frame
        self.buttons_frame = ttk.Frame(self)
        
        # Validate button
        self.validate_button = ttk.Button(
            self.buttons_frame,
            text="Validate Targets",
            command=self._validate_targets
        )
        
        # Clear button
        self.clear_button = ttk.Button(
            self.buttons_frame,
            text="Clear",
            command=self.clear
        )
        
        # Load sample button
        self.sample_button = ttk.Button(
            self.buttons_frame,
            text="Load Sample",
            command=self._load_sample
        )
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            self,
            textvariable=self.status_var,
            style='Muted.TLabel'
        )
    
    def _setup_layout(self):
        """Set up widget layout."""
        # Radio buttons
        self.manual_radio.grid(row=0, column=0, sticky='w', padx=(0, ReMapTheme.SPACING['lg']))
        self.file_radio.grid(row=0, column=1, sticky='w')
        
        # Manual input frame
        self.manual_frame.grid(row=1, column=0, columnspan=2, sticky='ew', 
                              pady=ReMapTheme.SPACING['md'])
        self.manual_frame.grid_columnconfigure(0, weight=1)
        
        # Text area with scrollbar
        self.text_frame.grid(row=0, column=0, sticky='ew')
        self.text_frame.grid_columnconfigure(0, weight=1)
        
        self.target_text.grid(row=0, column=0, sticky='ew')
        self.text_scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Example label
        self.example_label.grid(row=1, column=0, sticky='w', 
                               pady=(ReMapTheme.SPACING['xs'], 0))
        
        # File input frame (initially hidden)
        self.file_frame.grid(row=2, column=0, columnspan=2, sticky='ew',
                            pady=ReMapTheme.SPACING['md'])
        self.file_frame.grid_columnconfigure(0, weight=1)
        
        # File entry and browse button
        self.file_entry.grid(row=0, column=0, sticky='ew',
                            padx=(0, ReMapTheme.SPACING['sm']))
        self.browse_button.grid(row=0, column=1)
        
        # File info
        self.file_info_label.grid(row=1, column=0, columnspan=2, sticky='w',
                                 pady=(ReMapTheme.SPACING['xs'], 0))
        
        # Buttons frame
        self.buttons_frame.grid(row=3, column=0, columnspan=2, sticky='ew',
                               pady=ReMapTheme.SPACING['md'])
        
        self.validate_button.pack(side='left', padx=(0, ReMapTheme.SPACING['sm']))
        self.clear_button.pack(side='left', padx=(0, ReMapTheme.SPACING['sm']))
        self.sample_button.pack(side='left')
        
        # Status label
        self.status_label.grid(row=4, column=0, columnspan=2, sticky='w')
        
        # Configure grid weights
        self.grid_columnconfigure(0, weight=1)
        
        # Initial state
        self._on_input_method_change()
    
    def _setup_tooltips(self):
        """Set up tooltips for widgets."""
        ToolTip(self.manual_radio, "Enter targets manually in the text area")
        ToolTip(self.file_radio, "Load targets from a text file")
        ToolTip(self.target_text, 
               "Enter IP addresses, ranges, or specific ports:\n"
               "• 192.168.1.1\n"
               "• 192.168.1.1-100\n"
               "• 192.168.1.1:80,443\n"
               "• One target per line")
        ToolTip(self.validate_button, "Check if entered targets are valid")
        ToolTip(self.clear_button, "Clear all targets")
        ToolTip(self.sample_button, "Load sample targets for testing")
    
    def _on_input_method_change(self):
        """Handle input method change."""
        method = self.input_method_var.get()
        
        if method == "manual":
            # Show manual input widgets
            for widget in self.manual_frame.winfo_children():
                widget.configure(state='normal')
                        
            # Hide file input widgets
            for widget in self.file_frame.winfo_children():
                if isinstance(widget, ttk.Entry):
                    widget.configure(state='disabled')
                else:
                    widget.configure(state='disabled')
            
            self.target_text.configure(state='normal')
            
        else:  # file method
            # Hide manual input widgets
            self.target_text.configure(state='disabled')
            
            # Show file input widgets
            for widget in self.file_frame.winfo_children():
                widget.configure(state='normal')
            
            self.file_entry.configure(state='readonly')  # Keep readonly
        
        # Clear status
        self.status_var.set("")
    
    def _browse_file(self):
        """Browse for target file."""
        try:
            file_path = filedialog.askopenfilename(
                title="Select Target File",
                filetypes=[
                    ("Text files", "*.txt"),
                    ("All files", "*.*")
                ]
            )
            
            if file_path:
                self.file_path_var.set(file_path)
                self._load_file_info(file_path)
                
        except Exception as e:
            logger.error(f"Error browsing file: {e}")
            messagebox.showerror("Error", f"Error browsing file: {e}")
    
    def _load_file_info(self, file_path: str):
        """Load and display file information."""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            # Count non-empty lines
            target_count = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
            
            file_size = len(''.join(lines))
            
            self.file_info_var.set(f"File: {target_count} targets, {file_size} bytes")
            self.status_var.set(f"File loaded: {file_path}")
            
        except Exception as e:
            logger.error(f"Error loading file info: {e}")
            self.file_info_var.set("Error reading file")
            self.status_var.set(f"Error: {e}")
    
    def _validate_targets(self):
        """Validate entered targets."""
        try:
            targets = self.get_targets()
            
            if not targets:
                self.status_var.set("No targets to validate")
                return
            
            # Validate targets
            issues = TargetParser.validate_targets(targets)
            
            if not issues:
                self.status_var.set(f"✅ All {len(targets)} targets are valid")
            else:
                # Show issues in a dialog
                issues_text = "\n".join(issues)
                messagebox.showwarning("Validation Issues", issues_text)
                self.status_var.set(f"⚠️ {len(issues)} validation issue(s) found")
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            self.status_var.set(f"❌ Validation error: {e}")
            messagebox.showerror("Validation Error", str(e))
    
    def _load_sample(self):
        """Load sample targets for testing."""
        sample_targets = """# Sample targets for testing
192.168.1.1
10.0.0.1-10
172.16.1.100:80,443
127.0.0.1:8080"""
        
        if self.input_method_var.get() == "manual":
            self.target_text.delete(1.0, tk.END)
            self.target_text.insert(1.0, sample_targets)
            self.status_var.set("Sample targets loaded")
        else:
            messagebox.showinfo("Sample Targets", 
                              "Switch to manual input to use sample targets")
    
    def get_targets(self) -> List[Target]:
        """Get targets from current input method."""
        try:
            method = self.input_method_var.get()
            
            if method == "manual":
                # Get from text area
                text_content = self.target_text.get(1.0, tk.END).strip()
                if not text_content:
                    return []
                
                return TargetParser.parse_target_string(text_content)
            
            else:  # file method
                file_path = self.file_path_var.get()
                if not file_path:
                    raise ValueError("No file selected")
                
                return TargetParser.parse_target_file(file_path)
                
        except ValidationError as e:
            logger.warning(f"Target validation error: {e}")
            raise ValueError(f"Invalid targets: {e}")
        except Exception as e:
            logger.error(f"Error getting targets: {e}")
            raise
    
    def set_targets(self, targets: List[Target]):
        """Set targets in the input area."""
        try:
            # Convert targets to string format
            target_lines = []
            for target in targets:
                if target.has_specific_ports:
                    ports_str = ','.join(map(str, target.ports))
                    target_lines.append(f"{target.ip_address}:{ports_str}")
                else:
                    target_lines.append(target.ip_address)
            
            target_text = '\n'.join(target_lines)
            
            # Set to manual input
            self.input_method_var.set("manual")
            self._on_input_method_change()
            
            # Set text
            self.target_text.delete(1.0, tk.END)
            self.target_text.insert(1.0, target_text)
            
            self.status_var.set(f"Loaded {len(targets)} targets")
            
        except Exception as e:
            logger.error(f"Error setting targets: {e}")
            raise
    
    def clear(self):
        """Clear all input."""
        try:
            # Clear text area
            self.target_text.delete(1.0, tk.END)
            
            # Clear file path
            self.file_path_var.set("")
            self.file_info_var.set("")
            
            # Clear status
            self.status_var.set("")
            
            logger.debug("Target input cleared")
            
        except Exception as e:
            logger.error(f"Error clearing targets: {e}")
    
    def get_target_count(self) -> int:
        """Get count of current targets."""
        try:
            targets = self.get_targets()
            return len(targets)
        except:
            return 0
    
    def is_empty(self) -> bool:
        """Check if no targets are entered."""
        return self.get_target_count() == 0