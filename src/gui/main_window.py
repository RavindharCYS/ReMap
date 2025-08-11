"""Main GUI window for ReMap application."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Optional

from .target_input_frame import TargetInputFrame
from .scan_options_frame import ScanOptionsFrame
from .results_frame import ResultsFrame
from .settings_frame import SettingsFrame
from .progress_dialog import ProgressDialog
from .styles import configure_styles, ReMapTheme, icon_manager
from ..core.scanner import Scanner
from ..models.settings import ScanSettings
from ..models.scan_result import ScanResult
from ..analysis.security_analyzer import SecurityAnalyzer, SecurityAnalysisResult
from ..reports.export_manager import ExportManager
from ..utils.logger import setup_logger
from ..utils.config import ConfigManager

logger = setup_logger(__name__)

class MainWindow:
    """Main application window."""
    
    def __init__(self, root: tk.Tk, settings: ScanSettings):
        self.root = root
        self.settings = settings
        self.config_manager = ConfigManager()
        
        # Initialize core components
        self.scanner = Scanner(settings)
        self.security_analyzer = SecurityAnalyzer()
        self.export_manager = ExportManager()
        
        # State variables
        self.current_scan_result: Optional[ScanResult] = None
        self.current_analysis_result: Optional[SecurityAnalysisResult] = None
        self.progress_dialog: Optional[ProgressDialog] = None
        
        # Initialize GUI
        self._setup_gui()
        self._setup_callbacks()
        
        logger.info("Main window initialized")
    
    def _setup_gui(self):
        """Set up the main GUI layout."""
        # Configure styles
        configure_styles()
        
        # Configure root window
        self.root.configure(bg=ReMapTheme.COLORS['background'])
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create main layout
        self._create_main_layout()
        
        # Create status bar
        self._create_status_bar()
        
        # Set window icon and title
        try:
            # In production, you would set an actual icon file
            self.root.title("ReMap - Network Security Scanner")
        except Exception as e:
            logger.warning(f"Could not set window icon: {e}")
    
    def _create_menu_bar(self):
        """Create the application menu bar."""
        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # File menu
        file_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.new_scan, accelerator="Ctrl+N")
        file_menu.add_command(label="Load XML Results...", command=self.load_xml_results, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export Report...", command=self.export_report, accelerator="Ctrl+E")
        file_menu.add_command(label="Export Package...", command=self.export_package)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_application, accelerator="Ctrl+Q")
        
        # Scan menu
        scan_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Start Scan", command=self.start_scan, accelerator="F5")
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan, accelerator="Esc")
        scan_menu.add_separator()
        scan_menu.add_command(label="Quick Scan", command=lambda: self.quick_scan('fast'))
        scan_menu.add_command(label="Full Scan", command=lambda: self.quick_scan('all'))
        
        # Analysis menu
        analysis_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Run Security Analysis", command=self.run_analysis, accelerator="F6")
        analysis_menu.add_separator()
        analysis_menu.add_command(label="TLS Analysis", command=lambda: self.run_specific_analysis('tls'))
        analysis_menu.add_command(label="SSL Certificate Check", command=lambda: self.run_specific_analysis('ssl'))
        analysis_menu.add_command(label="SMB Analysis", command=lambda: self.run_specific_analysis('smb'))
        analysis_menu.add_command(label="Web Service Detection", command=lambda: self.run_specific_analysis('web'))
        
        # Tools menu
        tools_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Settings", command=self.show_settings, accelerator="Ctrl+,")
        tools_menu.add_command(label="View Logs", command=self.view_logs)
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear Results", command=self.clear_results)
        
        # Help menu
        help_menu = tk.Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
                
        # Bind keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self.new_scan())
        self.root.bind('<Control-o>', lambda e: self.load_xml_results())
        self.root.bind('<Control-e>', lambda e: self.export_report())
        self.root.bind('<Control-q>', lambda e: self.exit_application())
        self.root.bind('<F5>', lambda e: self.start_scan())
        self.root.bind('<Escape>', lambda e: self.stop_scan())
        self.root.bind('<F6>', lambda e: self.run_analysis())
        self.root.bind('<Control-comma>', lambda e: self.show_settings())
    
    def _create_main_layout(self):
        """Create the main application layout."""
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                                pady=ReMapTheme.SPACING['md'])
        
        # Create paned window for resizable layout
        self.main_paned = ttk.PanedWindow(self.main_container, orient='horizontal')
        self.main_paned.pack(fill='both', expand=True)
        
        # Left panel (input and options)
        self.left_panel = ttk.Frame(self.main_paned, style='Card.TFrame')
        self.main_paned.add(self.left_panel, weight=1)
        
        # Right panel (results)
        self.right_panel = ttk.Frame(self.main_paned, style='Card.TFrame')
        self.main_paned.add(self.right_panel, weight=2)
        
        # Configure left panel
        self._setup_left_panel()
        
        # Configure right panel
        self._setup_right_panel()
    
    def _setup_left_panel(self):
        """Set up the left panel with input controls."""
        # Create notebook for tabbed interface
        self.left_notebook = ttk.Notebook(self.left_panel, style='Custom.TNotebook')
        self.left_notebook.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                               pady=ReMapTheme.SPACING['md'])
        
        # Scan tab
        self.scan_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.scan_tab, text=f"{icon_manager.get_icon('scan')} Scan")
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.left_notebook)
        self.left_notebook.add(self.settings_tab, text=f"{icon_manager.get_icon('settings')} Settings")
        
        # Create frames for scan tab
        self._create_scan_tab()
        
        # Create settings frame
        self.settings_frame = SettingsFrame(self.settings_tab, self.settings, self._on_settings_changed)
        self.settings_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                                pady=ReMapTheme.SPACING['sm'])
    
    def _create_scan_tab(self):
        """Create the scan tab contents."""
        # Target input frame
        self.target_input_frame = TargetInputFrame(self.scan_tab)
        self.target_input_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                    pady=ReMapTheme.SPACING['sm'])
        
        # Scan options frame
        self.scan_options_frame = ScanOptionsFrame(self.scan_tab)
        self.scan_options_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                    pady=ReMapTheme.SPACING['sm'])
        
        # Action buttons frame
        self._create_action_buttons()
        
        # Progress frame
        self._create_progress_frame()
    
    def _create_action_buttons(self):
        """Create action buttons."""
        button_frame = ttk.Frame(self.scan_tab)
        button_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                         pady=ReMapTheme.SPACING['md'])
        
        # Start scan button
        self.start_button = ttk.Button(button_frame, text="Start Scan", 
                                      style='Primary.TButton', command=self.start_scan)
        self.start_button.pack(side='left', padx=(0, ReMapTheme.SPACING['sm']))
        
        # Stop scan button
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", 
                                     style='Danger.TButton', command=self.stop_scan, 
                                     state='disabled')
        self.stop_button.pack(side='left', padx=(0, ReMapTheme.SPACING['sm']))
        
        # Load XML button
        self.load_xml_button = ttk.Button(button_frame, text="Load XML", 
                                         command=self.load_xml_results)
        self.load_xml_button.pack(side='left', padx=(0, ReMapTheme.SPACING['sm']))
        
        # Run analysis button
        self.analyze_button = ttk.Button(button_frame, text="Analyze", 
                                        style='Success.TButton', command=self.run_analysis,
                                        state='disabled')
        self.analyze_button.pack(side='left')
    
    def _create_progress_frame(self):
        """Create progress display frame."""
        self.progress_frame = ttk.LabelFrame(self.scan_tab, text="Progress")
        self.progress_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                pady=ReMapTheme.SPACING['sm'])
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.progress_frame, variable=self.progress_var,
                                           style='Custom.Horizontal.TProgressbar')
        self.progress_bar.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                              pady=ReMapTheme.SPACING['sm'])
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(self.progress_frame, textvariable=self.status_var)
        self.status_label.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                              pady=(0, ReMapTheme.SPACING['sm']))
    
    def _setup_right_panel(self):
        """Set up the right panel with results."""
        # Create notebook for results
        self.results_notebook = ttk.Notebook(self.right_panel, style='Custom.TNotebook')
        self.results_notebook.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                                  pady=ReMapTheme.SPACING['md'])
        
        # Results tab
        self.results_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.results_tab, text=f"{icon_manager.get_icon('report')} Results")
        
        # Analysis tab
        self.analysis_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.analysis_tab, text=f"{icon_manager.get_icon('security')} Analysis")
        
        # Web services tab
        self.web_services_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.web_services_tab, text=f"{icon_manager.get_icon('web')} Web Services")
        
        # Create results frame
        self.results_frame = ResultsFrame(self.results_tab)
        self.results_frame.pack(fill='both', expand=True)
        
        # Create analysis results area
        self._create_analysis_tab()
        
        # Create web services area
        self._create_web_services_tab()
    
    def _create_analysis_tab(self):
        """Create analysis results tab."""
        # Analysis summary frame
        summary_frame = ttk.LabelFrame(self.analysis_tab, text="Analysis Summary")
        summary_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                          pady=ReMapTheme.SPACING['sm'])
        
        self.analysis_summary_text = tk.Text(summary_frame, height=6, state='disabled',
                                            font=ReMapTheme.FONTS['code'])
        self.analysis_summary_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                       pady=ReMapTheme.SPACING['sm'])
        
        # Vulnerabilities frame
        vuln_frame = ttk.LabelFrame(self.analysis_tab, text="Vulnerabilities")
        vuln_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                       pady=ReMapTheme.SPACING['sm'])
        
        # Create vulnerabilities treeview
        self._create_vulnerabilities_treeview(vuln_frame)
    
    def _create_vulnerabilities_treeview(self, parent):
        """Create vulnerabilities treeview."""
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                       pady=ReMapTheme.SPACING['sm'])
        
        columns = ('Host', 'Port', 'Vulnerability', 'Severity', 'Details')
        self.vulnerabilities_tree = ttk.Treeview(tree_frame, columns=columns, 
                                               show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.vulnerabilities_tree.column('#0', width=0, stretch=False)
        self.vulnerabilities_tree.column('Host', width=120, anchor='center')
        self.vulnerabilities_tree.column('Port', width=60, anchor='center')
        self.vulnerabilities_tree.column('Vulnerability', width=200)
        self.vulnerabilities_tree.column('Severity', width=80, anchor='center')
        self.vulnerabilities_tree.column('Details', width=300)
        
        # Configure headings
        for col in columns:
            self.vulnerabilities_tree.heading(col, text=col, anchor='w')
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.vulnerabilities_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.vulnerabilities_tree.xview)
        
        self.vulnerabilities_tree.configure(yscrollcommand=v_scrollbar.set,
                                           xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        self.vulnerabilities_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
    
    def _create_web_services_tab(self):
        """Create web services tab."""
        # Web services list frame
        web_frame = ttk.LabelFrame(self.web_services_tab, text="Detected Web Services")
        web_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                      pady=ReMapTheme.SPACING['sm'])
        
        # Create web services treeview
        self._create_web_services_treeview(web_frame)
        
        # Web service details frame
        details_frame = ttk.LabelFrame(self.web_services_tab, text="Service Details")
        details_frame.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                          pady=ReMapTheme.SPACING['sm'])
        
        self.web_details_text = tk.Text(details_frame, height=8, state='disabled',
                                       font=ReMapTheme.FONTS['code'])
        self.web_details_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                  pady=ReMapTheme.SPACING['sm'])
    
    def _create_web_services_treeview(self, parent):
        """Create web services treeview."""
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                       pady=ReMapTheme.SPACING['sm'])
        
        columns = ('Host', 'Port', 'URL', 'Server', 'Applications')
        self.web_services_tree = ttk.Treeview(tree_frame, columns=columns, 
                                            show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.web_services_tree.column('#0', width=0, stretch=False)
        self.web_services_tree.column('Host', width=120, anchor='center')
        self.web_services_tree.column('Port', width=60, anchor='center')
        self.web_services_tree.column('URL', width=250)
        self.web_services_tree.column('Server', width=150)
        self.web_services_tree.column('Applications', width=200)
        
        # Configure headings
        for col in columns:
            self.web_services_tree.heading(col, text=col, anchor='w')
        
        # Bind selection event
        self.web_services_tree.bind('<<TreeviewSelect>>', self._on_web_service_select)
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.web_services_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.web_services_tree.xview)
        
        self.web_services_tree.configure(yscrollcommand=v_scrollbar.set,
                                        xscrollcommand=h_scrollbar.set)
        
        # Pack widgets
        self.web_services_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
    
    def _create_status_bar(self):
        """Create the status bar."""
        self.status_frame = ttk.Frame(self.root, style='Status.TFrame')
        self.status_frame.pack(side='bottom', fill='x')
        
        # Status message
        self.status_message = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.status_frame, textvariable=self.status_message)
        status_label.pack(side='left', padx=ReMapTheme.SPACING['md'])
        
        # Scanner status
        self.scanner_status = tk.StringVar(value="Idle")
        scanner_label = ttk.Label(self.status_frame, textvariable=self.scanner_status,
                                 style='Muted.TLabel')
        scanner_label.pack(side='right', padx=ReMapTheme.SPACING['md'])
    
    def _setup_callbacks(self):
        """Set up callbacks for scanner and analyzer."""
        # Scanner callbacks
        self.scanner.set_progress_callback(self._on_scan_progress)
        self.scanner.set_completion_callback(self._on_scan_complete)
        
        # Security analyzer callbacks
        self.security_analyzer.set_progress_callback(self._on_analysis_progress)
        
        # Window close callback
        self.root.protocol("WM_DELETE_WINDOW", self.exit_application)
    
    # Event handlers
    def _on_scan_progress(self, message: str):
        """Handle scan progress updates."""
        self.status_var.set(message)
        self.status_message.set(f"Scanning: {message}")
        self.scanner_status.set("Running")
        self.root.update_idletasks()
    
    def _on_scan_complete(self, scan_result: Optional[ScanResult], success: bool):
        """Handle scan completion."""
        if success and scan_result:
            self.current_scan_result = scan_result
            self.results_frame.display_results(scan_result)
            self.analyze_button.configure(state='normal')
            
            # Update status
            self.status_var.set(f"Scan completed: {scan_result.hosts_up}/{scan_result.total_hosts} hosts up")
            self.status_message.set("Scan completed successfully")
            
            # Show results tab
            self.results_notebook.select(self.results_tab)
            
        else:
            self.status_var.set("Scan failed")
            self.status_message.set("Scan failed - check logs for details")
        
        # Update UI state
        self._set_scan_state(False)
        self.scanner_status.set("Idle")
    
    def _on_analysis_progress(self, message: str):
        """Handle analysis progress updates."""
        self.status_message.set(f"Analyzing: {message}")
        self.root.update_idletasks()
    
    def _on_analysis_complete(self, analysis_result: SecurityAnalysisResult):
        """Handle analysis completion."""
        self.current_analysis_result = analysis_result
        self._update_analysis_display()
        
        self.status_message.set("Analysis completed")
        
        # Show analysis tab
        self.results_notebook.select(self.analysis_tab)
    
    def _on_settings_changed(self, new_settings: ScanSettings):
        """Handle settings changes."""
        self.settings = new_settings
        self.scanner.update_settings(new_settings)
        self.config_manager.save_settings(new_settings)
        
        logger.info("Settings updated")
    
    def _on_web_service_select(self, event):
        """Handle web service selection."""
        selection = self.web_services_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        item_data = self.web_services_tree.item(item_id)
        
        # Get service details (this would be implemented based on stored data)
        details = "Service details would be displayed here"
        
        self.web_details_text.configure(state='normal')
        self.web_details_text.delete(1.0, tk.END)
        self.web_details_text.insert(1.0, details)
        self.web_details_text.configure(state='disabled')
    
    # Action methods
    def new_scan(self):
        """Start a new scan."""
        # Clear previous results
        self.clear_results()
        
        # Reset UI
        self.target_input_frame.clear()
        self.status_message.set("Ready for new scan")
    
    def start_scan(self):
        """Start a network scan."""
        try:
            # Get targets from input frame
            targets = self.target_input_frame.get_targets()
            if not targets:
                messagebox.showerror("Error", "Please enter targets to scan")
                return
            
            # Get scan options
            scan_options = self.scan_options_frame.get_options()
            
            # Update UI state
            self._set_scan_state(True)
            
            # Start scan
            success = self.scanner.start_scan(targets, scan_options['scan_type'])
            if not success:
                messagebox.showerror("Error", "Failed to start scan")
                self._set_scan_state(False)
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            messagebox.showerror("Error", f"Failed to start scan: {e}")
            self._set_scan_state(False)
    
    def stop_scan(self):
        """Stop the current scan."""
        try:
            self.scanner.cancel_scan()
            self.status_message.set("Stopping scan...")
            
        except Exception as e:
            logger.error(f"Failed to stop scan: {e}")
            messagebox.showerror("Error", f"Failed to stop scan: {e}")
    
    def quick_scan(self, scan_type: str):
        """Perform a quick scan with predefined settings."""
        # Set scan type in options frame
        self.scan_options_frame.set_scan_type(scan_type)
        
        # Start scan
        self.start_scan()
    
    def load_xml_results(self):
        """Load XML scan results from file."""
        try:
            file_path = filedialog.askopenfilename(
                title="Load XML Results",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
                initialdir=str(self.config_manager.config_dir / "scans")
            )
            
            if file_path:
                success = self.scanner.load_xml_results(file_path)
                if success:
                    self.current_scan_result = self.scanner.current_result
                    self.results_frame.display_results(self.current_scan_result)
                    self.analyze_button.configure(state='normal')
                    
                    self.status_message.set(f"Loaded results from {file_path}")
                else:
                    messagebox.showerror("Error", "Failed to load XML file")
            
        except Exception as e:
            logger.error(f"Failed to load XML results: {e}")
            messagebox.showerror("Error", f"Failed to load XML results: {e}")
    
    def run_analysis(self):
        """Run security analysis on current results."""
        if not self.current_scan_result:
            messagebox.showerror("Error", "No scan results available for analysis")
            return
        
        try:
            # Get analysis options from settings frame
            analysis_options = self.settings_frame.get_analysis_options()
            
            self.status_message.set("Running security analysis...")
            
            # Run analysis in separate thread
            analysis_thread = threading.Thread(
                target=self._run_analysis_thread,
                args=(analysis_options,),
                daemon=True
            )
            analysis_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start analysis: {e}")
            messagebox.showerror("Error", f"Failed to start analysis: {e}")
    
    def _run_analysis_thread(self, analysis_options):
        """Run analysis in separate thread."""
        try:
            analysis_result = self.security_analyzer.analyze_scan_results(
                self.current_scan_result, analysis_options
            )
            
            # Update UI in main thread
            self.root.after(0, lambda: self._on_analysis_complete(analysis_result))
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {e}"))
    
    def run_specific_analysis(self, analysis_type: str):
        """Run specific type of analysis."""
        if not self.current_scan_result:
            messagebox.showerror("Error", "No scan results available for analysis")
            return
        
        analysis_options = {
            'tls_check': analysis_type == 'tls',
            'ssl_check': analysis_type == 'ssl',
            'smb_check': analysis_type == 'smb',
            'web_detection': analysis_type == 'web'
        }
        
        self._run_analysis_thread(analysis_options)
    
    def export_report(self):
        """Export scan and analysis results as report."""
        if not self.current_scan_result:
            messagebox.showerror("Error", "No results to export")
            return
        
        try:
            # Show file dialog
            file_path = filedialog.asksaveasfilename(
                title="Export Report",
                defaultextension=".html",
                filetypes=[
                    ("HTML files", "*.html"),
                    ("JSON files", "*.json"),
                    ("CSV files", "*.csv"),
                    ("XML files", "*.xml"),
                    ("Text files", "*.txt")
                ]
            )
            
            if file_path:
                # Determine format from extension
                format_type = file_path.split('.')[-1].lower()
                
                # Export report
                exported_path = self.export_manager.report_generator.generate_report(
                    self.current_scan_result,
                    self.current_analysis_result,
                    format_type,
                    file_path
                )
                
                if exported_path:
                    messagebox.showinfo("Success", f"Report exported to:\n{exported_path}")
                    self.status_message.set(f"Report exported: {exported_path}")
                else:
                    messagebox.showerror("Error", "Failed to export report")
            
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            messagebox.showerror("Error", f"Failed to export report: {e}")
    
    def export_package(self):
        """Export comprehensive package with all formats."""
        if not self.current_scan_result:
            messagebox.showerror("Error", "No results to export")
            return
        
        try:
            # Show directory dialog
            directory = filedialog.askdirectory(
                title="Select Export Directory"
            )
            
            if directory:
                self.status_message.set("Creating export package...")
                
                # Create export package in separate thread
                export_thread = threading.Thread(
                    target=self._create_export_package_thread,
                    args=(directory,),
                    daemon=True
                )
                export_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to create export package: {e}")
            messagebox.showerror("Error", f"Failed to create export package: {e}")
    
    def _create_export_package_thread(self, directory):
        """Create export package in separate thread."""
        try:
            package_path = self.export_manager.create_export_package(
                self.current_scan_result,
                self.current_analysis_result,
                f"{directory}/remap_export_package.zip"
            )
            
            # Update UI in main thread
            self.root.after(0, lambda: messagebox.showinfo(
                "Success", f"Export package created:\n{package_path}"
            ))
            self.root.after(0, lambda: self.status_message.set("Export package created"))
            
        except Exception as e:
            logger.error(f"Export package creation failed: {e}")
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"Failed to create export package: {e}"
            ))
    
    def show_settings(self):
        """Show settings dialog."""
        # Switch to settings tab
        self.left_notebook.select(self.settings_tab)
    
    def view_logs(self):
        """Show log viewer window."""
        try:
            from .log_viewer import LogViewerWindow
            LogViewerWindow(self.root)
        except ImportError:
            messagebox.showinfo("Info", "Log viewer not available")
    
    def clear_results(self):
        """Clear all results and reset UI."""
        try:
            result = messagebox.askyesno(
                "Confirm Clear",
                "This will clear all scan results and analysis data. Continue?"
            )
            
            if result:
                self.current_scan_result = None
                self.current_analysis_result = None
                
                # Clear display frames
                self.results_frame.clear_results()
                self._clear_analysis_display()
                
                # Reset UI state
                self.analyze_button.configure(state='disabled')
                self.status_message.set("Results cleared")
                
        except Exception as e:
            logger.error(f"Failed to clear results: {e}")
            messagebox.showerror("Error", f"Failed to clear results: {e}")
    
    def show_documentation(self):
        """Show documentation."""
        messagebox.showinfo("Documentation", 
                           "Documentation is available online at:\nhttps://github.com/your-repo/remap")
    
    def show_about(self):
        """Show about dialog."""
        about_text = """ReMap - Network Security Scanner
Version 1.0

A comprehensive network scanning and security analysis tool
built with Python and Tkinter.

Features:
• Nmap integration for network scanning
• Security analysis (TLS, SSL, SMB)
• Web service detection
• Multiple report formats
• Customizable scan options

© 2024 ReMap Project"""
        
        messagebox.showinfo("About ReMap", about_text)
    
    def exit_application(self):
        """Exit the application."""
        try:
            # Check if scan is running
            if self.scanner.is_scanning():
                result = messagebox.askyesno(
                    "Confirm Exit",
                    "A scan is currently running. Stop the scan and exit?"
                )
                
                if result:
                    self.scanner.cancel_scan()
                else:
                    return
            
            # Save settings
            self.config_manager.save_settings(self.settings)
            
            # Close application
            self.root.quit()
            self.root.destroy()
            
        except Exception as e:
            logger.error(f"Error during application exit: {e}")
            self.root.quit()
            self.root.destroy()
    
    # UI helper methods
    def _set_scan_state(self, scanning: bool):
        """Update UI state based on scanning status."""
        if scanning:
            self.start_button.configure(state='disabled')
            self.stop_button.configure(state='normal')
            self.load_xml_button.configure(state='disabled')
            self.progress_bar.configure(mode='indeterminate')
            self.progress_bar.start()
        else:
            self.start_button.configure(state='normal')
            self.stop_button.configure(state='disabled')
            self.load_xml_button.configure(state='normal')
            self.progress_bar.stop()
            self.progress_bar.configure(mode='determinate', value=0)
    
    def _update_analysis_display(self):
        """Update analysis results display."""
        if not self.current_analysis_result:
            return
        
        # Update summary
        summary = self.current_analysis_result.get_summary()
        summary_text = f"""Analysis Summary:
Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}
  Critical: {summary.get('severity_breakdown', {}).get('critical', 0)}
  High: {summary.get('severity_breakdown', {}).get('high', 0)}
  Medium: {summary.get('severity_breakdown', {}).get('medium', 0)}
  Low: {summary.get('severity_breakdown', {}).get('low', 0)}

TLS Checks: {summary.get('tls_checks', 0)}
SSL Checks: {summary.get('ssl_checks', 0)}
SMB Checks: {summary.get('smb_checks', 0)}
Web Services: {summary.get('web_services_found', 0)}

Analysis Duration: {summary.get('analysis_duration', 0):.1f}s"""
        
        self.analysis_summary_text.configure(state='normal')
        self.analysis_summary_text.delete(1.0, tk.END)
        self.analysis_summary_text.insert(1.0, summary_text)
        self.analysis_summary_text.configure(state='disabled')
        
        # Update vulnerabilities tree
        self._update_vulnerabilities_tree()
        
        # Update web services tree
        self._update_web_services_tree()
    
    def _update_vulnerabilities_tree(self):
        """Update vulnerabilities treeview."""
        # Clear existing items
        for item in self.vulnerabilities_tree.get_children():
            self.vulnerabilities_tree.delete(item)
        
        if not self.current_analysis_result:
            return
        
        # Add vulnerabilities
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'low': '#28a745'
        }
        
        for vuln in self.current_analysis_result.vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            port = vuln.get('port', '')
            
            item_id = self.vulnerabilities_tree.insert('', 'end', values=(
                vuln['host'],
                port,
                vuln['vulnerability'],
                vuln.get('severity', 'Medium').title(),
                vuln.get('details', '')[:100] + '...' if len(vuln.get('details', '')) > 100 else vuln.get('details', '')
            ))
            
            # Set row color based on severity
            if severity in severity_colors:
                self.vulnerabilities_tree.set(item_id, 'Severity', vuln.get('severity', 'Medium').title())
    
    def _update_web_services_tree(self):
        """Update web services treeview."""
        # Clear existing items
        for item in self.web_services_tree.get_children():
            self.web_services_tree.delete(item)
        
        if not self.current_analysis_result:
            return
        
        # Add web services
        for web_service in self.current_analysis_result.web_services:
            result = web_service.get('result', {})
            server_info = result.get('server_info', {})
            applications = result.get('applications', [])
            urls = result.get('urls', [])
            
            main_url = urls[0] if urls else f"http://{web_service['host']}:{web_service['port']}"
            app_names = ', '.join([app.get('name', '') for app in applications])
            
            self.web_services_tree.insert('', 'end', values=(
                web_service['host'],
                web_service['port'],
                main_url,
                server_info.get('server', 'Unknown'),
                app_names or 'Unknown'
            ))
    
    def _clear_analysis_display(self):
        """Clear analysis display."""
        # Clear summary
        self.analysis_summary_text.configure(state='normal')
        self.analysis_summary_text.delete(1.0, tk.END)
        self.analysis_summary_text.configure(state='disabled')
        
        # Clear vulnerabilities
        for item in self.vulnerabilities_tree.get_children():
            self.vulnerabilities_tree.delete(item)
        
        # Clear web services
        for item in self.web_services_tree.get_children():
            self.web_services_tree.delete(item)
        
        # Clear web details
        self.web_details_text.configure(state='normal')
        self.web_details_text.delete(1.0, tk.END)
        self.web_details_text.configure(state='disabled')