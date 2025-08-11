"""Results frame for displaying scan and analysis results."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
from typing import Optional, List, Dict, Any
import json

from .styles import ReMapTheme, ToolTip, icon_manager, create_status_colors, create_severity_colors
from ..models.scan_result import ScanResult, Host, Port
from ..analysis.security_analyzer import SecurityAnalysisResult
from ..core.xml_parser import NmapXMLParser
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ResultsFrame(ttk.Frame):
    """Frame for displaying scan results with multiple views."""
    
    def __init__(self, parent):
        super().__init__(parent)
        
        self.current_scan_result: Optional[ScanResult] = None
        self.current_analysis_result: Optional[SecurityAnalysisResult] = None
        self.status_colors = create_status_colors()
        self.severity_colors = create_severity_colors()
        
        self._create_widgets()
        self._setup_layout()
        self._setup_bindings()
        
        logger.debug("Results frame initialized")
    
    def _create_widgets(self):
        """Create result display widgets."""
        # Create notebook for different result views
        self.results_notebook = ttk.Notebook(self, style='Custom.TNotebook')
        
        # Summary tab
        self.summary_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.summary_tab, text=f"{icon_manager.get_icon('info')} Summary")
        
        # Hosts tab
        self.hosts_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.hosts_tab, text=f"{icon_manager.get_icon('network')} Hosts")
        
        # Services tab
        self.services_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.services_tab, text=f"{icon_manager.get_icon('scan')} Services")
        
        # Vulnerabilities tab
        self.vulnerabilities_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.vulnerabilities_tab, text=f"{icon_manager.get_icon('security')} Vulnerabilities")
        
        # Web Services tab
        self.web_services_tab = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.web_services_tab, text=f"{icon_manager.get_icon('web')} Web Services")
        
        # Create tab contents
        self._create_summary_tab()
        self._create_hosts_tab()
        self._create_services_tab()
        self._create_vulnerabilities_tab()
        self._create_web_services_tab()
        
        # Action bar
        self._create_action_bar()
    
    def _create_summary_tab(self):
        """Create summary tab content."""
        # Summary statistics frame
        stats_frame = ttk.LabelFrame(self.summary_tab, text="Scan Statistics")
        stats_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], pady=ReMapTheme.SPACING['md'])
        
        # Create stats display
        self.stats_text = tk.Text(stats_frame, height=8, state='disabled',
                                 font=ReMapTheme.FONTS['code'], wrap=tk.WORD)
        
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient='vertical', 
                                       command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=stats_scrollbar.set)
        
        self.stats_text.pack(side='left', fill='both', expand=True,
                           padx=ReMapTheme.SPACING['sm'], pady=ReMapTheme.SPACING['sm'])
        stats_scrollbar.pack(side='right', fill='y')
        
        # Top services frame
        services_frame = ttk.LabelFrame(self.summary_tab, text="Top Services")
        services_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                           pady=ReMapTheme.SPACING['md'])
        
        # Top services treeview
        self._create_top_services_tree(services_frame)
        
        # Scan timeline frame
        timeline_frame = ttk.LabelFrame(self.summary_tab, text="Scan Information")
        timeline_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                           pady=ReMapTheme.SPACING['md'])
        
        self.timeline_text = tk.Text(timeline_frame, height=4, state='disabled',
                                    font=ReMapTheme.FONTS['default'], wrap=tk.WORD)
        self.timeline_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                               pady=ReMapTheme.SPACING['sm'])
    
    def _create_top_services_tree(self, parent):
        """Create top services treeview."""
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                       pady=ReMapTheme.SPACING['sm'])
        
        columns = ('Service', 'Count', 'Percentage')
        self.top_services_tree = ttk.Treeview(tree_frame, columns=columns, 
                                             show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.top_services_tree.column('#0', width=0, stretch=False)
        self.top_services_tree.column('Service', width=150, anchor='w')
        self.top_services_tree.column('Count', width=100, anchor='center')
        self.top_services_tree.column('Percentage', width=100, anchor='center')
        
        # Configure headings
        for col in columns:
            self.top_services_tree.heading(col, text=col, anchor='w')
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.top_services_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.top_services_tree.xview)
        
        self.top_services_tree.configure(yscrollcommand=v_scrollbar.set,
                                        xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.top_services_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
    
    def _create_hosts_tab(self):
        """Create hosts tab content."""
        # Hosts filter frame
        filter_frame = ttk.Frame(self.hosts_tab)
        filter_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                         pady=ReMapTheme.SPACING['md'])
        
        # Filter options
        ttk.Label(filter_frame, text="Show:").pack(side='left')
        
        self.host_filter_var = tk.StringVar(value="all")
        filter_options = [("All Hosts", "all"), ("Up Only", "up"), ("Down Only", "down")]
        
        for text, value in filter_options:
            ttk.Radiobutton(filter_frame, text=text, variable=self.host_filter_var, 
                           value=value, command=self._filter_hosts).pack(side='left', 
                           padx=ReMapTheme.SPACING['md'])
        
        # Search frame
        search_frame = ttk.Frame(filter_frame)
        search_frame.pack(side='right')
        
        ttk.Label(search_frame, text="Search:").pack(side='left')
        self.host_search_var = tk.StringVar()
        self.host_search_var.trace('w', self._on_host_search)
        
        search_entry = ttk.Entry(search_frame, textvariable=self.host_search_var,
                                style='Custom.TEntry', width=20)
        search_entry.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        # Hosts treeview
        self._create_hosts_tree()
    
    def _create_hosts_tree(self):
        """Create hosts treeview."""
        tree_frame = ttk.Frame(self.hosts_tab)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                       pady=ReMapTheme.SPACING['md'])
        
        columns = ('IP Address', 'Hostname', 'Status', 'Open Ports', 'OS', 'Last Seen')
        self.hosts_tree = ttk.Treeview(tree_frame, columns=columns, 
                                      show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.hosts_tree.column('#0', width=0, stretch=False)
        self.hosts_tree.column('IP Address', width=120, anchor='center')
        self.hosts_tree.column('Hostname', width=150, anchor='w')
        self.hosts_tree.column('Status', width=80, anchor='center')
        self.hosts_tree.column('Open Ports', width=100, anchor='center')
        self.hosts_tree.column('OS', width=200, anchor='w')
        self.hosts_tree.column('Last Seen', width=150, anchor='center')
        
        # Configure headings
        for col in columns:
            self.hosts_tree.heading(col, text=col, anchor='w')
        
        # Bind events
        self.hosts_tree.bind('<<TreeviewSelect>>', self._on_host_select)
        self.hosts_tree.bind('<Double-1>', self._on_host_double_click)
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.hosts_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.hosts_tree.xview)
        
        self.hosts_tree.configure(yscrollcommand=v_scrollbar.set,
                                 xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.hosts_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Host details frame
        details_frame = ttk.LabelFrame(self.hosts_tab, text="Host Details")
        details_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                          pady=ReMapTheme.SPACING['md'])
        
        self.host_details_text = tk.Text(details_frame, height=6, state='disabled',
                                        font=ReMapTheme.FONTS['code'], wrap=tk.WORD)
        self.host_details_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                   pady=ReMapTheme.SPACING['sm'])
    
    def _create_services_tab(self):
        """Create services tab content."""
        # Services filter frame
        services_filter_frame = ttk.Frame(self.services_tab)
        services_filter_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                                  pady=ReMapTheme.SPACING['md'])
        
        # Port state filter
        ttk.Label(services_filter_frame, text="Port State:").pack(side='left')
        
        self.port_filter_var = tk.StringVar(value="open")
        port_filter_options = [("Open", "open"), ("All", "all")]
        
        for text, value in port_filter_options:
            ttk.Radiobutton(services_filter_frame, text=text, 
                           variable=self.port_filter_var, value=value, 
                           command=self._filter_services).pack(side='left', 
                           padx=ReMapTheme.SPACING['md'])
        
        # Service search
        search_frame = ttk.Frame(services_filter_frame)
        search_frame.pack(side='right')
        
        ttk.Label(search_frame, text="Filter Service:").pack(side='left')
        self.service_search_var = tk.StringVar()
        self.service_search_var.trace('w', self._on_service_search)
        
        service_search_entry = ttk.Entry(search_frame, textvariable=self.service_search_var,
                                        style='Custom.TEntry', width=15)
        service_search_entry.pack(side='left', padx=(ReMapTheme.SPACING['sm'], 0))
        
        # Services treeview
        self._create_services_tree()
    
    def _create_services_tree(self):
        """Create services treeview."""
        tree_frame = ttk.Frame(self.services_tab)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                       pady=ReMapTheme.SPACING['md'])
        
        columns = ('Host', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Extra Info')
        self.services_tree = ttk.Treeview(tree_frame, columns=columns, 
                                         show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.services_tree.column('#0', width=0, stretch=False)
        self.services_tree.column('Host', width=120, anchor='center')
        self.services_tree.column('Port', width=60, anchor='center')
        self.services_tree.column('Protocol', width=80, anchor='center')
        self.services_tree.column('State', width=80, anchor='center')
        self.services_tree.column('Service', width=100, anchor='w')
        self.services_tree.column('Version', width=200, anchor='w')
        self.services_tree.column('Extra Info', width=200, anchor='w')
        
        # Configure headings
        for col in columns:
            self.services_tree.heading(col, text=col, anchor='w')
        
        # Bind events
        self.services_tree.bind('<<TreeviewSelect>>', self._on_service_select)
        self.services_tree.bind('<Double-1>', self._on_service_double_click)
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.services_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.services_tree.xview)
        
        self.services_tree.configure(yscrollcommand=v_scrollbar.set,
                                    xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.services_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Service details frame
        service_details_frame = ttk.LabelFrame(self.services_tab, text="Service Details")
        service_details_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                                  pady=ReMapTheme.SPACING['md'])
        
        self.service_details_text = tk.Text(service_details_frame, height=6, state='disabled',
                                          font=ReMapTheme.FONTS['code'], wrap=tk.WORD)
        self.service_details_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                     pady=ReMapTheme.SPACING['sm'])
    
    def _create_vulnerabilities_tab(self):
        """Create vulnerabilities tab content."""
        # Vulnerability filter frame
        vuln_filter_frame = ttk.Frame(self.vulnerabilities_tab)
        vuln_filter_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                              pady=ReMapTheme.SPACING['md'])
        
        # Severity filter
        ttk.Label(vuln_filter_frame, text="Severity:").pack(side='left')
        
        self.vuln_filter_var = tk.StringVar(value="all")
        vuln_filter_options = [("All", "all"), ("Critical", "critical"), 
                              ("High", "high"), ("Medium", "medium"), ("Low", "low")]
        
        for text, value in vuln_filter_options:
            ttk.Radiobutton(vuln_filter_frame, text=text, 
                           variable=self.vuln_filter_var, value=value, 
                           command=self._filter_vulnerabilities).pack(side='left', 
                           padx=ReMapTheme.SPACING['sm'])
        
        # Vulnerabilities treeview
        self._create_vulnerabilities_tree()
    
    def _create_vulnerabilities_tree(self):
        """Create vulnerabilities treeview."""
        tree_frame = ttk.Frame(self.vulnerabilities_tab)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                       pady=ReMapTheme.SPACING['md'])
        
        columns = ('Host', 'Port', 'Vulnerability', 'Severity', 'Details')
        self.vulnerabilities_tree = ttk.Treeview(tree_frame, columns=columns, 
                                               show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.vulnerabilities_tree.column('#0', width=0, stretch=False)
        self.vulnerabilities_tree.column('Host', width=120, anchor='center')
        self.vulnerabilities_tree.column('Port', width=60, anchor='center')
        self.vulnerabilities_tree.column('Vulnerability', width=200, anchor='w')
        self.vulnerabilities_tree.column('Severity', width=80, anchor='center')
        self.vulnerabilities_tree.column('Details', width=300, anchor='w')
        
        # Configure headings
        for col in columns:
            self.vulnerabilities_tree.heading(col, text=col, anchor='w')
        
        # Bind events
        self.vulnerabilities_tree.bind('<<TreeviewSelect>>', self._on_vulnerability_select)
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.vulnerabilities_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.vulnerabilities_tree.xview)
        
        self.vulnerabilities_tree.configure(yscrollcommand=v_scrollbar.set,
                                           xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.vulnerabilities_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Vulnerability details frame
        vuln_details_frame = ttk.LabelFrame(self.vulnerabilities_tab, text="Vulnerability Details")
        vuln_details_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                               pady=ReMapTheme.SPACING['md'])
        
        self.vuln_details_text = tk.Text(vuln_details_frame, height=8, state='disabled',
                                        font=ReMapTheme.FONTS['code'], wrap=tk.WORD)
        self.vuln_details_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                   pady=ReMapTheme.SPACING['sm'])
    
    def _create_web_services_tab(self):
        """Create web services tab content."""
        # Web services treeview
        tree_frame = ttk.Frame(self.web_services_tab)
        tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['md'], 
                       pady=ReMapTheme.SPACING['md'])
        
        columns = ('Host', 'Port', 'URL', 'Server', 'Applications', 'Status')
        self.web_services_tree = ttk.Treeview(tree_frame, columns=columns, 
                                            show='tree headings', style='Custom.Treeview')
        
        # Configure columns
        self.web_services_tree.column('#0', width=0, stretch=False)
        self.web_services_tree.column('Host', width=120, anchor='center')
        self.web_services_tree.column('Port', width=60, anchor='center')
        self.web_services_tree.column('URL', width=250, anchor='w')
        self.web_services_tree.column('Server', width=150, anchor='w')
        self.web_services_tree.column('Applications', width=200, anchor='w')
        self.web_services_tree.column('Status', width=100, anchor='center')
        
        # Configure headings
        for col in columns:
            self.web_services_tree.heading(col, text=col, anchor='w')
        
        # Bind events
        self.web_services_tree.bind('<<TreeviewSelect>>', self._on_web_service_select)
        self.web_services_tree.bind('<Double-1>', self._on_web_service_double_click)
        
        # Create scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', 
                                   command=self.web_services_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal', 
                                   command=self.web_services_tree.xview)
        
        self.web_services_tree.configure(yscrollcommand=v_scrollbar.set,
                                        xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.web_services_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Web service details frame
        web_details_frame = ttk.LabelFrame(self.web_services_tab, text="Web Service Details")
        web_details_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                              pady=ReMapTheme.SPACING['md'])
        
        self.web_details_text = tk.Text(web_details_frame, height=10, state='disabled',
                                       font=ReMapTheme.FONTS['code'], wrap=tk.WORD)
        self.web_details_text.pack(fill='x', padx=ReMapTheme.SPACING['sm'], 
                                  pady=ReMapTheme.SPACING['sm'])
    
    def _create_action_bar(self):
        """Create action bar with export and utility buttons."""
        action_frame = ttk.Frame(self)
        action_frame.pack(fill='x', padx=ReMapTheme.SPACING['md'], 
                         pady=ReMapTheme.SPACING['md'])
        
        # Export buttons
        export_frame = ttk.LabelFrame(action_frame, text="Export")
        export_frame.pack(side='left', fill='y', padx=(0, ReMapTheme.SPACING['md']))
        
        export_buttons = [
            ("Export HTML", self._export_html),
            ("Export CSV", self._export_csv),
            ("Export JSON", self._export_json)
        ]
        
        for text, command in export_buttons:
            ttk.Button(export_frame, text=text, command=command).pack(
                side='left', padx=ReMapTheme.SPACING['xs'])
        
        # View buttons
        view_frame = ttk.LabelFrame(action_frame, text="View")
        view_frame.pack(side='left', fill='y', padx=(0, ReMapTheme.SPACING['md']))
        
        view_buttons = [
            ("Refresh", self._refresh_results),
            ("Expand All", self._expand_all_trees),
            ("Collapse All", self._collapse_all_trees)
        ]
        
        for text, command in view_buttons:
            ttk.Button(view_frame, text=text, command=command).pack(
                side='left', padx=ReMapTheme.SPACING['xs'])
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(action_frame, text="Quick Stats")
        stats_frame.pack(side='right', fill='y')
        
        self.quick_stats_text = tk.Text(stats_frame, height=2, width=40, state='disabled',
                                       font=ReMapTheme.FONTS['small'], wrap=tk.NONE)
        self.quick_stats_text.pack(padx=ReMapTheme.SPACING['sm'], pady=ReMapTheme.SPACING['sm'])
    
    def _setup_layout(self):
        """Set up frame layout."""
        self.results_notebook.pack(fill='both', expand=True)
    
    def _setup_bindings(self):
        """Set up event bindings."""
        # Bind notebook tab changes
        self.results_notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)
        
        # Set up tooltips
        ToolTip(self.hosts_tree, "Double-click to view detailed host information")
        ToolTip(self.services_tree, "Double-click to copy service details")
        ToolTip(self.web_services_tree, "Double-click to open URL in browser")
    
    # Event handlers
    def _on_tab_changed(self, event):
        """Handle tab change events."""
        try:
            selected_tab = self.results_notebook.select()
            tab_text = self.results_notebook.tab(selected_tab, "text")
            logger.debug(f"Switched to tab: {tab_text}")
            
            # Refresh tab-specific content if needed
            if "Summary" in tab_text:
                self._update_quick_stats()
                
        except Exception as e:
            logger.error(f"Error handling tab change: {e}")
    
    def _on_host_select(self, event):
        """Handle host selection."""
        try:
            selection = self.hosts_tree.selection()
            if not selection or not self.current_scan_result:
                return
            
            item_id = selection[0]
            item_data = self.hosts_tree.item(item_id)
            host_ip = item_data['values'][0]
            
            # Find host in scan results
            host = next((h for h in self.current_scan_result.hosts if h.ip_address == host_ip), None)
            if host:
                self._display_host_details(host)
                
        except Exception as e:
            logger.error(f"Error handling host selection: {e}")
    
    def _on_host_double_click(self, event):
        """Handle host double-click."""
        try:
            selection = self.hosts_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.hosts_tree.item(item_id)
            host_ip = item_data['values'][0]
            
            # Show detailed host information dialog
            self._show_host_details_dialog(host_ip)
            
        except Exception as e:
            logger.error(f"Error handling host double-click: {e}")
    
    def _on_service_select(self, event):
        """Handle service selection."""
        try:
            selection = self.services_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.services_tree.item(item_id)
            
            # Display service details
            service_details = f"""Service Details:
Host: {item_data['values'][0]}
Port: {item_data['values'][1]}/{item_data['values'][2]}
State: {item_data['values'][3]}
Service: {item_data['values'][4]}
Version: {item_data['values'][5]}
Extra Info: {item_data['values'][6]}"""
            
            self._update_text_widget(self.service_details_text, service_details)
            
        except Exception as e:
            logger.error(f"Error handling service selection: {e}")
    
    def _on_service_double_click(self, event):
        """Handle service double-click (copy to clipboard)."""
        try:
            selection = self.services_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.services_tree.item(item_id)
            
            # Create service string for clipboard
            service_str = f"{item_data['values'][0]}:{item_data['values'][1]} ({item_data['values'][4]})"
            
            # Copy to clipboard
            self.clipboard_clear()
            self.clipboard_append(service_str)
            
            # Show confirmation
            self._show_status_message(f"Copied to clipboard: {service_str}")
            
        except Exception as e:
            logger.error(f"Error copying service details: {e}")
    
    def _on_vulnerability_select(self, event):
        """Handle vulnerability selection."""
        try:
            selection = self.vulnerabilities_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.vulnerabilities_tree.item(item_id)
            
            # Find full vulnerability details
            if self.current_analysis_result:
                host_ip = item_data['values'][0]
                vuln_name = item_data['values'][2]
                
                vuln = next((v for v in self.current_analysis_result.vulnerabilities 
                            if v['host'] == host_ip and v['vulnerability'] == vuln_name), None)
                
                if vuln:
                    details = f"""Vulnerability Details:
Host: {vuln['host']}
Port: {vuln.get('port', 'N/A')}
Vulnerability: {vuln['vulnerability']}
Severity: {vuln.get('severity', 'Medium').title()}

Description:
{vuln.get('details', 'No additional details available')}

Detected: {vuln.get('timestamp', 'Unknown').strftime('%Y-%m-%d %H:%M:%S') if vuln.get('timestamp') else 'Unknown'}"""
                    
                    self._update_text_widget(self.vuln_details_text, details)
                    
        except Exception as e:
            logger.error(f"Error handling vulnerability selection: {e}")
    
    def _on_web_service_select(self, event):
        """Handle web service selection."""
        try:
            selection = self.web_services_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.web_services_tree.item(item_id)
            
            # Find web service details
            if self.current_analysis_result:
                host_ip = item_data['values'][0]
                port = item_data['values'][1]
                
                web_service = next((ws for ws in self.current_analysis_result.web_services 
                                  if ws['host'] == host_ip and str(ws['port']) == str(port)), None)
                
                if web_service:
                    self._display_web_service_details(web_service)
                    
        except Exception as e:
            logger.error(f"Error handling web service selection: {e}")
    
    def _on_web_service_double_click(self, event):
        """Handle web service double-click (open URL)."""
        try:
            selection = self.web_services_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_data = self.web_services_tree.item(item_id)
            url = item_data['values'][2]
            
            if url and url.startswith(('http://', 'https://')):
                webbrowser.open(url)
                self._show_status_message(f"Opened URL: {url}")
            
        except Exception as e:
            logger.error(f"Error opening web service URL: {e}")
    
    def _on_host_search(self, *args):
        """Handle host search."""
        self._filter_hosts()
    
    def _on_service_search(self, *args):
        """Handle service search."""
        self._filter_services()
    
    # Display methods
    def display_results(self, scan_result: ScanResult, analysis_result: Optional[SecurityAnalysisResult] = None):
        """Display scan and analysis results."""
        try:
            self.current_scan_result = scan_result
            self.current_analysis_result = analysis_result
            
            # Update all displays
            self._update_summary_display()
            self._update_hosts_display()
            self._update_services_display()
            self._update_vulnerabilities_display()
            self._update_web_services_display()
            self._update_quick_stats()
            
            # Switch to summary tab
            self.results_notebook.select(self.summary_tab)
            
            logger.info(f"Displayed results: {scan_result.total_hosts} hosts, {scan_result.hosts_up} up")
            
        except Exception as e:
            logger.error(f"Error displaying results: {e}")
            messagebox.showerror("Error", f"Error displaying results: {e}")
    
    def _update_summary_display(self):
        """Update summary tab display."""
        if not self.current_scan_result:
            return
        
        try:
            # Calculate statistics
            open_ports = sum(len([p for p in host.ports if p.state == 'open']) 
                           for host in self.current_scan_result.hosts)
            
            closed_ports = sum(len([p for p in host.ports if p.state == 'closed']) 
                             for host in self.current_scan_result.hosts)
            
            filtered_ports = sum(len([p for p in host.ports if p.state == 'filtered']) 
                               for host in self.current_scan_result.hosts)
            
            # Service statistics
            service_counts = {}
            for host in self.current_scan_result.hosts:
                for port in host.ports:
                    if port.state == 'open' and port.service:
                        service = port.service
                        service_counts[service] = service_counts.get(service, 0) + 1
            
            # OS statistics
            os_counts = {}
            for host in self.current_scan_result.hosts:
                if host.os_info:
                    os_counts[host.os_info] = os_counts.get(host.os_info, 0) + 1
            
            # Build summary text
            summary_lines = [
                "SCAN SUMMARY",
                "=" * 50,
                f"Total Hosts Scanned: {self.current_scan_result.total_hosts}",
                f"Hosts Up: {self.current_scan_result.hosts_up}",
                f"Hosts Down: {self.current_scan_result.total_hosts - self.current_scan_result.hosts_up}",
                "",
                "PORT STATISTICS",
                "-" * 30,
                f"Open Ports: {open_ports}",
                f"Closed Ports: {closed_ports}",
                f"Filtered Ports: {filtered_ports}",
                f"Total Ports Scanned: {open_ports + closed_ports + filtered_ports}",
                "",
                "TOP SERVICES",
                "-" * 30
            ]
            
            # Add top services
            top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            for service, count in top_services:
                summary_lines.append(f"{service}: {count}")
            
            if os_counts:
                summary_lines.extend([
                    "",
                    "OPERATING SYSTEMS",
                    "-" * 30
                ])
                for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True):
                    summary_lines.append(f"{os_name}: {count}")
            
            # Analysis summary
            if self.current_analysis_result:
                analysis_summary = self.current_analysis_result.get_summary()
                summary_lines.extend([
                    "",
                    "SECURITY ANALYSIS",
                    "-" * 30,
                    f"Total Vulnerabilities: {analysis_summary.get('total_vulnerabilities', 0)}",
                    f"Web Services: {analysis_summary.get('web_services_found', 0)}",
                    f"Analysis Duration: {analysis_summary.get('analysis_duration', 0):.1f}s"
                ])
                
                severity_breakdown = analysis_summary.get('severity_breakdown', {})
                if any(severity_breakdown.values()):
                    summary_lines.append("")
                    for severity, count in severity_breakdown.items():
                        if count > 0:
                            summary_lines.append(f"{severity.title()}: {count}")
            
            # Update stats display
            summary_text = "\n".join(summary_lines)
            self._update_text_widget(self.stats_text, summary_text)
            
            # Update top services tree
            self._update_top_services_tree(top_services, open_ports)
            
            # Update timeline
            timeline_text = self._generate_timeline_text()
            self._update_text_widget(self.timeline_text, timeline_text)
            
        except Exception as e:
            logger.error(f"Error updating summary display: {e}")
    
    def _update_top_services_tree(self, top_services: List[tuple], total_open_ports: int):
        """Update top services treeview."""
        try:
            # Clear existing items
            for item in self.top_services_tree.get_children():
                self.top_services_tree.delete(item)
            
            # Add services
            for service, count in top_services:
                percentage = (count / total_open_ports * 100) if total_open_ports > 0 else 0
                
                self.top_services_tree.insert('', 'end', values=(
                    service,
                    count,
                    f"{percentage:.1f}%"
                ))
                
        except Exception as e:
            logger.error(f"Error updating top services tree: {e}")
    
    def _generate_timeline_text(self) -> str:
        """Generate scan timeline information."""
        try:
            lines = []
            
            if self.current_scan_result.start_time:
                lines.append(f"Scan Started: {self.current_scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if self.current_scan_result.end_time:
                lines.append(f"Scan Completed: {self.current_scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if self.current_scan_result.duration:
                lines.append(f"Duration: {self.current_scan_result.duration:.1f} seconds")
            
            # Scan info
            scan_info = self.current_scan_result.scan_info
            if scan_info:
                if 'scanner' in scan_info:
                    lines.append(f"Scanner: {scan_info['scanner']}")
                if 'version' in scan_info:
                    lines.append(f"Version: {scan_info['version']}")
                if 'type' in scan_info:
                    lines.append(f"Scan Type: {scan_info['type']}")
            
            return "\n".join(lines) if lines else "No timeline information available"
            
        except Exception as e:
            logger.error(f"Error generating timeline: {e}")
            return "Error generating timeline information"
    
    def _update_hosts_display(self):
        """Update hosts tab display."""
        if not self.current_scan_result:
            return
        
        try:
            # Clear existing items
            for item in self.hosts_tree.get_children():
                self.hosts_tree.delete(item)
            
            # Add hosts
            for host in self.current_scan_result.hosts:
                open_ports_count = len([p for p in host.ports if p.state == 'open'])
                last_seen = self.current_scan_result.start_time.strftime('%Y-%m-%d %H:%M') if self.current_scan_result.start_time else 'Unknown'
                
                item_id = self.hosts_tree.insert('', 'end', values=(
                    host.ip_address,
                    host.hostname or '',
                    host.state.title(),
                    open_ports_count,
                    host.os_info or '',
                    last_seen
                ))
                
                # Color code based on status
                if host.state == 'up':
                    self.hosts_tree.set(item_id, 'Status', host.state.title())
                else:
                    self.hosts_tree.set(item_id, 'Status', host.state.title())
            
            # Apply current filter
            self._filter_hosts()
            
        except Exception as e:
            logger.error(f"Error updating hosts display: {e}")
    
    def _update_services_display(self):
        """Update services tab display."""
        if not self.current_scan_result:
            return
        
        try:
            # Clear existing items
            for item in self.services_tree.get_children():
                self.services_tree.delete(item)
            
            # Add services
            for host in self.current_scan_result.hosts:
                for port in host.ports:
                    extra_info = ""
                    if port.extra_info:
                        # Summarize extra info
                        info_parts = []
                        if 'service_details' in port.extra_info:
                            service_details = port.extra_info['service_details']
                            if 'method' in service_details:
                                info_parts.append(f"Method: {service_details['method']}")
                        extra_info = "; ".join(info_parts[:2])  # Limit to first 2 items
                    
                    item_id = self.services_tree.insert('', 'end', values=(
                        host.ip_address,
                        port.number,
                        port.protocol,
                        port.state.title(),
                        port.service or '',
                        port.version or '',
                        extra_info
                    ))
                    
                    # Color code based on port state
                    if port.state == 'open':
                        self.services_tree.set(item_id, 'State', port.state.title())
            
            # Apply current filter
            self._filter_services()
            
        except Exception as e:
            logger.error(f"Error updating services display: {e}")
    
    def _update_vulnerabilities_display(self):
        """Update vulnerabilities tab display."""
        try:
            # Clear existing items
            for item in self.vulnerabilities_tree.get_children():
                self.vulnerabilities_tree.delete(item)
            
            if not self.current_analysis_result or not self.current_analysis_result.vulnerabilities:
                return
            
            # Add vulnerabilities
            for vuln in self.current_analysis_result.vulnerabilities:
                port_str = str(vuln.get('port', '')) if vuln.get('port') else ''
                details_preview = vuln.get('details', '')[:100] + '...' if len(vuln.get('details', '')) > 100 else vuln.get('details', '')
                
                item_id = self.vulnerabilities_tree.insert('', 'end', values=(
                    vuln['host'],
                    port_str,
                    vuln['vulnerability'],
                    vuln.get('severity', 'Medium').title(),
                    details_preview
                ))
            
            # Apply current filter
            self._filter_vulnerabilities()
            
        except Exception as e:
            logger.error(f"Error updating vulnerabilities display: {e}")
    
    def _update_web_services_display(self):
        """Update web services tab display."""
        try:
            # Clear existing items
            for item in self.web_services_tree.get_children():
                self.web_services_tree.delete(item)
            
            if not self.current_analysis_result or not self.current_analysis_result.web_services:
                return
            
            # Add web services
            for web_service in self.current_analysis_result.web_services:
                result = web_service.get('result', {})
                server_info = result.get('server_info', {})
                applications = result.get('applications', [])
                urls = result.get('urls', [])
                
                main_url = urls[0] if urls else f"http://{web_service['host']}:{web_service['port']}"
                app_names = ', '.join([app.get('name', '') for app in applications])
                status_code = server_info.get('status_code', 'Unknown')
                                
                self.web_services_tree.insert('', 'end', values=(
                    web_service['host'],
                    web_service['port'],
                    main_url,
                    server_info.get('server', 'Unknown'),
                    app_names or 'Unknown',
                    status_code
                ))
                
        except Exception as e:
            logger.error(f"Error updating web services display: {e}")
    
    def _display_host_details(self, host: Host):
        """Display detailed host information."""
        try:
            details_lines = [
                f"Host: {host.ip_address}",
                f"Hostname: {host.hostname or 'Unknown'}",
                f"Status: {host.state.title()}",
                f"OS: {host.os_info or 'Unknown'}",
                ""
            ]
            
            if host.ports:
                details_lines.extend([
                    f"Ports ({len(host.ports)} total):",
                    "-" * 30
                ])
                
                # Group ports by state
                ports_by_state = {}
                for port in host.ports:
                    state = port.state
                    if state not in ports_by_state:
                        ports_by_state[state] = []
                    ports_by_state[state].append(port)
                
                # Display ports by state
                for state in ['open', 'closed', 'filtered']:
                    if state in ports_by_state:
                        ports = ports_by_state[state]
                        details_lines.append(f"{state.title()} ({len(ports)}):")
                        
                        for port in ports[:10]:  # Limit to first 10
                            service_info = f" ({port.service})" if port.service else ""
                            version_info = f" - {port.version}" if port.version else ""
                            details_lines.append(f"  {port.number}/{port.protocol}{service_info}{version_info}")
                        
                        if len(ports) > 10:
                            details_lines.append(f"  ... and {len(ports) - 10} more")
                        details_lines.append("")
            
            # Extra information
            if host.extra_info:
                details_lines.extend([
                    "Additional Information:",
                    "-" * 30
                ])
                
                for key, value in host.extra_info.items():
                    if isinstance(value, (str, int, float)):
                        details_lines.append(f"{key}: {value}")
                    elif isinstance(value, list) and len(value) > 0:
                        details_lines.append(f"{key}: {len(value)} items")
            
            details_text = "\n".join(details_lines)
            self._update_text_widget(self.host_details_text, details_text)
            
        except Exception as e:
            logger.error(f"Error displaying host details: {e}")
    
    def _display_web_service_details(self, web_service: Dict[str, Any]):
        """Display detailed web service information."""
        try:
            result = web_service.get('result', {})
            server_info = result.get('server_info', {})
            applications = result.get('applications', [])
            security_headers = result.get('security_headers', {})
            urls = result.get('urls', [])
            
            details_lines = [
                f"Web Service Details:",
                f"Host: {web_service['host']}:{web_service['port']}",
                f"Main URL: {urls[0] if urls else 'Unknown'}",
                f"Server: {server_info.get('server', 'Unknown')}",
                f"Status Code: {server_info.get('status_code', 'Unknown')}",
                f"Content Type: {server_info.get('content_type', 'Unknown')}",
                ""
            ]
            
            # Applications
            if applications:
                details_lines.extend([
                    "Detected Applications:",
                    "-" * 25
                ])
                
                for app in applications:
                    app_name = app.get('name', 'Unknown')
                    app_type = app.get('type', '')
                    confidence = app.get('confidence', '')
                    
                    app_line = app_name
                    if app_type:
                        app_line += f" ({app_type})"
                    if confidence:
                        app_line += f" - {confidence} confidence"
                    
                    details_lines.append(f"• {app_line}")
                
                details_lines.append("")
            
            # Security Headers
            if security_headers:
                details_lines.extend([
                    "Security Headers:",
                    "-" * 20
                ])
                
                for header_name, header_info in security_headers.items():
                    status = "✓" if header_info.get('present', False) else "✗"
                    value = header_info.get('value', '')
                    
                    header_line = f"{status} {header_name}"
                    if value and header_info.get('present'):
                        header_line += f": {value[:50]}{'...' if len(value) > 50 else ''}"
                    
                    details_lines.append(header_line)
                
                details_lines.append("")
            
            # Additional URLs
            if len(urls) > 1:
                details_lines.extend([
                    "Additional URLs:",
                    "-" * 18
                ])
                
                for url in urls[1:6]:  # Show up to 5 additional URLs
                    details_lines.append(f"• {url}")
                
                if len(urls) > 6:
                    details_lines.append(f"• ... and {len(urls) - 6} more")
            
            details_text = "\n".join(details_lines)
            self._update_text_widget(self.web_details_text, details_text)
            
        except Exception as e:
            logger.error(f"Error displaying web service details: {e}")
    
    def _show_host_details_dialog(self, host_ip: str):
        """Show detailed host information in a dialog."""
        try:
            # Find host
            host = next((h for h in self.current_scan_result.hosts if h.ip_address == host_ip), None)
            if not host:
                return
            
            # Create dialog
            dialog = tk.Toplevel(self)
            dialog.title(f"Host Details - {host_ip}")
            dialog.geometry("600x500")
            dialog.transient(self.winfo_toplevel())
            dialog.grab_set()
            
            # Create content frame
            main_frame = ttk.Frame(dialog, padding=ReMapTheme.SPACING['md'])
            main_frame.pack(fill='both', expand=True)
            
            # Host info frame
            info_frame = ttk.LabelFrame(main_frame, text="Host Information")
            info_frame.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
            
            # Basic info
            info_text = f"""IP Address: {host.ip_address}
Hostname: {host.hostname or 'Unknown'}
Status: {host.state.title()}
OS: {host.os_info or 'Unknown'}
Open Ports: {len([p for p in host.ports if p.state == 'open'])}
Total Ports: {len(host.ports)}"""
            
            info_label = ttk.Label(info_frame, text=info_text, justify='left')
            info_label.pack(anchor='w', padx=ReMapTheme.SPACING['md'], 
                          pady=ReMapTheme.SPACING['md'])
            
            # Ports frame
            ports_frame = ttk.LabelFrame(main_frame, text="Ports")
            ports_frame.pack(fill='both', expand=True, pady=(0, ReMapTheme.SPACING['md']))
            
            # Ports treeview
            ports_tree_frame = ttk.Frame(ports_frame)
            ports_tree_frame.pack(fill='both', expand=True, padx=ReMapTheme.SPACING['sm'], 
                                 pady=ReMapTheme.SPACING['sm'])
            
            columns = ('Port', 'Protocol', 'State', 'Service', 'Version')
            ports_tree = ttk.Treeview(ports_tree_frame, columns=columns, 
                                     show='tree headings', style='Custom.Treeview')
            
            # Configure columns
            ports_tree.column('#0', width=0, stretch=False)
            for i, col in enumerate(columns):
                width = [60, 80, 80, 120, 200][i]
                ports_tree.column(col, width=width, anchor='w' if i > 2 else 'center')
                ports_tree.heading(col, text=col, anchor='w')
            
            # Add ports
            for port in host.ports:
                ports_tree.insert('', 'end', values=(
                    port.number,
                    port.protocol,
                    port.state,
                    port.service or '',
                    port.version or ''
                ))
            
            # Scrollbar for ports tree
            ports_scrollbar = ttk.Scrollbar(ports_tree_frame, orient='vertical',
                                          command=ports_tree.yview)
            ports_tree.configure(yscrollcommand=ports_scrollbar.set)
            
            ports_tree.pack(side='left', fill='both', expand=True)
            ports_scrollbar.pack(side='right', fill='y')
            
            # Buttons frame
            buttons_frame = ttk.Frame(main_frame)
            buttons_frame.pack(fill='x')
            
            ttk.Button(buttons_frame, text="Close", 
                      command=dialog.destroy).pack(side='right')
            
            ttk.Button(buttons_frame, text="Export Details", 
                      command=lambda: self._export_host_details(host)).pack(
                      side='right', padx=(0, ReMapTheme.SPACING['sm']))
            
            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
            y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
            dialog.geometry(f"+{x}+{y}")
            
        except Exception as e:
            logger.error(f"Error showing host details dialog: {e}")
            messagebox.showerror("Error", f"Error showing host details: {e}")
    
    # Filter methods
    def _filter_hosts(self):
        """Filter hosts display based on current filters."""
        try:
            filter_value = self.host_filter_var.get()
            search_term = self.host_search_var.get().lower()
            
            # Get all items
            all_items = list(self.hosts_tree.get_children())
            
            for item in all_items:
                item_data = self.hosts_tree.item(item)
                values = item_data['values']
                
                # Apply status filter
                show_item = True
                if filter_value == "up" and values[2].lower() != "up":
                    show_item = False
                elif filter_value == "down" and values[2].lower() == "up":
                    show_item = False
                
                # Apply search filter
                if show_item and search_term:
                    searchable_text = f"{values[0]} {values[1]}".lower()
                    if search_term not in searchable_text:
                        show_item = False
                
                # Show/hide item
                if show_item:
                    self.hosts_tree.reattach(item, '', 'end')
                else:
                    self.hosts_tree.detach(item)
                    
        except Exception as e:
            logger.error(f"Error filtering hosts: {e}")
    
    def _filter_services(self):
        """Filter services display based on current filters."""
        try:
            port_filter = self.port_filter_var.get()
            search_term = self.service_search_var.get().lower()
            
            # Get all items
            all_items = list(self.services_tree.get_children())
            
            for item in all_items:
                item_data = self.services_tree.item(item)
                values = item_data['values']
                
                # Apply port state filter
                show_item = True
                if port_filter == "open" and values[3].lower() != "open":
                    show_item = False
                
                # Apply service search filter
                if show_item and search_term:
                    searchable_text = f"{values[4]} {values[5]}".lower()
                    if search_term not in searchable_text:
                        show_item = False
                
                # Show/hide item
                if show_item:
                    self.services_tree.reattach(item, '', 'end')
                else:
                    self.services_tree.detach(item)
                    
        except Exception as e:
            logger.error(f"Error filtering services: {e}")
    
    def _filter_vulnerabilities(self):
        """Filter vulnerabilities display based on severity."""
        try:
            severity_filter = self.vuln_filter_var.get()
            
            # Get all items
            all_items = list(self.vulnerabilities_tree.get_children())
            
            for item in all_items:
                item_data = self.vulnerabilities_tree.item(item)
                values = item_data['values']
                
                # Apply severity filter
                show_item = True
                if severity_filter != "all":
                    item_severity = values[3].lower()
                    if severity_filter != item_severity:
                        show_item = False
                
                # Show/hide item
                if show_item:
                    self.vulnerabilities_tree.reattach(item, '', 'end')
                else:
                    self.vulnerabilities_tree.detach(item)
                    
        except Exception as e:
            logger.error(f"Error filtering vulnerabilities: {e}")
    
    # Export methods
    def _export_html(self):
        """Export results as HTML."""
        try:
            if not self.current_scan_result:
                messagebox.showwarning("Warning", "No results to export")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Export HTML Report",
                defaultextension=".html",
                filetypes=[("HTML files", "*.html")]
            )
            
            if file_path:
                from ..reports.report_generator import ReportGenerator
                generator = ReportGenerator()
                
                exported_path = generator.generate_report(
                    self.current_scan_result,
                    self.current_analysis_result,
                    'html',
                    file_path
                )
                
                if exported_path:
                    messagebox.showinfo("Success", f"HTML report exported to:\n{exported_path}")
                else:
                    messagebox.showerror("Error", "Failed to export HTML report")
                    
        except Exception as e:
            logger.error(f"Error exporting HTML: {e}")
            messagebox.showerror("Error", f"Failed to export HTML: {e}")
    
    def _export_csv(self):
        """Export results as CSV."""
        try:
            if not self.current_scan_result:
                messagebox.showwarning("Warning", "No results to export")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Export CSV Report",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")]
            )
            
            if file_path:
                from ..reports.report_generator import ReportGenerator
                generator = ReportGenerator()
                
                exported_path = generator.generate_report(
                    self.current_scan_result,
                    self.current_analysis_result,
                    'csv',
                    file_path
                )
                
                if exported_path:
                    messagebox.showinfo("Success", f"CSV report exported to:\n{exported_path}")
                else:
                    messagebox.showerror("Error", "Failed to export CSV report")
                    
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            messagebox.showerror("Error", f"Failed to export CSV: {e}")
    
    def _export_json(self):
        """Export results as JSON."""
        try:
            if not self.current_scan_result:
                messagebox.showwarning("Warning", "No results to export")
                return
            
            file_path = filedialog.asksaveasfilename(
                title="Export JSON Report",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            
            if file_path:
                from ..reports.report_generator import ReportGenerator
                generator = ReportGenerator()
                
                exported_path = generator.generate_report(
                    self.current_scan_result,
                    self.current_analysis_result,
                    'json',
                    file_path
                )
                
                if exported_path:
                    messagebox.showinfo("Success", f"JSON report exported to:\n{exported_path}")
                else:
                    messagebox.showerror("Error", "Failed to export JSON report")
                    
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            messagebox.showerror("Error", f"Failed to export JSON: {e}")
    
    def _export_host_details(self, host: Host):
        """Export detailed host information."""
        try:
            file_path = filedialog.asksaveasfilename(
                title=f"Export Host Details - {host.ip_address}",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")]
            )
            
            if not file_path:
                return
            
            if file_path.endswith('.json'):
                # Export as JSON
                host_data = {
                    'ip_address': host.ip_address,
                    'hostname': host.hostname,
                    'state': host.state,
                    'os_info': host.os_info,
                    'ports': [
                        {
                            'number': port.number,
                            'protocol': port.protocol,
                            'state': port.state,
                            'service': port.service,
                            'version': port.version,
                            'extra_info': port.extra_info
                        }
                        for port in host.ports
                    ],
                    'extra_info': host.extra_info
                }
                
                with open(file_path, 'w') as f:
                    json.dump(host_data, f, indent=2, default=str)
            else:
                # Export as text
                lines = [
                    f"Host Details: {host.ip_address}",
                    "=" * 50,
                    f"IP Address: {host.ip_address}",
                    f"Hostname: {host.hostname or 'Unknown'}",
                    f"Status: {host.state.title()}",
                    f"OS: {host.os_info or 'Unknown'}",
                    "",
                    f"Ports ({len(host.ports)} total):",
                    "-" * 30
                ]
                
                for port in host.ports:
                    port_line = f"{port.number}/{port.protocol} - {port.state}"
                    if port.service:
                        port_line += f" ({port.service})"
                    if port.version:
                        port_line += f" - {port.version}"
                    lines.append(port_line)
                
                with open(file_path, 'w') as f:
                    f.write('\n'.join(lines))
            
            messagebox.showinfo("Success", f"Host details exported to:\n{file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting host details: {e}")
            messagebox.showerror("Error", f"Failed to export host details: {e}")
    
    # Utility methods
    def _refresh_results(self):
        """Refresh the results display."""
        if self.current_scan_result:
            self.display_results(self.current_scan_result, self.current_analysis_result)
            self._show_status_message("Results refreshed")
    
    def _expand_all_trees(self):
        """Expand all treeview items."""
        trees = [self.hosts_tree, self.services_tree, self.vulnerabilities_tree, 
                self.web_services_tree, self.top_services_tree]
        
        for tree in trees:
            try:
                for item in tree.get_children():
                    tree.item(item, open=True)
            except Exception as e:
                logger.error(f"Error expanding tree: {e}")
        
        self._show_status_message("All trees expanded")
    
    def _collapse_all_trees(self):
        """Collapse all treeview items."""
        trees = [self.hosts_tree, self.services_tree, self.vulnerabilities_tree, 
                self.web_services_tree, self.top_services_tree]
        
        for tree in trees:
            try:
                for item in tree.get_children():
                    tree.item(item, open=False)
            except Exception as e:
                logger.error(f"Error collapsing tree: {e}")
        
        self._show_status_message("All trees collapsed")
    
    def _update_quick_stats(self):
        """Update quick stats display."""
        try:
            if not self.current_scan_result:
                self._update_text_widget(self.quick_stats_text, "No scan results available")
                return
            
            hosts_up = self.current_scan_result.hosts_up
            total_hosts = self.current_scan_result.total_hosts
            open_ports = sum(len([p for p in host.ports if p.state == 'open']) 
                           for host in self.current_scan_result.hosts)
            
            # Vulnerability stats
            vuln_count = 0
            critical_count = 0
            if self.current_analysis_result:
                vuln_count = len(self.current_analysis_result.vulnerabilities)
                critical_count = len([v for v in self.current_analysis_result.vulnerabilities 
                                    if v.get('severity', '').lower() == 'critical'])
            
            stats_text = f"Hosts: {hosts_up}/{total_hosts} up | Open Ports: {open_ports}"
            if vuln_count > 0:
                stats_text += f" | Vulnerabilities: {vuln_count}"
                if critical_count > 0:
                    stats_text += f" ({critical_count} critical)"
            
            self._update_text_widget(self.quick_stats_text, stats_text)
            
        except Exception as e:
            logger.error(f"Error updating quick stats: {e}")
    
    def _update_text_widget(self, widget: tk.Text, text: str):
        """Update text widget content."""
        try:
            widget.configure(state='normal')
            widget.delete(1.0, tk.END)
            widget.insert(1.0, text)
            widget.configure(state='disabled')
        except Exception as e:
            logger.error(f"Error updating text widget: {e}")
    
    def _show_status_message(self, message: str, duration: int = 3000):
        """Show temporary status message."""
        try:
            # This would typically update a status bar
            # For now, we'll just log it
            logger.info(f"Status: {message}")
            
            # Could implement a temporary status display here
            # self.after(duration, lambda: self._clear_status_message())
            
        except Exception as e:
            logger.error(f"Error showing status message: {e}")
    
    def clear_results(self):
        """Clear all results from display."""
        try:
            # Clear data
            self.current_scan_result = None
            self.current_analysis_result = None
            
            # Clear all treeviews
            trees = [
                self.hosts_tree, self.services_tree, self.vulnerabilities_tree,
                self.web_services_tree, self.top_services_tree
            ]
            
            for tree in trees:
                for item in tree.get_children():
                    tree.delete(item)
            
            # Clear text widgets
            text_widgets = [
                self.stats_text, self.timeline_text, self.host_details_text,
                self.service_details_text, self.vuln_details_text,
                self.web_details_text, self.quick_stats_text
            ]
            
            for widget in text_widgets:
                self._update_text_widget(widget, "")
            
            # Reset filters
            self.host_filter_var.set("all")
            self.port_filter_var.set("open")
            self.vuln_filter_var.set("all")
            self.host_search_var.set("")
            self.service_search_var.set("")
            
            logger.info("Results display cleared")
            
        except Exception as e:
            logger.error(f"Error clearing results: {e}")
    
    def get_selected_hosts(self) -> List[str]:
        """Get currently selected host IP addresses."""
        try:
            selection = self.hosts_tree.selection()
            hosts = []
            
            for item_id in selection:
                item_data = self.hosts_tree.item(item_id)
                host_ip = item_data['values'][0]
                hosts.append(host_ip)
            
            return hosts
            
        except Exception as e:
            logger.error(f"Error getting selected hosts: {e}")
            return []
    
    def get_selected_services(self) -> List[Dict[str, Any]]:
        """Get currently selected services."""
        try:
            selection = self.services_tree.selection()
            services = []
            
            for item_id in selection:
                item_data = self.services_tree.item(item_id)
                values = item_data['values']
                
                service = {
                    'host': values[0],
                    'port': int(values[1]),
                    'protocol': values[2],
                    'state': values[3],
                    'service': values[4],
                    'version': values[5]
                }
                services.append(service)
            
            return services
            
        except Exception as e:
            logger.error(f"Error getting selected services: {e}")
            return []
    
    def select_tab(self, tab_name: str):
        """Select a specific tab by name."""
        try:
            tab_map = {
                'summary': self.summary_tab,
                'hosts': self.hosts_tab,
                'services': self.services_tab,
                'vulnerabilities': self.vulnerabilities_tab,
                'web_services': self.web_services_tab
            }
            
            if tab_name in tab_map:
                self.results_notebook.select(tab_map[tab_name])
                logger.debug(f"Selected tab: {tab_name}")
            else:
                logger.warning(f"Unknown tab name: {tab_name}")
                
        except Exception as e:
            logger.error(f"Error selecting tab: {e}")
    
    def get_current_tab(self) -> str:
        """Get currently selected tab name."""
        try:
            current = self.results_notebook.select()
            tab_text = self.results_notebook.tab(current, "text")
            
            # Extract tab name from text (remove emoji)
            if "Summary" in tab_text:
                return "summary"
            elif "Hosts" in tab_text:
                return "hosts"
            elif "Services" in tab_text:
                return "services"
            elif "Vulnerabilities" in tab_text:
                return "vulnerabilities"
            elif "Web Services" in tab_text:
                return "web_services"
            else:
                return "unknown"
                
        except Exception as e:
            logger.error(f"Error getting current tab: {e}")
            return "unknown"
    
    def set_analysis_results(self, analysis_result: SecurityAnalysisResult):
        """Set analysis results and update display."""
        try:
            self.current_analysis_result = analysis_result
            
            # Update displays that show analysis results
            self._update_summary_display()
            self._update_vulnerabilities_display()
            self._update_web_services_display()
            self._update_quick_stats()
            
            logger.info("Analysis results updated in display")
            
        except Exception as e:
            logger.error(f"Error setting analysis results: {e}")
    
    def highlight_host(self, host_ip: str):
        """Highlight a specific host in the hosts tree."""
        try:
            # Find and select the host
            for item in self.hosts_tree.get_children():
                item_data = self.hosts_tree.item(item)
                if item_data['values'][0] == host_ip:
                    self.hosts_tree.selection_set(item)
                    self.hosts_tree.focus(item)
                    self.hosts_tree.see(item)
                    
                    # Switch to hosts tab
                    self.select_tab('hosts')
                    break
                    
        except Exception as e:
            logger.error(f"Error highlighting host: {e}")
    
    def highlight_service(self, host_ip: str, port: int):
        """Highlight a specific service in the services tree."""
        try:
            # Find and select the service
            for item in self.services_tree.get_children():
                item_data = self.services_tree.item(item)
                values = item_data['values']
                
                if values[0] == host_ip and int(values[1]) == port:
                    self.services_tree.selection_set(item)
                    self.services_tree.focus(item)
                    self.services_tree.see(item)
                    
                    # Switch to services tab
                    self.select_tab('services')
                    break
                    
        except Exception as e:
            logger.error(f"Error highlighting service: {e}")
    
    def get_results_summary(self) -> Dict[str, Any]:
        """Get summary of current results."""
        try:
            if not self.current_scan_result:
                return {}
            
            summary = {
                'total_hosts': self.current_scan_result.total_hosts,
                'hosts_up': self.current_scan_result.hosts_up,
                'scan_duration': self.current_scan_result.duration,
                'open_ports': sum(len([p for p in host.ports if p.state == 'open']) 
                                for host in self.current_scan_result.hosts),
                'total_ports': sum(len(host.ports) for host in self.current_scan_result.hosts)
            }
            
            # Add analysis summary if available
            if self.current_analysis_result:
                analysis_summary = self.current_analysis_result.get_summary()
                summary.update({
                    'vulnerabilities': analysis_summary.get('total_vulnerabilities', 0),
                    'web_services': analysis_summary.get('web_services_found', 0),
                    'analysis_duration': analysis_summary.get('analysis_duration', 0)
                })
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting results summary: {e}")
            return {}
    
    def apply_result_filters(self, filters: Dict[str, Any]):
        """Apply multiple filters to results."""
        try:
            # Apply host filters
            if 'host_status' in filters:
                self.host_filter_var.set(filters['host_status'])
            
            if 'host_search' in filters:
                self.host_search_var.set(filters['host_search'])
            
            # Apply service filters
            if 'port_state' in filters:
                self.port_filter_var.set(filters['port_state'])
            
            if 'service_search' in filters:
                self.service_search_var.set(filters['service_search'])
            
            # Apply vulnerability filters
            if 'vulnerability_severity' in filters:
                self.vuln_filter_var.set(filters['vulnerability_severity'])
            
            # Apply all filters
            self._filter_hosts()
            self._filter_services()
            self._filter_vulnerabilities()
            
            logger.debug(f"Applied result filters: {filters}")
            
        except Exception as e:
            logger.error(f"Error applying result filters: {e}")
    
    def export_current_view(self, format_type: str = 'csv'):
        """Export currently visible data in the active tab."""
        try:
            current_tab = self.get_current_tab()
            
            file_path = filedialog.asksaveasfilename(
                title=f"Export {current_tab.title()} Data",
                defaultextension=f".{format_type}",
                filetypes=[(f"{format_type.upper()} files", f"*.{format_type}")]
            )
            
            if not file_path:
                return
            
            if current_tab == 'hosts':
                self._export_tree_data(self.hosts_tree, file_path, format_type)
            elif current_tab == 'services':
                self._export_tree_data(self.services_tree, file_path, format_type)
            elif current_tab == 'vulnerabilities':
                self._export_tree_data(self.vulnerabilities_tree, file_path, format_type)
            elif current_tab == 'web_services':
                self._export_tree_data(self.web_services_tree, file_path, format_type)
            else:
                messagebox.showwarning("Warning", f"Cannot export {current_tab} data")
                return
            
            messagebox.showinfo("Success", f"Data exported to:\n{file_path}")
            
        except Exception as e:
            logger.error(f"Error exporting current view: {e}")
            messagebox.showerror("Error", f"Failed to export data: {e}")
    
    def _export_tree_data(self, tree: ttk.Treeview, file_path: str, format_type: str):
        """Export treeview data to file."""
        try:
            # Get column headers
            columns = []
            for col in tree['columns']:
                columns.append(tree.heading(col, 'text'))
            
            # Get visible items data
            rows = []
            for item in tree.get_children():
                if tree.parent(item) == '':  # Only top-level items
                    values = tree.item(item)['values']
                    rows.append(values)
            
            if format_type.lower() == 'csv':
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(columns)
                    writer.writerows(rows)
            
            elif format_type.lower() == 'json':
                data = []
                for row in rows:
                    item_dict = {columns[i]: row[i] for i in range(len(columns))}
                    data.append(item_dict)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
                
        except Exception as e:
            logger.error(f"Error exporting tree data: {e}")
            raise