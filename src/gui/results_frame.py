"""Results frame for displaying scan and analysis results in lists."""

import tkinter as tk
from tkinter import ttk
from tkinter.constants import BOTH  # CORRECTED IMPORT
import ttkbootstrap as bttk
from ttkbootstrap.tooltip import ToolTip
from typing import Optional, List, Dict, Any, Callable

from .styles import icon_manager, create_severity_colors, FONTS
from ..models.scan_result import ScanResult, Host
from ..analysis.security_analyzer import SecurityAnalysisResult
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ResultsFrame(bttk.Frame):
    """Manages the notebook with different result list views."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(fill=BOTH, expand=True)

        self.selection_callback: Optional[Callable[[str, Any], None]] = None

        self.notebook = bttk.Notebook(self)
        self.notebook.pack(fill=BOTH, expand=True)
        
        self.tabs = {}
        self._create_hosts_tab()
        self._create_vulnerabilities_tab()

    def set_selection_callback(self, callback: Callable[[str, Any], None]):
        self.selection_callback = callback
    
    def _create_treeview(self, parent, columns) -> ttk.Treeview:
        tree_frame = bttk.Frame(parent)
        tree_frame.pack(fill=BOTH, expand=True)
        tree = bttk.Treeview(tree_frame, columns=columns, show='headings', bootstyle='primary')
        vsb = bttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview, bootstyle="round")
        hsb = bttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview, bootstyle="round")
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        return tree

    def _create_hosts_tab(self):
        frame = bttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text=f" {icon_manager.get_icon('network')} Hosts")
        self.tabs["Hosts"] = frame
        
        columns = ('ip', 'hostname', 'status', 'ports')
        self.hosts_tree = self._create_treeview(frame, columns)
        
        self.hosts_tree.heading('ip', text='IP Address', command=lambda: self._sort_tree(self.hosts_tree, 'ip', False))
        self.hosts_tree.heading('hostname', text='Hostname', command=lambda: self._sort_tree(self.hosts_tree, 'hostname', False))
        self.hosts_tree.heading('status', text='Status', command=lambda: self._sort_tree(self.hosts_tree, 'status', False))
        self.hosts_tree.heading('ports', text='Open Ports', command=lambda: self._sort_tree(self.hosts_tree, 'ports', True)) # Sort numerically
        
        self.hosts_tree.column('ip', width=120, anchor='w')
        self.hosts_tree.column('hostname', width=200, anchor='w')
        self.hosts_tree.column('status', width=80, anchor='center')
        self.hosts_tree.column('ports', width=80, anchor='center')

        self.hosts_tree.bind('<<TreeviewSelect>>', self._on_host_select)

    def _create_vulnerabilities_tab(self):
        frame = bttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text=f" {icon_manager.get_icon('security')} Vulnerabilities")
        self.tabs["Vulnerabilities"] = frame
        
        columns = ('severity', 'host', 'port', 'vulnerability')
        self.vulns_tree = self._create_treeview(frame, columns)

        self.vulns_tree.heading('severity', text='Severity', command=lambda: self._sort_tree(self.vulns_tree, 'severity', False))
        self.vulns_tree.heading('host', text='Host', command=lambda: self._sort_tree(self.vulns_tree, 'host', False))
        self.vulns_tree.heading('port', text='Port', command=lambda: self._sort_tree(self.vulns_tree, 'port', True))
        self.vulns_tree.heading('vulnerability', text='Vulnerability', command=lambda: self._sort_tree(self.vulns_tree, 'vulnerability', False))

        self.vulns_tree.column('severity', width=80, anchor='w', stretch=False)
        self.vulns_tree.column('host', width=120, anchor='w', stretch=False)
        self.vulns_tree.column('port', width=60, anchor='center', stretch=False)
        
        self.vulns_tree.bind('<<TreeviewSelect>>', self._on_vuln_select)

    def display_results(self, scan_result: Optional[ScanResult], analysis_result: Optional[SecurityAnalysisResult]):
        self.clear_results()
        self.current_scan_result = scan_result
        self.current_analysis_result = analysis_result

        if scan_result:
            self._update_hosts_tab(scan_result)
        if analysis_result:
            self._update_vulnerabilities_tab(analysis_result)
    
    def _update_hosts_tab(self, scan_result: ScanResult):
        style = bttk.Style()
        self.hosts_tree.tag_configure('up', foreground=style.colors.success)
        self.hosts_tree.tag_configure('down', foreground=style.colors.secondary)
        for host in scan_result.hosts:
            tag = host.state.lower()
            open_ports = len([p for p in host.ports if p.state == 'open'])
            self.hosts_tree.insert('', 'end', values=(host.ip_address, host.hostname or "N/A", host.state, open_ports), iid=host.ip_address, tags=(tag,))

    def _update_vulnerabilities_tab(self, analysis_result: SecurityAnalysisResult):
        colors = create_severity_colors()
        severities = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severities:
            self.vulns_tree.tag_configure(severity, foreground=colors.get(severity, 'default'))
        
        for vuln in analysis_result.vulnerabilities:
            severity = vuln.get('severity', 'medium')
            self.vulns_tree.insert('', 'end', values=(severity.title(), vuln['host'], vuln.get('port', ''), vuln['vulnerability']), tags=(severity,))
        self._sort_tree(self.vulns_tree, 'severity', False, custom_sort_order=severities)
    
    def _on_host_select(self, event):
        if not self.selection_callback or not self.current_scan_result: return
        selection = self.hosts_tree.selection()
        if not selection: return
        
        host_ip = selection[0]
        host_data = next((h for h in self.current_scan_result.hosts if h.ip_address == host_ip), None)
        if host_data:
            self.selection_callback('host', host_data)
            
    def _on_vuln_select(self, event):
        if not self.selection_callback or not self.current_analysis_result: return
        selection = self.vulns_tree.selection()
        if not selection: return

        item = self.vulns_tree.item(selection[0])
        severity_str, host_ip, port_str, vuln_name = item['values']
        port = int(port_str) if port_str.isdigit() else None
        
        # Find the full vulnerability dictionary
        vuln_data = next((v for v in self.current_analysis_result.vulnerabilities if v['host'] == host_ip and v.get('port') == port and v['vulnerability'] == vuln_name), None)
        if vuln_data:
            self.selection_callback('vulnerability', vuln_data)

    def clear_results(self):
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        self.vulns_tree.delete(*self.vulns_tree.get_children())
        if self.selection_callback:
            self.selection_callback('clear', None)
    
    def select_tab_by_name(self, name: str):
        if name in self.tabs:
            self.notebook.select(self.tabs[name])

    def _sort_tree(self, tree: ttk.Treeview, col: str, is_numeric: bool, custom_sort_order: Optional[List[str]] = None):
        """Sort a treeview column when the heading is clicked."""
        data = [(tree.set(item, col), item) for item in tree.get_children('')]
        reverse = not getattr(tree, f"_{col}_order", False)
        
        if custom_sort_order:
            sort_map = {val.title(): i for i, val in enumerate(custom_sort_order)}
            default_index = len(sort_map)
            data.sort(key=lambda t: sort_map.get(t[0], default_index), reverse=reverse)
        elif is_numeric:
            data.sort(key=lambda t: int(t[0] or 0), reverse=reverse)
        else:
            data.sort(key=lambda t: str(t[0]).lower(), reverse=reverse)
            
        for index, (val, item) in enumerate(data):
            tree.move(item, '', index)
            
        setattr(tree, f"_{col}_order", reverse)