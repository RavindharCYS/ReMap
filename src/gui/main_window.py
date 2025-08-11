"""Main GUI window for ReMap application."""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
from typing import Optional, Dict, Any, Callable
import ttkbootstrap as bttk
from ttkbootstrap.constants import *
from pathlib import Path

from .target_input_frame import TargetInputFrame
from .scan_options_frame import ScanOptionsFrame
from .results_frame import ResultsFrame
from .log_viewer import LogViewerWindow
from .progress_dialog import ProgressDialog
from .styles import DEFAULT_THEME, FONTS, icon_manager
from ..core.scanner import Scanner, ScanStatus
from ..models.settings import ScanSettings
from ..models.scan_result import ScanResult, Host
from ..analysis.security_analyzer import SecurityAnalyzer, SecurityAnalysisResult
from ..reports.export_manager import ExportManager
from ..utils.logger import setup_logger
from ..utils.config import ConfigManager
from ..core.xml_parser import NmapXMLParser

logger = setup_logger(__name__)

class MainWindow:
    """Main application window."""

    def __init__(self, settings: ScanSettings, config_manager: ConfigManager):
        # The MainWindow now creates its own root window.
        self.root = bttk.Window(themename=DEFAULT_THEME)
        
        self.settings = settings
        self.config_manager = config_manager

        self.scanner = Scanner(settings)
        self.security_analyzer = SecurityAnalyzer()
        
        self.current_scan_result: Optional[ScanResult] = None
        self.current_analysis_result: Optional[SecurityAnalysisResult] = None
        
        self._setup_gui()
        self._setup_callbacks()
        logger.info("Main window initialized with ttkbootstrap.")

    # ... all other methods in MainWindow remain exactly the same ...
    def _setup_gui(self):
        self.root.title("ReMap - Network Security Scanner")
        self.root.geometry(f"{self.settings.window_width}x{self.settings.window_height}")
        self.root.minsize(1024, 700)
        
        self._create_menu_bar()
        self._create_main_layout()
        self._create_status_bar()

    def _create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        self.file_menu = tk.Menu(menubar, tearoff=0)
        self.file_menu.add_command(label="New Scan Session", command=self.clear_all, accelerator="Ctrl+N")
        self.file_menu.add_command(label="Load Scan from XML...", command=self.load_xml_results, accelerator="Ctrl+O")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Export Report...", command=self.export_report, accelerator="Ctrl+E", state="disabled")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.exit_application)
        menubar.add_cascade(label="File", menu=self.file_menu)

        # Scan Menu
        self.scan_menu = tk.Menu(menubar, tearoff=0)
        self.scan_menu.add_command(label="Start Scan", command=self.start_scan, accelerator="F5")
        self.scan_menu.add_command(label="Cancel Scan", command=self.stop_scan, accelerator="Esc", state="disabled")
        menubar.add_cascade(label="Scan", menu=self.scan_menu)
        
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Run Analysis", command=self.run_analysis, state="disabled")
        self.analysis_menu_item = tools_menu
        tools_menu.add_separator()
        tools_menu.add_command(label="View Logs", command=self.view_logs)

        # Keyboard shortcuts
        self.root.bind('<Control-n>', lambda e: self.clear_all())
        self.root.bind('<Control-o>', lambda e: self.load_xml_results())
        self.root.bind('<Control-e>', lambda e: self.export_report())
        self.root.bind('<F5>', lambda e: self.start_scan())
        self.root.bind('<Escape>', lambda e: self.stop_scan())

    def _create_main_layout(self):
        main_paned = bttk.PanedWindow(self.root, orient=HORIZONTAL)
        main_paned.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # --- Left Control Panel ---
        left_panel = bttk.Frame(main_paned, padding=10)
        self.target_input_frame = TargetInputFrame(left_panel)
        self.target_input_frame.pack(fill=X, pady=(0, 10))
        self.scan_options_frame = ScanOptionsFrame(left_panel)
        self.scan_options_frame.pack(fill=X, pady=(0, 15))
        self._create_action_buttons(left_panel)
        main_paned.add(left_panel, weight=1)

        # --- Right Results Panel (Vertically Paned) ---
        right_v_paned = bttk.PanedWindow(main_paned, orient=VERTICAL)
        main_paned.add(right_v_paned, weight=3)

        self.results_frame = ResultsFrame(right_v_paned)
        right_v_paned.add(self.results_frame, weight=2)
        
        # Detail view frame
        self.detail_frame = bttk.LabelFrame(right_v_paned, text="Details", padding=10)
        self.detail_text = tk.Text(self.detail_frame, wrap=WORD, font=FONTS['code'], state=DISABLED, bd=0, relief='flat')
        self.detail_text.pack(fill=BOTH, expand=True)
        style = bttk.Style()
        self.detail_text.config(background=style.colors.get('bg'), foreground=style.colors.get('fg'))
        right_v_paned.add(self.detail_frame, weight=1)

    def _create_action_buttons(self, parent):
        button_frame = bttk.Frame(parent)
        button_frame.pack(fill=X, pady=(10, 0))
        
        self.start_button = bttk.Button(button_frame, text="Start Scan", bootstyle="success", command=self.start_scan)
        self.start_button.pack(side=LEFT, fill=X, expand=True, padx=(0, 5))
        
        self.stop_button = bttk.Button(button_frame, text="Cancel", bootstyle="danger", command=self.stop_scan, state=DISABLED)
        self.stop_button.pack(side=LEFT, fill=X, expand=True)

    def _create_status_bar(self):
        self.status_bar = bttk.Frame(self.root, padding=(10, 5), bootstyle="primary")
        self.status_bar.pack(side=BOTTOM, fill=X)
        self.status_message_var = tk.StringVar(value="Ready")
        bttk.Label(self.status_bar, textvariable=self.status_message_var, bootstyle="inverse-primary").pack(side=LEFT)
        self.scan_progress_bar = bttk.Progressbar(self.status_bar, bootstyle="success-striped", length=200)

    def _setup_callbacks(self):
        self.scanner.set_progress_callback(self._on_scan_progress)
        self.scanner.set_completion_callback(self._on_scan_complete)
        self.root.protocol("WM_DELETE_WINDOW", self.exit_application)
        self.results_frame.set_selection_callback(self.display_details)

    def start_scan(self):
        if self.scanner.is_scanning(): return
        try:
            targets = self.target_input_frame.get_targets()
            if not targets:
                messagebox.showerror("No Targets", "Please enter at least one target.")
                return
            
            self._update_scanner_settings_from_ui()
            self._set_ui_state_scanning(True)
            self.scanner.start_scan(targets, self.settings.default_scan_type)

        except Exception as e:
            logger.error(f"Failed to start scan: {e}", exc_info=True)
            messagebox.showerror("Scan Error", f"An error occurred while starting the scan:\n{e}")
            self._set_ui_state_scanning(False)
    
    def _update_scanner_settings_from_ui(self):
        ui_options = self.scan_options_frame.get_options()
        for key, value in ui_options.items():
            if hasattr(self.settings, key):
                setattr(self.settings, key, value)
        self.scanner.update_settings(self.settings)

    def stop_scan(self):
        if self.scanner.is_scanning():
            self.scanner.cancel_scan()
            self.status_message_var.set("Cancelling scan...")

    def run_analysis(self):
        if not self.current_scan_result:
            messagebox.showerror("No Data", "Please run a scan or load results first.")
            return

        analysis_options = { 'tls_check': True, 'ssl_check': True, 'smb_check': True, 'web_detection': True }
        
        progress = ProgressDialog(self.root, "Analysis in Progress", cancelable=False)

        def _analysis_thread_target():
            result = self.security_analyzer.analyze_scan_results(self.current_scan_result, analysis_options)
            self.root.after(0, self._finalize_analysis, result, progress)

        threading.Thread(target=_analysis_thread_target, daemon=True).start()

    def _finalize_analysis(self, result: SecurityAnalysisResult, progress: ProgressDialog):
        progress.close()
        self.current_analysis_result = result
        self.results_frame.display_results(self.current_scan_result, result)
        self.status_message_var.set(f"Analysis complete. Found {len(result.vulnerabilities)} potential issues.")
        self.results_frame.select_tab_by_name("Vulnerabilities")
        
    def _on_scan_progress(self, message: str):
        self.root.after(0, self.status_message_var.set, message)

    def _on_scan_complete(self, scan_result: Optional[ScanResult], success: bool):
        self.root.after(0, self._finalize_scan, scan_result, success)
    
    def _finalize_scan(self, scan_result, success):
        self._set_ui_state_scanning(False)
        if success and scan_result:
            self.current_scan_result = scan_result
            self.results_frame.display_results(scan_result, None)
            self.file_menu.entryconfig("Export Report...", state="normal")
            self.analysis_menu_item.entryconfig("Run Analysis", state="normal")
            self.status_message_var.set(f"Scan complete. Found {scan_result.hosts_up} active hosts.")
        elif not self.scanner.cancel_event.is_set():
             self.status_message_var.set("Scan failed. Check logs.")
             messagebox.showerror("Scan Failed", "Scan failed. Please check logs for details.")

    def _set_ui_state_scanning(self, is_scanning: bool):
        state = DISABLED if is_scanning else NORMAL
        self.start_button.config(state=state)
        self.target_input_frame.set_state(state)
        self.scan_options_frame.set_state(state)
        
        self.stop_button.config(state=NORMAL if is_scanning else DISABLED)
        self.scan_menu.entryconfig("Start Scan", state=state)
        self.scan_menu.entryconfig("Cancel Scan", state=NORMAL if is_scanning else DISABLED)
        self.file_menu.entryconfig("Load Scan from XML...", state=state)
        self.analysis_menu_item.entryconfig("Run Analysis", state=DISABLED if is_scanning else NORMAL if self.current_scan_result else DISABLED)

        if is_scanning:
            self.scan_progress_bar.pack(side=RIGHT, padx=10)
            self.scan_progress_bar.start()
        else:
            self.scan_progress_bar.stop()
            self.scan_progress_bar.pack_forget()

    def display_details(self, detail_type: str, data: Any):
        if detail_type == 'host' and data:
            details = f"IP: {data.ip_address}\nHostname: {data.hostname or 'N/A'}\nOS: {data.os_info or 'N/A'}\n\n--- PORTS ---\n"
            details += "{:<8} {:<10} {:<20} {}\n".format("Port", "State", "Service", "Version")
            details += "-"*65 + "\n"
            for port in sorted(data.ports, key=lambda p: p.number):
                details += f"{port.number}/{port.protocol:<7} {port.state:<10} {port.service or '':<20} {port.version or ''}\n"
        elif detail_type == 'vulnerability' and data:
            details = f"Vulnerability: {data['vulnerability']}\nSeverity: {data['severity'].title()}\n\n"
            details += f"Host: {data['host']}\nPort: {data['port'] or 'N/A'}\n\n--- DETAILS ---\n{data.get('details', 'No additional details available.')}"
        else:
            details = "Select an item to see details."

        self.detail_text.config(state=NORMAL)
        self.detail_text.delete('1.0', END)
        self.detail_text.insert('1.0', details)
        self.detail_text.config(state=DISABLED)
        
    def load_xml_results(self):
        scans_dir = self.config_manager.config_dir / "scans"
        scans_dir.mkdir(exist_ok=True, parents=True)
        file_path = filedialog.askopenfilename(
            title="Load Nmap XML Results",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            initialdir=scans_dir
        )
        if not file_path: return
        try:
            scan_result = NmapXMLParser.parse_xml_file(file_path)
            self.clear_all()
            self.current_scan_result = scan_result
            self.results_frame.display_results(scan_result, None)
            self.file_menu.entryconfig("Export Report...", state="normal")
            self.analysis_menu_item.entryconfig("Run Analysis", state="normal")
            self.status_message_var.set(f"Loaded results from {Path(file_path).name}")
        except Exception as e:
            logger.error(f"Failed to load XML file {file_path}: {e}", exc_info=True)
            messagebox.showerror("Load Error", f"Could not load or parse the XML file:\n{e}")
    
    def export_report(self):
        if not self.current_scan_result:
            messagebox.showerror("No Data", "No results to export.")
            return
            
        reports_dir = self.config_manager.config_dir / "reports"
        reports_dir.mkdir(exist_ok=True, parents=True)    
        file_path = filedialog.asksaveasfilename(
            title="Export Report", defaultextension=".html",
            initialdir=reports_dir,
            filetypes=[("HTML Report", "*.html"), ("JSON Report", "*.json"), ("CSV Report", "*.csv")]
        )
        if not file_path: return

        try:
            ext = Path(file_path).suffix[1:].lower()
            export_manager = ExportManager()
            export_manager.export_comprehensive_report(
                self.current_scan_result, self.current_analysis_result,
                export_formats=[ext], output_directory=str(Path(file_path).parent)
            )
            messagebox.showinfo("Export Successful", f"Report saved to {file_path}")
        except Exception as e:
            logger.error(f"Failed to export report: {e}", exc_info=True)
            messagebox.showerror("Export Error", f"An error occurred during export:\n{e}")
            
    def clear_all(self):
        self.current_scan_result = None
        self.current_analysis_result = None
        self.target_input_frame.clear()
        self.results_frame.clear_results()
        self.display_details("clear", None)
        self.file_menu.entryconfig("Export Report...", state="disabled")
        self.analysis_menu_item.entryconfig("Run Analysis", state="disabled")
        self.status_message_var.set("Ready")

    def show_settings(self):
        messagebox.showinfo("Settings", "In a full app, a detailed settings dialog would open here.\nFor now, settings are managed in `~/.remap/settings.json`.")

    def view_logs(self):
        try:
            LogViewerWindow(self.root)
        except Exception as e:
            logger.error(f"Could not open log viewer: {e}")
            messagebox.showerror("Error", "Could not open the log viewer window.")
            
    def exit_application(self):
        if self.scanner.is_scanning():
            if messagebox.askyesno("Confirm Exit", "A scan is running. Do you want to stop it and exit?"):
                self.stop_scan()
            else:
                return

        if self.settings.remember_window:
            self.settings.window_width = self.root.winfo_width()
            self.settings.window_height = self.root.winfo_height()
        
        self.config_manager.save_settings(self.settings)
        self.root.destroy()