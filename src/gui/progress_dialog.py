"""Progress dialog for showing scan and analysis progress."""

import tkinter as tk
import ttkbootstrap as bttk
from typing import Optional, Callable
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ProgressDialog:
    """Modal progress dialog with cancel support."""
    
    def __init__(self, parent: tk.Tk, title: str, 
                 cancelable: bool = True, cancel_callback: Optional[Callable] = None):
        self.parent = parent
        self.cancel_callback = cancel_callback
        self.cancelled = False
        
        self.dialog = bttk.Toplevel(self.parent)
        self.dialog.title(title)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        self._center_dialog()
        self._create_widgets(cancelable)
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel if cancelable else self.dialog.bell)

        logger.debug(f"Progress dialog '{title}' created.")
    
    def _center_dialog(self):
        self.dialog.update_idletasks()
        width, height = 400, 180
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (width // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')

    def _create_widgets(self, cancelable: bool):
        main_frame = bttk.Frame(self.dialog, padding=15)
        main_frame.pack(fill='both', expand=True)

        self.status_var = tk.StringVar(value="Initializing...")
        status_label = bttk.Label(main_frame, textvariable=self.status_var, font=("-size 11 -weight bold"), anchor='center')
        status_label.pack(fill='x', pady=(5, 10))

        self.progress_bar = bttk.Progressbar(main_frame, mode='indeterminate', bootstyle="success-striped")
        self.progress_bar.pack(fill='x', expand=True, pady=(0, 10))
        self.progress_bar.start(10)

        self.detail_var = tk.StringVar(value="")
        detail_label = bttk.Label(main_frame, textvariable=self.detail_var, bootstyle="secondary", anchor='center')
        detail_label.pack(fill='x', pady=(0, 15))

        if cancelable:
            self.cancel_button = bttk.Button(main_frame, text="Cancel", command=self._on_cancel, bootstyle="danger-outline")
            self.cancel_button.pack(pady=(0, 5))
        
    def update_progress(self, percentage: Optional[float] = None, status: Optional[str] = None, detail: Optional[str] = None):
        if not self.dialog.winfo_exists(): return
        
        if status: self.status_var.set(status)
        if detail: self.detail_var.set(detail)
            
        if percentage is not None:
            if self.progress_bar.cget('mode') == 'indeterminate':
                self.progress_bar.stop()
                self.progress_bar.config(mode='determinate')
            self.progress_bar['value'] = percentage
        self.dialog.update_idletasks()
    
    def _on_cancel(self):
        if not self.cancelled:
            self.cancelled = True
            self.status_var.set("Cancelling...")
            self.detail_var.set("Please wait for the current task to terminate.")
            if hasattr(self, 'cancel_button'): self.cancel_button.config(state='disabled')
            
            if self.cancel_callback:
                try:
                    self.cancel_callback()
                except Exception as e:
                    logger.error(f"Error in cancel callback: {e}")

    def close(self):
        if self.dialog and self.dialog.winfo_exists():
            self.dialog.grab_release()
            self.dialog.destroy()
            logger.debug("Progress dialog closed.")
    
    def is_cancelled(self) -> bool:
        return self.cancelled