"""Progress dialog for showing scan and analysis progress."""

import tkinter as tk
from tkinter import ttk
import threading
from typing import Optional, Callable

from .styles import ReMapTheme, icon_manager
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ProgressDialog:
    """Modal progress dialog with cancel support."""
    
    def __init__(self, parent: tk.Tk, title: str = "Progress", 
                 cancelable: bool = True, cancel_callback: Optional[Callable] = None):
        self.parent = parent
        self.title = title
        self.cancelable = cancelable
        self.cancel_callback = cancel_callback
        self.cancelled = False
        
        self.dialog = None
        self.progress_var = None
        self.status_var = None
        self.detail_var = None
        
        self._create_dialog()
        logger.debug(f"Progress dialog created: {title}")
    
    def _create_dialog(self):
        """Create the progress dialog."""
        # Create top level window
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title(self.title)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Configure dialog
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=ReMapTheme.COLORS['background'])
        
        # Center dialog on parent
        self._center_dialog()
        
        # Create widgets
        self._create_widgets()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)
    
    def _center_dialog(self):
        """Center dialog on parent window."""
        try:
            # Get parent geometry
            parent_x = self.parent.winfo_x()
            parent_y = self.parent.winfo_y()
            parent_width = self.parent.winfo_width()
            parent_height = self.parent.winfo_height()
            
            # Calculate dialog position
            dialog_width = 400
            dialog_height = 200
            
            x = parent_x + (parent_width - dialog_width) // 2
            y = parent_y + (parent_height - dialog_height) // 2
            
            self.dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
            
        except Exception as e:
            logger.warning(f"Could not center dialog: {e}")
            self.dialog.geometry("400x200")
    
    def _create_widgets(self):
        """Create dialog widgets."""
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=ReMapTheme.SPACING['lg'])
        main_frame.pack(fill='both', expand=True)
        
        # Icon and title frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, ReMapTheme.SPACING['lg']))
        
        # Progress icon
        icon_label = ttk.Label(header_frame, text=icon_manager.get_icon('scan'), 
                              font=('Segoe UI', 16))
        icon_label.pack(side='left', padx=(0, ReMapTheme.SPACING['md']))
        
        # Title label
        title_label = ttk.Label(header_frame, text=self.title, 
                               style='Heading.TLabel')
        title_label.pack(side='left')
        
        # Status label
        self.status_var = tk.StringVar(value="Initializing...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var,
                                style='Subheading.TLabel')
        status_label.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var,
                                      style='Custom.Horizontal.TProgressbar',
                                      mode='indeterminate')
        progress_bar.pack(fill='x', pady=(0, ReMapTheme.SPACING['md']))
        progress_bar.start(10)  # Start animation
        
        # Detail label (smaller text for additional info)
        self.detail_var = tk.StringVar(value="")
        detail_label = ttk.Label(main_frame, textvariable=self.detail_var,
                                style='Muted.TLabel', font=ReMapTheme.FONTS['small'])
        detail_label.pack(fill='x', pady=(0, ReMapTheme.SPACING['lg']))
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x')
        
        # Cancel button (if cancelable)
        if self.cancelable:
            cancel_button = ttk.Button(button_frame, text="Cancel",
                                      style='Secondary.TButton',
                                      command=self._on_cancel)
            cancel_button.pack(side='right')
        
        # Store references
        self.progress_bar = progress_bar
        self.cancel_button = cancel_button if self.cancelable else None
    
    def update_progress(self, percentage: Optional[float] = None, 
                       status: Optional[str] = None, 
                       detail: Optional[str] = None):
        """Update progress dialog."""
        try:
            if not self.dialog or not self.dialog.winfo_exists():
                return
            
            if percentage is not None:
                # Switch to determinate mode if needed
                if self.progress_bar['mode'] == 'indeterminate':
                    self.progress_bar.stop()
                    self.progress_bar.configure(mode='determinate')
                
                self.progress_var.set(percentage)
            
            if status is not None:
                self.status_var.set(status)
            
            if detail is not None:
                self.detail_var.set(detail)
            
            # Update dialog
            self.dialog.update_idletasks()
            
        except Exception as e:
            logger.error(f"Error updating progress dialog: {e}")
    
    def set_indeterminate(self, indeterminate: bool = True):
        """Set progress bar to indeterminate or determinate mode."""
        try:
            if not self.dialog or not self.dialog.winfo_exists():
                return
            
            if indeterminate:
                if self.progress_bar['mode'] != 'indeterminate':
                    self.progress_bar.configure(mode='indeterminate')
                    self.progress_bar.start(10)
            else:
                if self.progress_bar['mode'] != 'determinate':
                    self.progress_bar.stop()
                    self.progress_bar.configure(mode='determinate')
                    self.progress_var.set(0)
            
        except Exception as e:
            logger.error(f"Error setting progress mode: {e}")
    
    def _on_cancel(self):
        """Handle cancel button or window close."""
        try:
            if self.cancelable and not self.cancelled:
                self.cancelled = True
                
                # Update UI
                if self.cancel_button:
                    self.cancel_button.configure(state='disabled', text="Cancelling...")
                
                self.status_var.set("Cancelling...")
                self.detail_var.set("Please wait while the operation is cancelled...")
                
                # Call cancel callback
                if self.cancel_callback:
                    try:
                        self.cancel_callback()
                    except Exception as e:
                        logger.error(f"Error in cancel callback: {e}")
                
                # Close after short delay to show cancellation message
                self.dialog.after(1000, self.close)
            else:
                self.close()
                
        except Exception as e:
            logger.error(f"Error handling cancel: {e}")
            self.close()
    
    def close(self):
        """Close the progress dialog."""
        try:
            if self.dialog and self.dialog.winfo_exists():
                self.dialog.grab_release()
                self.dialog.destroy()
                
            logger.debug("Progress dialog closed")
            
        except Exception as e:
            logger.error(f"Error closing progress dialog: {e}")
    
    def is_cancelled(self) -> bool:
        """Check if dialog was cancelled."""
        return self.cancelled
    
    def show(self):
        """Show the dialog (modal)."""
        try:
            if self.dialog and self.dialog.winfo_exists():
                self.dialog.deiconify()
                self.dialog.focus_set()
                
        except Exception as e:
            logger.error(f"Error showing progress dialog: {e}")
    
    def hide(self):
        """Hide the dialog."""
        try:
            if self.dialog and self.dialog.winfo_exists():
                self.dialog.withdraw()
                
        except Exception as e:
            logger.error(f"Error hiding progress dialog: {e}")

class ProgressManager:
    """Manager for progress dialogs and status updates."""
    
    def __init__(self, parent: tk.Tk):
        self.parent = parent
        self.current_dialog: Optional[ProgressDialog] = None
        self.progress_callback: Optional[Callable] = None
    
    def start_progress(self, title: str = "Progress", cancelable: bool = True,
                      cancel_callback: Optional[Callable] = None) -> ProgressDialog:
        """Start a new progress dialog."""
        try:
            # Close existing dialog
            self.stop_progress()
            
            # Create new dialog
            self.current_dialog = ProgressDialog(
                self.parent, title, cancelable, cancel_callback
            )
            
            self.current_dialog.show()
            return self.current_dialog
            
        except Exception as e:
            logger.error(f"Error starting progress dialog: {e}")
            return None
    
    def update_progress(self, percentage: Optional[float] = None,
                       status: Optional[str] = None,
                       detail: Optional[str] = None):
        """Update current progress dialog."""
        try:
            if self.current_dialog:
                self.current_dialog.update_progress(percentage, status, detail)
                
            # Also call callback if set
            if self.progress_callback:
                self.progress_callback(percentage, status, detail)
                
        except Exception as e:
            logger.error(f"Error updating progress: {e}")
    
    def stop_progress(self):
        """Stop and close current progress dialog."""
        try:
            if self.current_dialog:
                self.current_dialog.close()
                self.current_dialog = None
                
        except Exception as e:
            logger.error(f"Error stopping progress: {e}")
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates."""
        self.progress_callback = callback
    
    def is_progress_active(self) -> bool:
        """Check if progress dialog is active."""
        return self.current_dialog is not None
    
    def is_cancelled(self) -> bool:
        """Check if current progress was cancelled."""
        if self.current_dialog:
            return self.current_dialog.is_cancelled()
        return False