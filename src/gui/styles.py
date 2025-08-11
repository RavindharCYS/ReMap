"""GUI styling and themes for ReMap application."""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any

class ReMapTheme:
    """Theme configuration for ReMap GUI."""
    
    # Color palette
    COLORS = {
        'primary': '#667eea',
        'primary_dark': '#5a6fd8',
        'primary_light': '#7a8ef2',
        'secondary': '#764ba2',
        'accent': '#f093fb',
        'background': '#f8f9fa',
        'surface': '#ffffff',
        'error': '#dc3545',
        'warning': '#ffc107',
        'success': '#28a745',
        'info': '#17a2b8',
        'dark': '#343a40',
        'light': '#f8f9fa',
        'muted': '#6c757d',
        'text': '#212529',
        'text_muted': '#6c757d',
        'border': '#dee2e6',
        'hover': '#e9ecef'
    }
    
    # Fonts
    FONTS = {
        'default': ('Segoe UI', 9),
        'heading': ('Segoe UI', 12, 'bold'),
        'subheading': ('Segoe UI', 10, 'bold'),
        'code': ('Consolas', 9),
        'large': ('Segoe UI', 11),
        'small': ('Segoe UI', 8)
    }
    
    # Padding and margins
    SPACING = {
        'xs': 2,
        'sm': 5,
        'md': 10,
        'lg': 15,
        'xl': 20,
        'xxl': 30
    }

def configure_styles():
    """Configure ttk styles for the application."""
    style = ttk.Style()
    
    # Configure theme
    style.theme_use('clam')
    
    # Configure styles
    configure_button_styles(style)
    configure_frame_styles(style)
    configure_entry_styles(style)
    configure_treeview_styles(style)
    configure_progressbar_styles(style)
    configure_label_styles(style)
    configure_notebook_styles(style)

def configure_button_styles(style: ttk.Style):
    """Configure button styles."""
    # Primary button
    style.configure('Primary.TButton',
                   background=ReMapTheme.COLORS['primary'],
                   foreground='white',
                   borderwidth=0,
                   focuscolor='none',
                   padding=(15, 8))
    
    style.map('Primary.TButton',
              background=[('active', ReMapTheme.COLORS['primary_dark']),
                         ('pressed', ReMapTheme.COLORS['primary_dark'])])
    
    # Success button
    style.configure('Success.TButton',
                   background=ReMapTheme.COLORS['success'],
                   foreground='white',
                   borderwidth=0,
                   focuscolor='none',
                   padding=(15, 8))
    
    style.map('Success.TButton',
              background=[('active', '#218838'),
                         ('pressed', '#1e7e34')])
    
    # Danger button
    style.configure('Danger.TButton',
                   background=ReMapTheme.COLORS['error'],
                   foreground='white',
                   borderwidth=0,
                   focuscolor='none',
                   padding=(15, 8))
    
    style.map('Danger.TButton',
              background=[('active', '#c82333'),
                         ('pressed', '#bd2130')])
    
    # Warning button
    style.configure('Warning.TButton',
                   background=ReMapTheme.COLORS['warning'],
                   foreground=ReMapTheme.COLORS['dark'],
                   borderwidth=0,
                   focuscolor='none',
                   padding=(15, 8))
    
    style.map('Warning.TButton',
              background=[('active', '#e0a800'),
                         ('pressed', '#d39e00')])
    
    # Secondary button
    style.configure('Secondary.TButton',
                   background=ReMapTheme.COLORS['muted'],
                   foreground='white',
                   borderwidth=0,
                   focuscolor='none',
                   padding=(15, 8))
    
    style.map('Secondary.TButton',
              background=[('active', '#545b62'),
                         ('pressed', '#4e555b')])

def configure_frame_styles(style: ttk.Style):
    """Configure frame styles."""
    # Card frame
    style.configure('Card.TFrame',
                   background=ReMapTheme.COLORS['surface'],
                   relief='solid',
                   borderwidth=1)
    
    # Header frame
    style.configure('Header.TFrame',
                   background=ReMapTheme.COLORS['primary'],
                   relief='flat')
    
    # Sidebar frame
    style.configure('Sidebar.TFrame',
                   background=ReMapTheme.COLORS['light'],
                   relief='solid',
                   borderwidth=1)
    
    # Status frame
    style.configure('Status.TFrame',
                   background=ReMapTheme.COLORS['background'],
                   relief='sunken',
                   borderwidth=1)

def configure_entry_styles(style: ttk.Style):
    """Configure entry styles."""
    style.configure('Custom.TEntry',
                   padding=(8, 5),
                   borderwidth=1,
                   relief='solid')
    
    style.map('Custom.TEntry',
              bordercolor=[('focus', ReMapTheme.COLORS['primary']),
                          ('!focus', ReMapTheme.COLORS['border'])])

def configure_treeview_styles(style: ttk.Style):
    """Configure treeview styles."""
    style.configure('Custom.Treeview',
                   background=ReMapTheme.COLORS['surface'],
                   foreground=ReMapTheme.COLORS['text'],
                   fieldbackground=ReMapTheme.COLORS['surface'],
                   borderwidth=1,
                   relief='solid')
    
    style.configure('Custom.Treeview.Heading',
                   background=ReMapTheme.COLORS['primary'],
                   foreground='white',
                   borderwidth=1,
                   relief='solid')
    
    style.map('Custom.Treeview',
              background=[('selected', ReMapTheme.COLORS['primary']),
                         ('focus', ReMapTheme.COLORS['primary_light'])])
    
    style.map('Custom.Treeview.Heading',
              background=[('active', ReMapTheme.COLORS['primary_dark'])])

def configure_progressbar_styles(style: ttk.Style):
    """Configure progressbar styles."""
    style.configure('Custom.Horizontal.TProgressbar',
                   background=ReMapTheme.COLORS['primary'],
                   troughcolor=ReMapTheme.COLORS['border'],
                   borderwidth=0,
                   lightcolor=ReMapTheme.COLORS['primary'],
                   darkcolor=ReMapTheme.COLORS['primary'])

def configure_label_styles(style: ttk.Style):
    """Configure label styles."""
    # Heading label
    style.configure('Heading.TLabel',
                   font=ReMapTheme.FONTS['heading'],
                   foreground=ReMapTheme.COLORS['text'],
                   background=ReMapTheme.COLORS['background'])
    
    # Subheading label
    style.configure('Subheading.TLabel',
                   font=ReMapTheme.FONTS['subheading'],
                   foreground=ReMapTheme.COLORS['text'],
                   background=ReMapTheme.COLORS['background'])
    
    # Success label
    style.configure('Success.TLabel',
                   foreground=ReMapTheme.COLORS['success'],
                   background=ReMapTheme.COLORS['background'])
    
    # Error label
    style.configure('Error.TLabel',
                   foreground=ReMapTheme.COLORS['error'],
                   background=ReMapTheme.COLORS['background'])
    
    # Warning label
    style.configure('Warning.TLabel',
                   foreground=ReMapTheme.COLORS['warning'],
                   background=ReMapTheme.COLORS['background'])
    
    # Muted label
    style.configure('Muted.TLabel',
                   foreground=ReMapTheme.COLORS['text_muted'],
                   background=ReMapTheme.COLORS['background'])

def configure_notebook_styles(style: ttk.Style):
    """Configure notebook styles."""
    style.configure('Custom.TNotebook',
                   background=ReMapTheme.COLORS['background'],
                   borderwidth=1)
    
    style.configure('Custom.TNotebook.Tab',
                   background=ReMapTheme.COLORS['light'],
                   foreground=ReMapTheme.COLORS['text'],
                   padding=(12, 8),
                   borderwidth=1)
    
    style.map('Custom.TNotebook.Tab',
              background=[('selected', ReMapTheme.COLORS['primary']),
                         ('active', ReMapTheme.COLORS['hover'])],
              foreground=[('selected', 'white'),
                         ('active', ReMapTheme.COLORS['text'])])

def apply_widget_style(widget, style_name: str = None, **kwargs):
    """Apply custom style to a widget."""
    if style_name:
        if hasattr(widget, 'configure'):
            widget.configure(style=style_name)
    
    # Apply additional styling options
    for option, value in kwargs.items():
        try:
            widget.configure(**{option: value})
        except tk.TclError:
            pass  # Ignore invalid options

def create_status_colors() -> Dict[str, str]:
    """Create status color mapping."""
    return {
        'up': ReMapTheme.COLORS['success'],
        'down': ReMapTheme.COLORS['error'],
        'open': ReMapTheme.COLORS['success'],
        'closed': ReMapTheme.COLORS['error'],
        'filtered': ReMapTheme.COLORS['warning'],
        'unknown': ReMapTheme.COLORS['muted'],
        'running': ReMapTheme.COLORS['info'],
        'completed': ReMapTheme.COLORS['success'],
        'failed': ReMapTheme.COLORS['error'],
        'cancelled': ReMapTheme.COLORS['warning'],
        'idle': ReMapTheme.COLORS['muted']
    }

def create_severity_colors() -> Dict[str, str]:
    """Create vulnerability severity color mapping."""
    return {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745',
        'info': '#17a2b8'
    }

class ToolTip:
    """Create a tooltip for a given widget."""
    
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.tipwindow = None
    
    def enter(self, event=None):
        self.showtip()
    
    def leave(self, event=None):
        self.hidetip()
    
    def showtip(self):
        if self.tipwindow or not self.text:
            return
        
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                        background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                        font=ReMapTheme.FONTS['small'])
        label.pack(ipadx=1)
    
    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

def create_scrollable_frame(parent, **kwargs):
    """Create a scrollable frame widget."""
    # Create main frame
    main_frame = ttk.Frame(parent, **kwargs)
    
    # Create canvas and scrollbar
    canvas = tk.Canvas(main_frame, highlightthickness=0)
    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack widgets
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Store references
    main_frame.canvas = canvas
    main_frame.scrollable_frame = scrollable_frame
    main_frame.scrollbar = scrollbar
    
    # Bind mousewheel
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    canvas.bind("<MouseWheel>", _on_mousewheel)
    
    return main_frame

class IconManager:
    """Manage icons and images for the GUI."""
    
    def __init__(self):
        self.icons = {}
        self._load_default_icons()
    
    def _load_default_icons(self):
        """Load default icons (placeholder implementation)."""
        # In a real implementation, you would load actual icon files
        # For now, we'll use text-based icons
        self.icons = {
            'scan': '🔍',
            'settings': '⚙️',
            'report': '📊',
            'export': '💾',
            'help': '❓',
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'success': '✅',
            'play': '▶️',
            'stop': '⏹️',
            'pause': '⏸️',
            'refresh': '🔄',
            'folder': '📁',
            'file': '📄',
            'network': '🌐',
            'security': '🔒',
            'vulnerability': '🛡️',
            'web': '🌍'
        }
    
    def get_icon(self, name: str) -> str:
        """Get icon by name."""
        return self.icons.get(name, '❓')
    
    def add_icon(self, name: str, icon: str):
        """Add custom icon."""
        self.icons[name] = icon

# Global icon manager instance
icon_manager = IconManager()