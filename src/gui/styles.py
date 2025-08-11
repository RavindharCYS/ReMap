"""GUI styling and themes for ReMap application."""
import ttkbootstrap as bttk
from typing import Dict

# All styling is now handled by ttkbootstrap. This file provides helpers
# and constants related to the UI's appearance.

DEFAULT_THEME = "superhero" # Good dark theme. Try "cosmo" or "litera" for light themes.

# Define fonts for widgets that don't get styled automatically by ttk, like tk.Text
FONTS = {
    'default': ('Segoe UI', 10),
    'code': ('Consolas', 10, 'normal'),
    'small': ('Segoe UI', 8)
}

class IconManager:
    """Manage icons and images for the GUI (uses simple text symbols)."""
    def __init__(self):
        self.icons = {
            'scan': '🔍', 'settings': '⚙️', 'report': '📊', 'info': 'ℹ️',
            'network': '🌐', 'security': '🛡️', 'web': '🌍',
        }
    def get_icon(self, name: str) -> str:
        return self.icons.get(name, '●')

# Create a single global instance for the app to use
icon_manager = IconManager()

def create_severity_colors() -> Dict[str, str]:
    """Create vulnerability severity color mapping for use with treeview tags."""
    style = bttk.Style()
    return {
        'critical': style.colors.get('danger'),
        'high': style.colors.get('warning'),
        'medium': style.colors.get('info'),
        'low': style.colors.get('success'),
        'info': style.colors.get('secondary')
    }