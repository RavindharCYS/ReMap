"""Main entry point for ReMap application."""
import sys
import argparse
import tkinter as tk
# We don't need ttkbootstrap here anymore, MainWindow handles it.
import warnings

# Set up path if running as a script
if __package__ is None or __package__ == '':
    from pathlib import Path
    src_path = Path(__file__).parent.resolve()
    sys.path.insert(0, str(src_path.parent))

from src.gui.main_window import MainWindow
from src.utils.logger import setup_logger
from src.utils.config import ConfigManager

warnings.filterwarnings("ignore", category=DeprecationWarning)

logger = setup_logger("ReMap")

def main():
    """Main application entry point."""
    try:
        parser = argparse.ArgumentParser(description="ReMap - Network Security Scanner")
        parser.parse_args()

        config_manager = ConfigManager()
        settings = config_manager.load_settings()
        start_gui(settings, config_manager)

    except KeyboardInterrupt:
        logger.info("Application interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"A critical error occurred on startup: {e}", exc_info=True)
        try:
            root = tk.Tk()
            root.withdraw()
            tk.messagebox.showerror(
                "Critical Error",
                f"An unexpected error occurred.\n\nError: {e}\n\nPlease check logs for details."
            )
        finally:
            sys.exit(1)

def start_gui(settings, config_manager):
    """Initializes and starts the main GUI application window."""
    try:
        logger.info("Starting ReMap GUI...")
        
        # MainWindow will create its own root window now.
        # We don't need to create one here.
        app = MainWindow(settings, config_manager)
        
        # The mainloop is called on the root window created inside MainWindow.
        app.root.mainloop()

    except Exception as e:
        logger.error("A fatal error occurred during GUI startup.", exc_info=True)
        try:
            err_root = tk.Tk()
            err_root.withdraw()
            tk.messagebox.showerror(
                "GUI Startup Failed",
                f"The graphical interface could not be started.\n\nError: {e}"
            )
        finally:
            sys.exit(1)

if __name__ == "__main__":
    main()