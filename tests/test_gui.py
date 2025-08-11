"""Tests for GUI components."""

import unittest
import tkinter as tk
from src.gui.main_window import MainWindow
from src.utils.config import ConfigManager

class TestMainWindow(unittest.TestCase):

    def setUp(self):
        """Set up the Tkinter root window and MainWindow instance."""
        # This prevents the main window from appearing during tests
        self.root = tk.Tk()
        self.root.withdraw() 
        self.config_manager = ConfigManager()
        self.settings = self.config_manager.load_settings()

    def test_main_window_creation(self):
        """Test if the main window can be created without errors."""
        try:
            app = MainWindow(self.root, self.settings, self.config_manager)
            self.assertIsInstance(app, MainWindow)
        except Exception as e:
            self.fail(f"MainWindow creation failed with exception: {e}")

    def tearDown(self):
        """Destroy the Tkinter root window."""
        self.root.destroy()

if __name__ == '__main__':
    unittest.main()