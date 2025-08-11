"""Main entry point for ReMap application."""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to path for imports
src_path = Path(__file__).parent
sys.path.insert(0, str(src_path))

from utils.logger import setup_logger
from utils.config import ConfigManager
from models.settings import ScanSettings

logger = setup_logger(__name__)

def main():
    """Main application entry point."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Initialize configuration
        config_manager = ConfigManager()
        settings = config_manager.load_settings()
        
        # Start appropriate interface
        if args.gui or not any([args.target, args.file, args.xml]):
            # Start GUI
            start_gui(settings)
        else:
            # Start CLI
            start_cli(args, settings)
            
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ReMap - Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  remap --gui                           # Start GUI interface
  remap -t 192.168.1.1-100             # Quick scan range
  remap -f targets.txt --scan-type all # Scan from file
  remap --xml scan_results.xml         # Load existing scan
        """
    )
    
    # Interface options
    parser.add_argument('--gui', action='store_true',
                       help='Start GUI interface (default if no other options)')
    
    # Target options
    parser.add_argument('-t', '--target', type=str,
                       help='Target IP address or range (e.g., 192.168.1.1-100)')
    
    parser.add_argument('-f', '--file', type=str,
                       help='File containing target list')
    
    # Scan options
    parser.add_argument('--scan-type', choices=['fast', '1000', 'all'], 
                       default='fast', help='Scan type (default: fast)')
    
    # Analysis options
    parser.add_argument('--xml', type=str,
                       help='Load existing XML scan results for analysis')
    
    parser.add_argument('--analyze', action='store_true',
                       help='Perform security analysis on results')
    
    parser.add_argument('--tls-check', action='store_true',
                       help='Check TLS versions and configurations')
    
    parser.add_argument('--ssl-check', action='store_true',
                       help='Check SSL certificates')
    
    parser.add_argument('--smb-check', action='store_true',
                       help='Check SMB signing configuration')
    
    # Output options
    parser.add_argument('-o', '--output', type=str,
                       help='Output file path for reports')
    
    parser.add_argument('--format', choices=['html', 'json', 'csv', 'xml', 'txt'],
                       default='html', help='Report format (default: html)')
    
    # Rate limiting
    parser.add_argument('--rate-limit', type=int, default=100,
                       help='Rate limit for scans (packets per second)')
    
    # Verbose output
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    return parser.parse_args()

def start_gui(settings: ScanSettings):
    """Start the GUI interface."""
    try:
        from gui.main_window import MainWindow
        import tkinter as tk
        
        logger.info("Starting ReMap GUI...")
        
        root = tk.Tk()
        app = MainWindow(root, settings)
        
        # Set window properties
        root.title("ReMap - Network Security Scanner")
        root.geometry("1200x800")
        root.minsize(800, 600)
        
        # Start the GUI event loop
        root.mainloop()
        
    except ImportError as e:
        logger.error(f"GUI dependencies not available: {e}")
        print("GUI interface not available. Please install tkinter.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"GUI startup failed: {e}")
        sys.exit(1)

def start_cli(args, settings: ScanSettings):
    """Start the CLI interface."""
    try:
        from cli.cli_interface import CLIInterface
        
        logger.info("Starting ReMap CLI...")
        
        cli = CLIInterface(settings)
        cli.run(args)
        
    except Exception as e:
        logger.error(f"CLI execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()