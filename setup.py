#!/usr/bin/env python3
"""
Setup script for ReMap Network Security Scanner.

This script handles the installation and distribution of ReMap.
"""

import sys
import os
from pathlib import Path
from setuptools import setup, find_packages

# Ensure Python version compatibility
if sys.version_info < (3, 7):
    print("Error: ReMap requires Python 3.7 or higher")
    print(f"Current version: {sys.version}")
    sys.exit(1)

# Read version from file
def get_version():
    """Get version from version file or default."""
    version_file = Path(__file__).parent / "src" / "__version__.py"
    if version_file.exists():
        with open(version_file, "r", encoding="utf-8") as f:
            exec(f.read())
            return locals()["__version__"]
    return "1.0.0"

# Read long description from README
def get_long_description():
    """Get long description from README file."""
    readme_file = Path(__file__).parent / "README.md"
    if readme_file.exists():
        with open(readme_file, "r", encoding="utf-8") as f:
            return f.read()
    return "ReMap - Network Security Scanner"

# Read requirements from requirements.txt
def get_requirements():
    """Parse requirements.txt and return list of requirements."""
    requirements_file = Path(__file__).parent / "requirements.txt"
    requirements = []
    
    if requirements_file.exists():
        with open(requirements_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip comments, empty lines, and development dependencies
                if (line and 
                    not line.startswith("#") and 
                    not line.startswith("git+") and
                    "pytest" not in line and
                    "black" not in line and
                    "flake8" not in line and
                    "mypy" not in line):
                    
                    # Handle platform-specific dependencies
                    if ";" in line:
                        req, condition = line.split(";", 1)
                        req = req.strip()
                        condition = condition.strip()
                        
                        # Evaluate simple platform conditions
                        if "platform_system" in condition:
                            if sys.platform.startswith("win") and "Windows" in condition:
                                requirements.append(req)
                            elif sys.platform.startswith("linux") and "Linux" in condition:
                                requirements.append(req)
                            elif "platform_system" not in condition:
                                requirements.append(req)
                        else:
                            requirements.append(req)
                    else:
                        requirements.append(line)
    
    # Core requirements that must be present
    core_requirements = [
        "requests>=2.28.0",
        "lxml>=4.9.1", 
        "pyOpenSSL>=22.1.0",
        "cryptography>=38.0.0",
        "psutil>=5.9.0"
    ]
    
    # Add core requirements if not already present
    for core_req in core_requirements:
        req_name = core_req.split(">=")[0].split("==")[0]
        if not any(req_name in req for req in requirements):
            requirements.append(core_req)
    
    return requirements

# Platform-specific requirements
def get_platform_requirements():
    """Get platform-specific requirements."""
    requirements = []
    
    if sys.platform.startswith("win"):
        requirements.extend([
            "pywin32>=304",
            "wmi>=1.5.1"
        ])
    
    return requirements

# Define entry points
entry_points = {
    "console_scripts": [
        "remap=src.main:main",
        "remap-cli=src.cli.cli_interface:main",
        "remap-gui=src.main:main"
    ],
    "gui_scripts": [
        "remap-gui=src.main:main"
    ]
}

# Package data
package_data = {
    "": [
        "*.json",
        "*.yaml", 
        "*.yml",
        "*.txt",
        "*.md",
        "*.rst"
    ],
    "src": [
        "resources/config/*.json",
        "resources/icons/*",
        "resources/templates/*"
    ]
}

# Additional data files
data_files = [
    ("remap/config", ["resources/config/default_settings.json"]),
    ("remap/docs", ["README.md"]),
]

# Classifiers for PyPI
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: X11 Applications :: Qt",
    "Environment :: Win32 (MS Windows)",
    "Environment :: MacOS X",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators", 
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Natural Language :: English",
    "Operating System :: OS Independent",
    "Operating System :: POSIX :: Linux",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: MacOS",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3 :: Only",
    "Topic :: Security",
    "Topic :: System :: Networking",
    "Topic :: System :: Networking :: Monitoring",
    "Topic :: System :: Systems Administration",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: Utilities"
]

# Setup configuration
setup_config = {
    "name": "remap-scanner",
    "version": get_version(),
    "author": "ReMap Development Team", 
    "author_email": "dev@remap-scanner.com",
    "description": "Advanced Network Security Scanner with GUI and Analysis Tools",
    "long_description": get_long_description(),
    "long_description_content_type": "text/markdown",
    "url": "https://github.com/remap-scanner/remap",
    "project_urls": {
        "Bug Reports": "https://github.com/remap-scanner/remap/issues",
        "Source": "https://github.com/remap-scanner/remap",
        "Documentation": "https://docs.remap-scanner.com",
        "Funding": "https://github.com/sponsors/remap-scanner",
    },
    "packages": find_packages(where="src"),
    "package_dir": {"": "src"},
    "package_data": package_data,
    "data_files": data_files,
    "include_package_data": True,
    "install_requires": get_requirements() + get_platform_requirements(),
    "extras_require": {
        "dev": [
            "pytest>=7.2.0",
            "pytest-cov>=4.0.0", 
            "black>=22.10.0",
            "flake8>=5.0.4",
            "mypy>=0.991",
            "pre-commit>=2.20.0"
        ],
        "docs": [
            "sphinx>=5.3.0",
            "sphinx-rtd-theme>=1.1.1",
            "myst-parser>=0.18.0"
        ],
        "gui": [
            "pillow>=9.2.0",
            "matplotlib>=3.6.0"
        ],
        "web": [
            "selenium>=4.7.0",
            "beautifulsoup4>=4.11.1"
        ],
        "advanced": [
            "scapy>=2.4.5",
            "impacket>=0.10.0", 
            "python-masscan>=0.1.6"
        ],
        "reporting": [
            "jinja2>=3.1.2",
            "openpyxl>=3.0.10",
            "pandas>=1.5.0"
        ]
    },
    "python_requires": ">=3.7",
    "entry_points": entry_points,
    "classifiers": classifiers,
    "keywords": [
        "network", "security", "scanner", "nmap", "vulnerability", 
        "penetration-testing", "infosec", "cybersecurity", "reconnaissance",
        "port-scanner", "network-analysis", "security-audit", "web-scanner"
    ],
    "license": "MIT",
    "platforms": ["any"],
    "zip_safe": False,
    
    # Additional metadata
    "maintainer": "ReMap Development Team",
    "maintainer_email": "maintainer@remap-scanner.com",
    
    # CLI options
    "options": {
        "build_scripts": {
            "executable": "/usr/bin/python3"
        },
        "bdist_wheel": {
            "universal": False
        }
    }
}

# Custom commands for development
class CustomCommands:
    """Custom setup commands for development workflow."""
    
    @staticmethod
    def install_dev_requirements():
        """Install development requirements."""
        import subprocess
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-e", ".[dev]"
        ])
    
    @staticmethod 
    def run_tests():
        """Run test suite."""
        import subprocess
        subprocess.check_call([
            sys.executable, "-m", "pytest", "tests/", "-v", "--cov=src"
        ])
    
    @staticmethod
    def format_code():
        """Format code using black."""
        import subprocess
        subprocess.check_call([
            sys.executable, "-m", "black", "src/", "tests/", "setup.py"
        ])

# Custom build commands
try:
    from setuptools import Command
    
    class TestCommand(Command):
        """Custom test command."""
        description = "Run test suite"
        user_options = []
        
        def initialize_options(self):
            pass
        
        def finalize_options(self):
            pass
        
        def run(self):
            CustomCommands.run_tests()
    
    class FormatCommand(Command):
        """Custom format command."""
        description = "Format code with black"
        user_options = []
        
        def initialize_options(self):
            pass
        
        def finalize_options(self):
            pass
        
        def run(self):
            CustomCommands.format_code()
    
    # Add custom commands
    setup_config["cmdclass"] = {
        "test": TestCommand,
        "format": FormatCommand
    }
    
except ImportError:
    pass

# Pre-installation checks
def check_system_requirements():
    """Check system requirements before installation."""
    print("Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"Error: Python 3.7+ required, found {sys.version}")
        return False
    
    # Check for Nmap availability
    import shutil
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        print("Warning: Nmap not found in PATH")
        print("Please install Nmap from https://nmap.org/download.html")
        
        # Don't fail installation, just warn
        response = input("Continue installation without Nmap? [y/N]: ")
        if response.lower() not in ['y', 'yes']:
            return False
    else:
        print(f"Found Nmap at: {nmap_path}")
    
    # Check available disk space
    import shutil as disk_util
    try:
        free_space = disk_util.disk_usage(".").free
        required_space = 100 * 1024 * 1024  # 100MB
        if free_space < required_space:
            print(f"Warning: Low disk space. Required: {required_space//1024//1024}MB, Available: {free_space//1024//1024}MB")
    except:
        pass
    
    print("System requirements check completed.")
    return True

# Post-installation setup
def post_install_setup():
    """Perform post-installation setup."""
    print("Performing post-installation setup...")
    
    try:
        # Create config directories
        from pathlib import Path
        
        config_dir = Path.home() / ".remap"
        (config_dir / "config").mkdir(parents=True, exist_ok=True)
        (config_dir / "logs").mkdir(parents=True, exist_ok=True)
        (config_dir / "scans").mkdir(parents=True, exist_ok=True)
        (config_dir / "reports").mkdir(parents=True, exist_ok=True)
        (config_dir / "exports").mkdir(parents=True, exist_ok=True)
        
        print(f"Created config directories in: {config_dir}")
        
        # Copy default settings if they don't exist
        default_settings_src = Path(__file__).parent / "resources" / "config" / "default_settings.json"
        default_settings_dst = config_dir / "config" / "settings.json"
        
        if default_settings_src.exists() and not default_settings_dst.exists():
            import shutil
            shutil.copy2(default_settings_src, default_settings_dst)
            print("Copied default settings")
        
        print("Post-installation setup completed successfully.")
        
    except Exception as e:
        print(f"Warning: Post-installation setup failed: {e}")

# Main setup execution
def main():
    """Main setup function."""
    print("=" * 60)
    print("ReMap Network Security Scanner - Installation")
    print("=" * 60)
    
    # Pre-installation checks
    if not check_system_requirements():
        print("Installation cancelled due to system requirement issues.")
        sys.exit(1)
    
    # Run setup
    try:
        setup(**setup_config)
        
        # Post-installation setup
        post_install_setup()
        
        print("\n" + "=" * 60)
        print("Installation completed successfully!")
        print("=" * 60)
        print("\nQuick Start:")
        print("  GUI Mode:     remap")
        print("  CLI Mode:     remap-cli --help")
        print("  Test Install: python -c 'import src; print(\"Import successful\")'")
        print("\nDocumentation: https://docs.remap-scanner.com")
        print("Support:       https://github.com/remap-scanner/remap/issues")
        
    except Exception as e:
        print(f"\nInstallation failed: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure you have Python 3.7+ installed")
        print("2. Try: pip install --upgrade pip setuptools wheel")
        print("3. For Windows: Install Microsoft Visual C++ Build Tools")
        print("4. For Linux: Install python3-dev and build-essential")
        print("5. Check our documentation for platform-specific issues")
        sys.exit(1)

if __name__ == "__main__":
    main()