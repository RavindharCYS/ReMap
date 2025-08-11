#!/usr/bin/env python3
"""
Setup script for ReMap Network Security Scanner.

This script handles the installation and distribution of ReMap.
"""

import sys
from pathlib import Path
from setuptools import setup, find_packages

# Ensure Python version compatibility
if sys.version_info < (3, 8):
    print("Error: ReMap requires Python 3.8 or higher")
    print(f"Current version: {sys.version}")
    sys.exit(1)

# Get project root
PROJECT_ROOT = Path(__file__).parent

# Read version from file
def get_version():
    """Get version from version file or default."""
    version_file = PROJECT_ROOT / "src" / "version.py"
    if version_file.exists():
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    # Exec is safe here as we're reading our own version file
                    exec(line)
                    return locals()["__version__"]
    return "1.0.0"

# Read long description from README
def get_long_description():
    """Get long description from README file."""
    readme_file = PROJECT_ROOT / "README.md"
    if readme_file.exists():
        with open(readme_file, "r", encoding="utf-8") as f:
            return f.read()
    return "ReMap - Advanced Network Security Scanner"

# Read requirements from requirements.txt
def get_requirements():
    """Parse requirements.txt and return list of requirements."""
    requirements_file = PROJECT_ROOT / "requirements.txt"
    requirements = []
    
    if requirements_file.exists():
        with open(requirements_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    requirements.append(line)
    return requirements

# Package data to include
package_data = {
    "src": [
        "resources/config/*.json",
        "resources/icons/*",
    ]
}

# Entry points for console and GUI scripts
entry_points = {
    "console_scripts": [
        "remap = src.main:main",
        "remap-cli = src.cli.cli_interface:main_cli",
    ],
    "gui_scripts": [
        "remap-gui = src.main:main"
    ]
}

# Classifiers for PyPI
classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Win32 (MS Windows)",
    "Environment :: X11 Applications",
    "Environment :: MacOS X",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3 :: Only",
    "Topic :: Security",
    "Topic :: System :: Networking",
    "Topic :: Utilities"
]

# Setup configuration
setup(
    name="remap-scanner",
    version=get_version(),
    author="ReMap Development Team",
    author_email="dev@remap-scanner.com",
    description="Advanced Network Security Scanner with GUI and Analysis Tools",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/remap-scanner/remap",
    project_urls={
        "Bug Reports": "https://github.com/remap-scanner/remap/issues",
        "Source": "https://github.com/remap-scanner/remap",
    },
    packages=find_packages(),
    package_data=package_data,
    include_package_data=True,
    install_requires=get_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.2.0",
            "pytest-cov>=4.0.0",
            "black>=22.10.0",
            "flake8>=5.0.4",
            "mypy>=0.991",
        ]
    },
    python_requires=">=3.8",
    entry_points=entry_points,
    classifiers=classifiers,
    keywords=[
        "network", "security", "scanner", "nmap", "vulnerability",
        "penetration-testing", "infosec", "cybersecurity"
    ],
    license="MIT",
    platforms=["any"],
    zip_safe=False,
)