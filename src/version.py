"""Version information for ReMap."""

__version__ = "1.0.0"
__version_info__ = (1, 0, 0)
__author__ = "ReMap Development Team"
__email__ = "dev@remap-scanner.com"
__license__ = "MIT"
__copyright__ = "2024 ReMap Development Team"
__url__ = "https://github.com/remap-scanner/remap"
__description__ = "Advanced Network Security Scanner with GUI and Analysis Tools"

# Build information
__build__ = "stable"
__build_date__ = "2024-01-01"
__build_number__ = "1000"

# Feature flags
FEATURES = {
    "gui_enabled": True,
    "cli_enabled": True,
    "analysis_enabled": True,
    "reporting_enabled": True,
    "web_detection": True,
    "ssl_analysis": True,
    "smb_analysis": True,
    "tls_analysis": True,
    "export_enabled": True,
    "advanced_scanning": True
}

# Version check function
def check_version():
    """Check if this version is supported."""
    import sys
    if sys.version_info < (3, 7):
        raise RuntimeError(f"ReMap {__version__} requires Python 3.7+")
    return True

# Get version string
def get_version_string():
    """Get formatted version string."""
    return f"ReMap v{__version__} ({__build__})"

# Get detailed version info
def get_version_info():
    """Get detailed version information."""
    import platform
    import sys
    
    return {
        "version": __version__,
        "version_info": __version_info__,
        "build": __build__,
        "build_date": __build_date__,
        "build_number": __build_number__,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "features": FEATURES
    }