"""Version information for ReMap."""

__version__ = "1.0.0"
__version_info__ = (1, 0, 0)
__author__ = "ReMap Development Team"
__email__ = "dev@remap-scanner.com"
__license__ = "MIT"
__copyright__ = "2024 ReMap Development Team"
__url__ = "https://github.com/remap-scanner/remap"
__description__ = "Advanced Network Security Scanner with GUI and Analysis Tools"

def check_version():
    """Check if this version is supported."""
    import sys
    if sys.version_info < (3, 8):
        raise RuntimeError(f"ReMap {__version__} requires Python 3.8+")
    return True

def get_version_string():
    """Get formatted version string."""
    return f"ReMap v{__version__}"

def get_version_info():
    """Get detailed version information."""
    import platform
    import sys

    return {
        "version": __version__,
        "version_info": __version_info__,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "platform": platform.platform(),
        "architecture": platform.machine(),
    }