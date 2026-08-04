"""
Platform adapter package initialization and factory function.
"""

import sys
from platform.base_adapter import BasePlatformAdapter
from platform.macos import MacOSAdapter
from platform.windows import WindowsAdapter
from platform.linux import LinuxAdapter

def get_platform_adapter() -> BasePlatformAdapter:
    """
    Auto-detects host OS and returns appropriate platform adapter instance.
    """
    if sys.platform.startswith("darwin"):
        return MacOSAdapter()
    elif sys.platform.startswith("win"):
        return WindowsAdapter()
    elif sys.platform.startswith("linux"):
        return LinuxAdapter()
    else:
        # Fallback to base platform adapter with generic python implementations
        return BasePlatformAdapter()
