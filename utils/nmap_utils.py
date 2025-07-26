"""
SANA Toolkit - Nmap Utilities
Handles nmap availability and provides fallback functionality
"""

import logging
import subprocess
import os
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class NmapAvailability:
    """Handles nmap availability and provides fallback functionality"""
    
    def __init__(self):
        self._nmap_available = None
        self._nmap_scanner = None
        self._check_nmap_availability()
    
    def _check_nmap_availability(self):
        """Check if nmap is available on the system"""
        try:
            # Try to import python-nmap
            import nmap
            self._nmap_available = True
            self._nmap_scanner = nmap.PortScanner()
            logger.info("✅ Nmap is available and ready to use")
        except ImportError:
            logger.warning("⚠️  python-nmap package not installed")
            self._nmap_available = False
            self._nmap_scanner = None
        except Exception as e:
            logger.warning(f"⚠️  Nmap initialization failed: {e}")
            self._nmap_available = False
            self._nmap_scanner = None
    
    @property
    def is_available(self) -> bool:
        """Check if nmap is available"""
        return self._nmap_available is True
    
    @property
    def scanner(self):
        """Get the nmap scanner instance if available"""
        return self._nmap_scanner
    
    def get_unavailable_message(self) -> Dict[str, Any]:
        """Get a message explaining why nmap features are unavailable"""
        return {
            "available": False,
            "message": "Nmap is not available on this system",
            "details": "Host discovery and port scanning features require nmap to be installed locally. These features are not available in cloud deployments for security reasons.",
            "features_affected": [
                "Host Discovery",
                "Port Scanning", 
                "Network Mapping",
                "Service Detection"
            ],
            "installation_guide": {
                "windows": "Download and install nmap from https://nmap.org/download.html",
                "linux": "sudo apt-get install nmap (Ubuntu/Debian) or sudo yum install nmap (CentOS/RHEL)",
                "macos": "brew install nmap (using Homebrew)"
            }
        }

# Global instance
nmap_availability = NmapAvailability()

def get_nmap_scanner():
    """Get nmap scanner if available, None otherwise"""
    return nmap_availability.scanner

def is_nmap_available():
    """Check if nmap is available"""
    return nmap_availability.is_available

def get_nmap_unavailable_message():
    """Get message for when nmap is unavailable"""
    return nmap_availability.get_unavailable_message() 