# SANA Flask App - Nmap Optional Deployment Guide

## Overview

This document outlines the changes made to make the SANA Flask application deployable to cloud platforms (like Render) without requiring nmap to be installed. The app now gracefully handles the absence of nmap and provides clear feedback to users.

## Changes Made

### 1. Created Nmap Utility Module (`utils/nmap_utils.py`)

**Purpose**: Centralized nmap availability checking and fallback functionality

**Key Features**:
- Checks if python-nmap package is available
- Provides friendly error messages when nmap is unavailable
- Returns None for nmap scanner when not available
- Includes installation guides for different platforms

**Usage**:
```python
from utils.nmap_utils import is_nmap_available, get_nmap_scanner, get_nmap_unavailable_message

# Check if nmap is available
if is_nmap_available():
    scanner = get_nmap_scanner()
    # Use scanner...
else:
    message = get_nmap_unavailable_message()
    # Show user-friendly message
```

### 2. Updated Database Schema (`models/database_init.py`)

**Fixed Issue**: `setting_key` column error in user_settings table

**Changes**:
- Modified `user_settings` table schema to use key-value pairs
- Added `setting_id`, `setting_key`, and `setting_value` columns
- Maintained backward compatibility with existing settings model

**New Schema**:
```sql
CREATE TABLE user_settings (
    setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    setting_key TEXT NOT NULL,
    setting_value TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    UNIQUE(user_id, setting_key)
);
```

### 3. Updated Route Files

#### `routes/host_discovery_routes.py`
- **Removed**: Direct `import nmap` and `nmap.PortScanner()` instantiation
- **Added**: Conditional nmap availability checking
- **Added**: User-friendly error responses when nmap is unavailable
- **Added**: Disabled UI elements when nmap features are not available

#### `app.py`
- **Removed**: Direct `import nmap` and `nmap.PortScanner()` instantiation
- **Added**: Conditional nmap availability checking in scan routes
- **Added**: Graceful error handling for nmap-dependent features

### 4. Updated Templates

#### `templates/host_discovery.html`
- **Added**: Nmap availability warning banner
- **Added**: Disabled state for discovery buttons when nmap unavailable
- **Added**: Installation guide display

#### `templates/nmap_scanner.html`
- **Added**: Nmap availability warning banner
- **Added**: Disabled state for scan buttons when nmap unavailable
- **Added**: Installation guide display

### 5. Created CSS Styling (`static/css/nmap-warning.css`)

**Features**:
- Professional warning alert styling
- Animated shimmer effect
- Responsive design
- Disabled button styling
- Installation guide formatting

### 6. Updated Requirements (`requirements.txt`)

**Changes**:
- **Removed**: `python-nmap==0.7.1` (made optional)
- **Added**: Comment explaining nmap is optional
- **Kept**: All other dependencies for core functionality

### 7. Created Test Script (`test_nmap_optional.py`)

**Purpose**: Verify app functionality without nmap

**Tests**:
- Nmap utility import and functionality
- App creation and startup
- Database schema creation
- Nmap availability detection

## Deployment Benefits

### ✅ Cloud Platform Compatibility
- App starts successfully on Render, Railway, Heroku, etc.
- No system-level nmap installation required
- Graceful degradation of features

### ✅ User Experience
- Clear, informative messages when nmap is unavailable
- Installation guides for different platforms
- Disabled UI elements prevent confusion
- Professional warning styling

### ✅ Security
- Prevents nmap-related security issues in cloud deployments
- Maintains security best practices
- Clear separation of local vs cloud capabilities

## Available Features by Environment

### Local Development (with nmap)
- ✅ Host Discovery
- ✅ Port Scanning
- ✅ Network Mapping
- ✅ Service Detection
- ✅ Vulnerability Scanning
- ✅ All DNS features
- ✅ All VirusTotal features
- ✅ All authentication features
- ✅ All scan history features

### Cloud Deployment (without nmap)
- ✅ DNS Reconnaissance
- ✅ VirusTotal Integration
- ✅ User Authentication
- ✅ Scan History Management
- ✅ Settings Management
- ⚠️ Host Discovery (disabled with warning)
- ⚠️ Port Scanning (disabled with warning)
- ⚠️ Network Mapping (disabled with warning)

## Installation Guide for Users

### Windows
1. Download nmap from https://nmap.org/download.html
2. Run the installer
3. Restart the application

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install nmap
```

### Linux (CentOS/RHEL)
```bash
sudo yum install nmap
```

### macOS
```bash
brew install nmap
```

## Testing

Run the test script to verify everything works:

```bash
python test_nmap_optional.py
```

Expected output:
```
✅ All tests passed! App is ready for deployment without nmap.
```

## Deployment Checklist

- [x] Nmap utility module created
- [x] Database schema fixed
- [x] Route files updated
- [x] Templates updated with warnings
- [x] CSS styling added
- [x] Requirements updated
- [x] Test script created
- [x] All tests passing

## Files Modified

1. `utils/nmap_utils.py` (new)
2. `models/database_init.py`
3. `routes/host_discovery_routes.py`
4. `app.py`
5. `templates/host_discovery.html`
6. `templates/nmap_scanner.html`
7. `static/css/nmap-warning.css` (new)
8. `requirements.txt`
9. `test_nmap_optional.py` (new)

## Conclusion

The SANA Flask application is now fully compatible with cloud deployments while maintaining all core functionality. Users get clear feedback about nmap availability and installation instructions. The app gracefully handles the absence of nmap without crashing or providing confusing error messages. 