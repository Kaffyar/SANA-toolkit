#!/usr/bin/env python3
"""
Test script to check package availability
"""

def test_packages():
    """Test if required packages are available"""
    print("🔍 Testing Package Availability")
    print("=" * 40)
    
    packages = [
        'sublist3r',
        'dnspython', 
        'whois',
        'requests',
        'Flask'
    ]
    
    for package in packages:
        try:
            __import__(package)
            print(f"✅ {package} - Available")
        except ImportError:
            print(f"❌ {package} - NOT AVAILABLE")
    
    print("\n📦 Package Test Complete")

if __name__ == "__main__":
    test_packages() 