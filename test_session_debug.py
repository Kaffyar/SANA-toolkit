#!/usr/bin/env python3
"""
Comprehensive session debugging test script
"""

import requests
import json
import time
import sys

def test_session_endpoints(base_url):
    """Test session endpoints to debug issues"""
    
    print("🧪 Testing Session Endpoints")
    print("=" * 50)
    
    # Test 1: Check initial session state
    print("\n1. Testing initial session state...")
    try:
        response = requests.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            session_data = response.json()
            print(f"   Session keys: {session_data.get('session_keys', [])}")
            print(f"   Session modified: {session_data.get('session_modified', False)}")
            print(f"   Session permanent: {session_data.get('session_permanent', False)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 2: Test setting session data
    print("\n2. Testing session data setting...")
    try:
        test_data = {
            'test_key': 'test_value_123',
            'test_email': 'test@example.com'
        }
        response = requests.post(f"{base_url}/auth/test-session", json=test_data)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   Success: {result.get('status')}")
            print(f"   Session keys: {result.get('session_keys', [])}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Check session data after setting
    print("\n3. Testing session data retrieval...")
    try:
        response = requests.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            session_data = response.json()
            print(f"   Session keys: {session_data.get('session_keys', [])}")
            print(f"   Test key: {session_data.get('test_key', 'Not found')}")
            print(f"   Test email: {session_data.get('test_email', 'Not found')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 4: Test OTP sending (this should set session data)
    print("\n4. Testing OTP sending (should set session data)...")
    try:
        otp_data = {
            'email': 'test@example.com'
        }
        response = requests.post(f"{base_url}/auth/api/send-login-otp", json=otp_data)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"   Success: {result.get('status')}")
            print(f"   Message: {result.get('message')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 5: Check session data after OTP send
    print("\n5. Testing session data after OTP send...")
    try:
        response = requests.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            session_data = response.json()
            print(f"   Session keys: {session_data.get('session_keys', [])}")
            print(f"   OTP email: {session_data.get('otp_email', 'Not found')}")
            print(f"   OTP type: {session_data.get('otp_type', 'Not found')}")
            print(f"   Session modified: {session_data.get('session_modified', False)}")
            print(f"   Session permanent: {session_data.get('session_permanent', False)}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")

def test_cookie_behavior(base_url):
    """Test cookie behavior and persistence"""
    
    print("\n🍪 Testing Cookie Behavior")
    print("=" * 50)
    
    # Create a session to track cookies
    session = requests.Session()
    
    # Test 1: Initial request
    print("\n1. Testing initial request...")
    try:
        response = session.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        print(f"   Cookies: {dict(session.cookies)}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 2: Set session data
    print("\n2. Testing session data setting with cookies...")
    try:
        test_data = {
            'test_key': 'cookie_test_value',
            'test_email': 'cookie@example.com'
        }
        response = session.post(f"{base_url}/auth/test-session", json=test_data)
        print(f"   Status: {response.status_code}")
        print(f"   Cookies after set: {dict(session.cookies)}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 3: Retrieve session data with same session
    print("\n3. Testing session data retrieval with cookies...")
    try:
        response = session.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            session_data = response.json()
            print(f"   Session keys: {session_data.get('session_keys', [])}")
            print(f"   Test key: {session_data.get('test_key', 'Not found')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test 4: Test with new session (should not have data)
    print("\n4. Testing with new session (should not have data)...")
    try:
        new_session = requests.Session()
        response = new_session.get(f"{base_url}/auth/session-debug")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            session_data = response.json()
            print(f"   Session keys: {session_data.get('session_keys', [])}")
            print(f"   Test key: {session_data.get('test_key', 'Not found')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Error: {e}")

def main():
    """Main test function"""
    
    if len(sys.argv) != 2:
        print("Usage: python test_session_debug.py <base_url>")
        print("Example: python test_session_debug.py https://sana-toolkit.onrender.com")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    
    print("🚀 SANA Flask App - Session Debug Test")
    print("=" * 60)
    print(f"Testing against: {base_url}")
    
    # Test session endpoints
    test_session_endpoints(base_url)
    
    # Test cookie behavior
    test_cookie_behavior(base_url)
    
    print("\n" + "=" * 60)
    print("✅ Session debugging test completed!")
    print("\nIf sessions are still empty, check:")
    print("1. FLASK_SECRET_KEY environment variable is set")
    print("2. FLASK_ENV is set to 'production'")
    print("3. HTTPS is working properly")
    print("4. Browser console for cookie errors")

if __name__ == "__main__":
    main() 