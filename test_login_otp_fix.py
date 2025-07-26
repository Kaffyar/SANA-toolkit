#!/usr/bin/env python3
"""
Test script to verify login OTP functionality
"""

import requests
import json
import time
import sqlite3
from datetime import datetime

def test_login_otp():
    """Test the login OTP process"""
    print("🧪 Testing Login OTP Process")
    print("=" * 40)
    
    # Test data
    test_email = "hamzacerts@gmail.com"  # Use the email that was just created
    
    print(f"📧 Test email: {test_email}")
    
    # Step 1: Send login OTP
    print("\n1️⃣ Sending login OTP...")
    try:
        login_response = requests.post('http://localhost:5000/api/send-login-otp', 
                                     json={'email': test_email},
                                     timeout=10)
        
        print(f"   Status: {login_response.status_code}")
        print(f"   Response: {login_response.json()}")
        
        if login_response.status_code != 200:
            print("❌ Login OTP send failed!")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {e}")
        return False
    
    # Step 2: Check database for OTP
    print("\n2️⃣ Checking database for OTP...")
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    # Get user_id for the email
    cursor.execute("SELECT user_id FROM users WHERE email = ?", (test_email,))
    user_result = cursor.fetchone()
    
    if user_result:
        user_id = user_result[0]
        print(f"   ✅ Found user_id: {user_id}")
        
        # Check for OTP with identifier
        cursor.execute("SELECT identifier, otp_code, otp_type, expires_at FROM user_otp WHERE identifier = ? AND otp_type = 'login' ORDER BY created_at DESC LIMIT 1", (str(user_id),))
        otp_record = cursor.fetchone()
        
        if otp_record:
            identifier, otp_code, otp_type, expires_at = otp_record
            print(f"   ✅ Found OTP record:")
            print(f"      - identifier: {identifier}")
            print(f"      - otp_code: {otp_code}")
            print(f"      - otp_type: {otp_type}")
            print(f"      - expires_at: {expires_at}")
            
            # Step 3: Test OTP verification
            print(f"\n3️⃣ Testing OTP verification with code: {otp_code}")
            
            # Get session cookies from the login response
            session_cookies = login_response.cookies
            
            try:
                verify_response = requests.post('http://localhost:5000/api/verify-otp',
                                              json={'otp_code': otp_code},
                                              cookies=session_cookies,
                                              timeout=10)
                
                print(f"   Status: {verify_response.status_code}")
                print(f"   Response: {verify_response.json()}")
                
                if verify_response.status_code == 200:
                    print("✅ Login OTP verification successful!")
                    conn.close()
                    print("\n🎉 Login OTP process test PASSED!")
                    return True
                else:
                    print("❌ Login OTP verification failed!")
                    conn.close()
                    return False
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Verification request error: {e}")
                conn.close()
                return False
        else:
            print("   ❌ No OTP record found!")
            conn.close()
            return False
    else:
        print("   ❌ User not found!")
        conn.close()
        return False

def test_database_schema():
    """Test database schema for login OTP"""
    print("\n🔍 Testing Database Schema")
    print("=" * 30)
    
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        # Check user_otp table schema
        cursor.execute("PRAGMA table_info(user_otp)")
        columns = cursor.fetchall()
        
        print("   user_otp table columns:")
        for col in columns:
            print(f"      - {col[1]} ({col[2]})")
        
        # Check if identifier column exists
        identifier_exists = any(col[1] == 'identifier' for col in columns)
        user_id_exists = any(col[1] == 'user_id' for col in columns)
        
        if identifier_exists:
            print("   ✅ identifier column exists")
        else:
            print("   ❌ identifier column missing")
            
        if user_id_exists:
            print("   ⚠️ user_id column still exists (may cause issues)")
        else:
            print("   ✅ user_id column removed")
        
        conn.close()
        return identifier_exists
        
    except Exception as e:
        print(f"❌ Database schema test error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Login OTP Tests")
    print("=" * 50)
    
    # Test database schema first
    if not test_database_schema():
        print("❌ Database schema test failed!")
        exit(1)
    
    # Test login OTP process
    if test_login_otp():
        print("\n✅ All login OTP tests passed!")
    else:
        print("\n❌ Login OTP tests failed!")
        exit(1) 