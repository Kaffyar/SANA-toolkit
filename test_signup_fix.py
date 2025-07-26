#!/usr/bin/env python3
"""
Test script to verify signup process is working correctly
"""

import requests
import json
import time
import sqlite3
from datetime import datetime

def test_signup_process():
    """Test the complete signup process"""
    print("🧪 Testing SANA Toolkit Signup Process")
    print("=" * 50)
    
    # Test data
    test_email = f"test_{int(time.time())}@example.com"
    test_password = "TestPass123!"
    
    print(f"📧 Test email: {test_email}")
    print(f"🔐 Test password: {test_password}")
    
    # Step 1: Send signup OTP
    print("\n1️⃣ Sending signup OTP...")
    signup_response = requests.post('http://localhost:5000/api/send-signup-otp', 
                                   json={'email': test_email, 'password': test_password})
    
    print(f"   Status: {signup_response.status_code}")
    print(f"   Response: {signup_response.json()}")
    
    if signup_response.status_code != 200:
        print("❌ Signup OTP send failed!")
        return False
    
    # Step 2: Check database for temp_registration
    print("\n2️⃣ Checking database for temp_registration...")
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    # Check temp_registrations table
    cursor.execute("SELECT temp_id, email, created_at FROM temp_registrations WHERE email = ?", (test_email,))
    temp_reg = cursor.fetchone()
    
    if temp_reg:
        temp_id, email, created_at = temp_reg
        print(f"   ✅ Found temp_registration:")
        print(f"      - temp_id: {temp_id}")
        print(f"      - email: {email}")
        print(f"      - created_at: {created_at}")
    else:
        print("   ❌ No temp_registration found!")
        conn.close()
        return False
    
    # Check user_otp table
    cursor.execute("SELECT identifier, otp_code, otp_type, expires_at FROM user_otp WHERE identifier = ?", (temp_id,))
    otp_record = cursor.fetchone()
    
    if otp_record:
        identifier, otp_code, otp_type, expires_at = otp_record
        print(f"   ✅ Found OTP record:")
        print(f"      - identifier: {identifier}")
        print(f"      - otp_code: {otp_code}")
        print(f"      - otp_type: {otp_type}")
        print(f"      - expires_at: {expires_at}")
    else:
        print("   ❌ No OTP record found!")
        conn.close()
        return False
    
    conn.close()
    
    # Step 3: Verify OTP (simulate the verification process)
    print(f"\n3️⃣ Verifying OTP with code: {otp_code}")
    
    # Get session cookies from the signup response
    session_cookies = signup_response.cookies
    
    verify_response = requests.post('http://localhost:5000/api/verify-otp',
                                   json={'otp_code': otp_code},
                                   cookies=session_cookies)
    
    print(f"   Status: {verify_response.status_code}")
    print(f"   Response: {verify_response.json()}")
    
    if verify_response.status_code == 200:
        print("✅ OTP verification successful!")
        
        # Step 4: Check if user was created
        print("\n4️⃣ Checking if user was created...")
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id, email, is_verified, created_at FROM users WHERE email = ?", (test_email,))
        user_record = cursor.fetchone()
        
        if user_record:
            user_id, email, is_verified, created_at = user_record
            print(f"   ✅ User created successfully:")
            print(f"      - user_id: {user_id}")
            print(f"      - email: {email}")
            print(f"      - is_verified: {is_verified}")
            print(f"      - created_at: {created_at}")
        else:
            print("   ❌ User not found in database!")
            conn.close()
            return False
        
        # Check if temp_registration was cleaned up
        cursor.execute("SELECT COUNT(*) FROM temp_registrations WHERE email = ?", (test_email,))
        temp_count = cursor.fetchone()[0]
        
        if temp_count == 0:
            print("   ✅ Temp registration cleaned up successfully")
        else:
            print(f"   ⚠️ Temp registration still exists ({temp_count} records)")
        
        conn.close()
        
        print("\n🎉 Complete signup process test PASSED!")
        return True
    else:
        print("❌ OTP verification failed!")
        return False

def test_database_schema():
    """Test database schema integrity"""
    print("\n🔍 Testing Database Schema")
    print("=" * 30)
    
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    # Check temp_registrations table structure
    cursor.execute("PRAGMA table_info(temp_registrations)")
    temp_columns = cursor.fetchall()
    
    print("📋 temp_registrations table columns:")
    for col in temp_columns:
        print(f"   - {col[1]} ({col[2]})")
    
    # Check user_otp table structure
    cursor.execute("PRAGMA table_info(user_otp)")
    otp_columns = cursor.fetchall()
    
    print("\n📋 user_otp table columns:")
    for col in otp_columns:
        print(f"   - {col[1]} ({col[2]})")
    
    # Verify identifier column exists
    otp_column_names = [col[1] for col in otp_columns]
    if 'identifier' in otp_column_names:
        print("✅ user_otp table has 'identifier' column")
    else:
        print("❌ user_otp table missing 'identifier' column")
        conn.close()
        return False
    
    conn.close()
    return True

if __name__ == "__main__":
    print("🚀 Starting SANA Toolkit Signup Tests")
    print("=" * 50)
    
    # Test database schema first
    if not test_database_schema():
        print("❌ Database schema test failed!")
        exit(1)
    
    # Test signup process
    if test_signup_process():
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Tests failed!")
        exit(1) 