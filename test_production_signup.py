#!/usr/bin/env python3
"""
Test script to simulate production signup process
"""

import requests
import json
import time
import sqlite3
from datetime import datetime

def test_production_signup():
    """Test the complete signup process as it would happen in production"""
    print("🧪 Testing Production Signup Process")
    print("=" * 50)
    
    # Test data
    test_email = f"test_{int(time.time())}@example.com"
    test_password = "TestPass123!"
    
    print(f"📧 Test email: {test_email}")
    print(f"🔐 Test password: {test_password}")
    
    # Step 1: Check database state before signup
    print("\n1️⃣ Checking database state before signup...")
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM temp_registrations")
    temp_before = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM user_otp")
    otp_before = cursor.fetchone()[0]
    
    print(f"   temp_registrations before: {temp_before}")
    print(f"   user_otp before: {otp_before}")
    conn.close()
    
    # Step 2: Send signup OTP
    print("\n2️⃣ Sending signup OTP...")
    try:
        signup_response = requests.post('http://localhost:5000/api/send-signup-otp', 
                                       json={'email': test_email, 'password': test_password},
                                       timeout=10)
        
        print(f"   Status: {signup_response.status_code}")
        print(f"   Response: {signup_response.json()}")
        
        if signup_response.status_code != 200:
            print("❌ Signup OTP send failed!")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {e}")
        return False
    
    # Step 3: Check database state after signup
    print("\n3️⃣ Checking database state after signup...")
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM temp_registrations")
    temp_after = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM user_otp")
    otp_after = cursor.fetchone()[0]
    
    print(f"   temp_registrations after: {temp_after}")
    print(f"   user_otp after: {otp_after}")
    
    # Check for the specific temp_registration
    cursor.execute("SELECT temp_id, email, created_at FROM temp_registrations WHERE email = ?", (test_email,))
    temp_reg = cursor.fetchone()
    
    if temp_reg:
        temp_id, email, created_at = temp_reg
        print(f"   ✅ Found temp_registration:")
        print(f"      - temp_id: {temp_id}")
        print(f"      - email: {email}")
        print(f"      - created_at: {created_at}")
        
        # Check for corresponding OTP
        cursor.execute("SELECT identifier, otp_code, otp_type, expires_at FROM user_otp WHERE identifier = ?", (temp_id,))
        otp_record = cursor.fetchone()
        
        if otp_record:
            identifier, otp_code, otp_type, expires_at = otp_record
            print(f"   ✅ Found OTP record:")
            print(f"      - identifier: {identifier}")
            print(f"      - otp_code: {otp_code}")
            print(f"      - otp_type: {otp_type}")
            print(f"      - expires_at: {expires_at}")
            
            # Step 4: Test OTP verification
            print(f"\n4️⃣ Testing OTP verification with code: {otp_code}")
            
            # Get session cookies from the signup response
            session_cookies = signup_response.cookies
            
            try:
                verify_response = requests.post('http://localhost:5000/api/verify-otp',
                                              json={'otp_code': otp_code},
                                              cookies=session_cookies,
                                              timeout=10)
                
                print(f"   Status: {verify_response.status_code}")
                print(f"   Response: {verify_response.json()}")
                
                if verify_response.status_code == 200:
                    print("✅ OTP verification successful!")
                    
                    # Step 5: Check if user was created
                    print("\n5️⃣ Checking if user was created...")
                    cursor.execute("SELECT user_id, email, is_verified, created_at FROM users WHERE email = ?", (test_email,))
                    user_record = cursor.fetchone()
                    
                    if user_record:
                        user_id, email, is_verified, created_at = user_record
                        print(f"   ✅ User created successfully:")
                        print(f"      - user_id: {user_id}")
                        print(f"      - email: {email}")
                        print(f"      - is_verified: {is_verified}")
                        print(f"      - created_at: {created_at}")
                        
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
                        print("   ❌ User not found in database!")
                        conn.close()
                        return False
                else:
                    print("❌ OTP verification failed!")
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
        print("   ❌ No temp_registration found!")
        conn.close()
        return False

def test_database_connection():
    """Test database connection and basic operations"""
    print("\n🔍 Testing Database Connection")
    print("=" * 30)
    
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT COUNT(*) FROM temp_registrations")
        count = cursor.fetchone()[0]
        print(f"✅ Database connection successful, temp_registrations count: {count}")
        
        # Test insertion with correct format
        test_temp_id = f"temp_{int(time.time())}_{'a' * 8}"
        test_email = "test_connection@example.com"
        
        cursor.execute('''
            INSERT INTO temp_registrations 
            (temp_id, email, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (test_temp_id, test_email, datetime.now(), 
              datetime.now().replace(year=datetime.now().year + 1)))
        
        conn.commit()
        print(f"✅ Test insertion successful with temp_id: {test_temp_id}")
        
        # Clean up
        cursor.execute("DELETE FROM temp_registrations WHERE temp_id = ?", (test_temp_id,))
        conn.commit()
        print("✅ Test cleanup successful")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting Production Signup Tests")
    print("=" * 50)
    
    # Test database connection first
    if not test_database_connection():
        print("❌ Database connection test failed!")
        exit(1)
    
    # Test signup process
    if test_production_signup():
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Tests failed!")
        exit(1) 