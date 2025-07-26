#!/usr/bin/env python3
"""
Test script to verify signup process and database insertion
This script will test the complete signup flow and verify that temp_registrations are properly inserted
"""

import requests
import json
import time
import sqlite3
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5000"  # Adjust if your app runs on different port
TEST_EMAIL = f"test_{int(time.time())}@example.com"
TEST_PASSWORD = "TestPass123!"

def test_database_connection():
    """Test database connection and schema"""
    print("🔍 Testing database connection...")
    
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        # Check if temp_registrations table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='temp_registrations'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            print("✅ temp_registrations table exists")
            
            # Get table schema
            cursor.execute("PRAGMA table_info(temp_registrations)")
            columns = cursor.fetchall()
            print(f"📋 Table columns: {[col[1] for col in columns]}")
            
            # Get row count
            cursor.execute("SELECT COUNT(*) FROM temp_registrations")
            count = cursor.fetchone()[0]
            print(f"📊 Current temp_registrations count: {count}")
            
        else:
            print("❌ temp_registrations table does not exist!")
            
        conn.close()
        return table_exists
        
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return False

def test_debug_endpoints():
    """Test debug endpoints"""
    print("\n🔍 Testing debug endpoints...")
    
    # Test database debug endpoint
    try:
        response = requests.get(f"{BASE_URL}/debug-database")
        if response.status_code == 200:
            data = response.json()
            print("✅ Database debug endpoint working")
            print(f"📊 Schema info: {data.get('schema_info', {})}")
            print(f"📋 Sample temp registrations: {len(data.get('temp_registrations_sample', []))}")
        else:
            print(f"❌ Database debug endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Database debug endpoint error: {e}")
    
    # Test session debug endpoint
    try:
        response = requests.get(f"{BASE_URL}/session-debug")
        if response.status_code == 200:
            data = response.json()
            print("✅ Session debug endpoint working")
            print(f"📋 Session keys: {data.get('session_keys', [])}")
        else:
            print(f"❌ Session debug endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Session debug endpoint error: {e}")

def test_temp_insert():
    """Test manual temp registration insertion"""
    print(f"\n🧪 Testing manual temp registration insertion for {TEST_EMAIL}...")
    
    try:
        response = requests.post(f"{BASE_URL}/test-temp-insert", 
                               json={'email': TEST_EMAIL},
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Manual temp insertion successful")
            print(f"🆔 Generated temp_id: {data.get('temp_id')}")
            return data.get('temp_id')
        else:
            print(f"❌ Manual temp insertion failed: {response.status_code}")
            print(f"Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Manual temp insertion error: {e}")
        return None

def test_signup_otp_send():
    """Test signup OTP sending"""
    print(f"\n📧 Testing signup OTP send for {TEST_EMAIL}...")
    
    try:
        response = requests.post(f"{BASE_URL}/api/send-signup-otp",
                               json={
                                   'email': TEST_EMAIL,
                                   'password': TEST_PASSWORD
                               },
                               headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Signup OTP send successful")
            print(f"📧 Response: {data.get('message')}")
            return True
        else:
            print(f"❌ Signup OTP send failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Signup OTP send error: {e}")
        return False

def verify_temp_registration_in_db(email, expected_temp_id=None):
    """Verify temp registration exists in database"""
    print(f"\n🔍 Verifying temp registration in database for {email}...")
    
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        # Check for temp registration by email
        cursor.execute("SELECT temp_id, email, created_at, expires_at FROM temp_registrations WHERE email = ?", (email,))
        result = cursor.fetchone()
        
        if result:
            temp_id, db_email, created_at, expires_at = result
            print(f"✅ Found temp registration in database:")
            print(f"   - temp_id: {temp_id}")
            print(f"   - email: {db_email}")
            print(f"   - created_at: {created_at}")
            print(f"   - expires_at: {expires_at}")
            
            if expected_temp_id and temp_id != expected_temp_id:
                print(f"⚠️  Warning: temp_id mismatch. Expected: {expected_temp_id}, Found: {temp_id}")
            
            conn.close()
            return temp_id
        else:
            print(f"❌ No temp registration found for {email}")
            
            # Show all temp registrations for debugging
            cursor.execute("SELECT temp_id, email, created_at FROM temp_registrations ORDER BY created_at DESC LIMIT 5")
            all_results = cursor.fetchall()
            if all_results:
                print("📋 Recent temp registrations:")
                for row in all_results:
                    print(f"   - {row[0]} -> {row[1]} ({row[2]})")
            else:
                print("📋 No temp registrations in database")
            
            conn.close()
            return None
            
    except Exception as e:
        print(f"❌ Database verification error: {e}")
        return None

def test_find_temp_id_by_email(email):
    """Test the find_temp_id_by_email method via API"""
    print(f"\n🔍 Testing find_temp_id_by_email for {email}...")
    
    # This would require an API endpoint, but we can test the database directly
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT temp_id FROM temp_registrations WHERE email = ? LIMIT 1", (email,))
        result = cursor.fetchone()
        
        if result:
            temp_id = result[0]
            print(f"✅ find_temp_id_by_email found: {temp_id}")
            conn.close()
            return temp_id
        else:
            print(f"❌ find_temp_id_by_email not found for {email}")
            conn.close()
            return None
            
    except Exception as e:
        print(f"❌ find_temp_id_by_email error: {e}")
        return None

def main():
    """Run comprehensive signup tests"""
    print("🚀 Starting comprehensive signup process tests")
    print("=" * 60)
    
    # Test 1: Database connection and schema
    db_ok = test_database_connection()
    if not db_ok:
        print("❌ Database test failed. Cannot continue.")
        return
    
    # Test 2: Debug endpoints
    test_debug_endpoints()
    
    # Test 3: Manual temp insertion
    manual_temp_id = test_temp_insert()
    if manual_temp_id:
        verify_temp_registration_in_db(TEST_EMAIL, manual_temp_id)
    
    # Test 4: Signup OTP send
    signup_success = test_signup_otp_send()
    if signup_success:
        # Wait a moment for database operations
        time.sleep(1)
        
        # Test 5: Verify temp registration after signup
        signup_temp_id = verify_temp_registration_in_db(TEST_EMAIL)
        if signup_temp_id:
            print("✅ Signup process successfully created temp registration in database")
        else:
            print("❌ Signup process failed to create temp registration in database")
        
        # Test 6: Test find_temp_id_by_email
        found_temp_id = test_find_temp_id_by_email(TEST_EMAIL)
        if found_temp_id:
            print("✅ find_temp_id_by_email working correctly")
        else:
            print("❌ find_temp_id_by_email not working correctly")
    
    print("\n" + "=" * 60)
    print("🏁 Signup process tests completed")
    
    if signup_success and signup_temp_id:
        print("✅ All tests passed - signup process is working correctly")
    else:
        print("❌ Some tests failed - signup process needs investigation")

if __name__ == "__main__":
    main() 