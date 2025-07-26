#!/usr/bin/env python3
"""
Test script to verify OTP table fix with identifier field
This script tests that the OTP system works correctly with both user_id and temp_id
"""

import sqlite3
import time
import secrets
from datetime import datetime, timedelta

# Configuration
DB_PATH = 'data/sana_toolkit.db'

def test_database_schema():
    """Test the updated OTP table schema"""
    print("🔍 Testing OTP table schema...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if user_otp table exists and has identifier column
        cursor.execute("PRAGMA table_info(user_otp)")
        columns = cursor.fetchall()
        
        column_names = [col[1] for col in columns]
        print(f"📋 OTP table columns: {column_names}")
        
        # Check for identifier column
        if 'identifier' in column_names:
            print("✅ identifier column exists in user_otp table")
        else:
            print("❌ identifier column missing from user_otp table")
            return False
        
        # Check for user_id column (should be migrated)
        if 'user_id' in column_names:
            print("⚠️ user_id column still exists (migration may be needed)")
        else:
            print("✅ user_id column has been migrated")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database schema test error: {e}")
        return False

def test_otp_save_and_verify():
    """Test OTP save and verify with different identifier types"""
    print("\n🧪 Testing OTP save and verify...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Test 1: Save OTP with user_id (login scenario)
        user_id = "123"
        otp_code_1 = "123456"
        print(f"📧 Testing OTP save with user_id: {user_id}")
        
        cursor.execute('''
            INSERT INTO user_otp (identifier, otp_code, otp_type, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, otp_code_1, 'login', datetime.now() + timedelta(minutes=10), datetime.now()))
        
        conn.commit()
        print(f"✅ OTP saved for user_id: {user_id}")
        
        # Test 2: Save OTP with temp_id (signup scenario)
        temp_id = f"temp_{int(time.time())}_{secrets.token_hex(4)}"
        otp_code_2 = "654321"
        print(f"📧 Testing OTP save with temp_id: {temp_id}")
        
        cursor.execute('''
            INSERT INTO user_otp (identifier, otp_code, otp_type, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (temp_id, otp_code_2, 'signup', datetime.now() + timedelta(minutes=10), datetime.now()))
        
        conn.commit()
        print(f"✅ OTP saved for temp_id: {temp_id}")
        
        # Test 3: Verify OTP with user_id
        print(f"🔍 Testing OTP verify with user_id: {user_id}")
        cursor.execute('''
            SELECT otp_id FROM user_otp 
            WHERE identifier = ? AND otp_code = ? AND otp_type = ? 
            AND is_used = FALSE AND expires_at > ?
        ''', (user_id, otp_code_1, 'login', datetime.now()))
        
        result = cursor.fetchone()
        if result:
            # Mark as used
            cursor.execute('UPDATE user_otp SET is_used = TRUE WHERE otp_id = ?', (result[0],))
            conn.commit()
            print(f"✅ OTP verified for user_id: {user_id}")
        else:
            print(f"❌ OTP verification failed for user_id: {user_id}")
        
        # Test 4: Verify OTP with temp_id
        print(f"🔍 Testing OTP verify with temp_id: {temp_id}")
        cursor.execute('''
            SELECT otp_id FROM user_otp 
            WHERE identifier = ? AND otp_code = ? AND otp_type = ? 
            AND is_used = FALSE AND expires_at > ?
        ''', (temp_id, otp_code_2, 'signup', datetime.now()))
        
        result = cursor.fetchone()
        if result:
            # Mark as used
            cursor.execute('UPDATE user_otp SET is_used = TRUE WHERE otp_id = ?', (result[0],))
            conn.commit()
            print(f"✅ OTP verified for temp_id: {temp_id}")
        else:
            print(f"❌ OTP verification failed for temp_id: {temp_id}")
        
        # Test 5: Show all OTPs in database
        print(f"\n📊 All OTPs in database:")
        cursor.execute('''
            SELECT identifier, otp_code, otp_type, is_used, created_at 
            FROM user_otp 
            ORDER BY created_at DESC 
            LIMIT 10
        ''')
        
        otps = cursor.fetchall()
        for otp in otps:
            identifier, code, otp_type, used, created = otp
            status = "✅ Used" if used else "⏳ Active"
            print(f"   - {identifier} ({otp_type}): {code} - {status} - {created}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ OTP test error: {e}")
        return False

def test_otp_service_integration():
    """Test integration with the OTP service"""
    print("\n🔧 Testing OTP service integration...")
    
    try:
        # Import the OTP service
        from models.email_otp_service import EmailOTPService
        
        otp_service = EmailOTPService(DB_PATH)
        
        # Test 1: Save OTP with user_id
        user_id = "456"
        otp_code = otp_service.generate_otp()
        print(f"📧 Testing OTP service save with user_id: {user_id}, code: {otp_code}")
        
        success = otp_service.save_otp_to_db(user_id, otp_code, 'login')
        if success:
            print(f"✅ OTP service save successful for user_id: {user_id}")
        else:
            print(f"❌ OTP service save failed for user_id: {user_id}")
            return False
        
        # Test 2: Verify OTP with user_id
        print(f"🔍 Testing OTP service verify with user_id: {user_id}, code: {otp_code}")
        success = otp_service.verify_otp(user_id, otp_code, 'login')
        if success:
            print(f"✅ OTP service verify successful for user_id: {user_id}")
        else:
            print(f"❌ OTP service verify failed for user_id: {user_id}")
            return False
        
        # Test 3: Save OTP with temp_id
        temp_id = f"temp_{int(time.time())}_{secrets.token_hex(4)}"
        otp_code_2 = otp_service.generate_otp()
        print(f"📧 Testing OTP service save with temp_id: {temp_id}, code: {otp_code_2}")
        
        success = otp_service.save_otp_to_db(temp_id, otp_code_2, 'signup')
        if success:
            print(f"✅ OTP service save successful for temp_id: {temp_id}")
        else:
            print(f"❌ OTP service save failed for temp_id: {temp_id}")
            return False
        
        # Test 4: Verify OTP with temp_id
        print(f"🔍 Testing OTP service verify with temp_id: {temp_id}, code: {otp_code_2}")
        success = otp_service.verify_otp(temp_id, otp_code_2, 'signup')
        if success:
            print(f"✅ OTP service verify successful for temp_id: {temp_id}")
        else:
            print(f"❌ OTP service verify failed for temp_id: {temp_id}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ OTP service integration test error: {e}")
        return False

def cleanup_test_data():
    """Clean up test data"""
    print("\n🧹 Cleaning up test data...")
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete test OTPs
        cursor.execute("DELETE FROM user_otp WHERE identifier LIKE 'temp_%' OR identifier IN ('123', '456')")
        deleted_count = cursor.rowcount
        conn.commit()
        
        print(f"✅ Cleaned up {deleted_count} test OTPs")
        conn.close()
        
    except Exception as e:
        print(f"❌ Cleanup error: {e}")

def main():
    """Run comprehensive OTP table fix tests"""
    print("🚀 Starting OTP table fix tests")
    print("=" * 50)
    
    # Test 1: Database schema
    schema_ok = test_database_schema()
    if not schema_ok:
        print("❌ Database schema test failed. Cannot continue.")
        return
    
    # Test 2: Direct database operations
    db_ok = test_otp_save_and_verify()
    if not db_ok:
        print("❌ Direct database test failed.")
        return
    
    # Test 3: OTP service integration
    service_ok = test_otp_service_integration()
    if not service_ok:
        print("❌ OTP service integration test failed.")
        return
    
    # Cleanup
    cleanup_test_data()
    
    print("\n" + "=" * 50)
    print("🏁 OTP table fix tests completed")
    
    if schema_ok and db_ok and service_ok:
        print("✅ All tests passed - OTP table fix is working correctly")
        print("✅ The identifier field now properly handles both user_id and temp_id")
    else:
        print("❌ Some tests failed - OTP table fix needs investigation")

if __name__ == "__main__":
    main() 