#!/usr/bin/env python3
"""
Test script to verify the complete signup flow with password storage
"""

import requests
import json
import time
import sqlite3
from models.user_model import UserManager

def test_signup_flow():
    """Test the complete signup flow"""
    print("🔍 Testing complete signup flow...")
    
    # Test data
    test_email = f"test_{int(time.time())}@example.com"
    test_password = "TestPass123!"
    
    print(f"📧 Using test email: {test_email}")
    print(f"🔑 Using test password: {test_password}")
    
    # Step 1: Send signup OTP
    print("\n1️⃣ Testing signup OTP send...")
    user_manager = UserManager()
    
    success, message, temp_id = user_manager.send_signup_otp(test_email, test_password)
    
    if not success:
        print(f"❌ Failed to send signup OTP: {message}")
        return False
    
    print(f"✅ Signup OTP sent successfully")
    print(f"   - temp_id: {temp_id}")
    print(f"   - message: {message}")
    
    # Step 2: Verify OTP is stored in database
    print("\n2️⃣ Verifying OTP storage in database...")
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    try:
        # Check temp_registrations
        cursor.execute("SELECT * FROM temp_registrations WHERE temp_id = ?", (temp_id,))
        temp_record = cursor.fetchone()
        
        if temp_record:
            print("✅ Temporary registration found in database")
            print(f"   - temp_id: {temp_record[0]}")
            print(f"   - email: {temp_record[1]}")
            print(f"   - password_hash: {'Present' if temp_record[3] else 'Missing'}")
            print(f"   - created_at: {temp_record[2]}")
            print(f"   - expires_at: {temp_record[4] if len(temp_record) > 4 else 'Not set'}")
        else:
            print("❌ Temporary registration not found in database")
            return False
        
        # Check OTP
        cursor.execute("SELECT * FROM user_otp WHERE user_id = ? AND otp_type = 'signup'", (temp_id,))
        otp_record = cursor.fetchone()
        
        if otp_record:
            print("✅ OTP found in database")
            print(f"   - otp_code: {otp_record[2]}")
            print(f"   - expires_at: {otp_record[5]}")
            otp_code = otp_record[2]
        else:
            print("❌ OTP not found in database")
            return False
            
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    finally:
        conn.close()
    
    # Step 3: Test OTP verification with stored password
    print("\n3️⃣ Testing OTP verification with stored password...")
    
    success, message = user_manager.verify_signup_otp(temp_id, otp_code)
    
    if success:
        print("✅ OTP verification successful")
        print(f"   - message: {message}")
    else:
        print(f"❌ OTP verification failed: {message}")
        return False
    
    # Step 4: Verify user was created
    print("\n4️⃣ Verifying user creation...")
    
    if user_manager.user_exists(test_email):
        print("✅ User account created successfully")
        
        # Get user details
        user = user_manager.get_user_by_email(test_email)
        if user:
            print(f"   - user_id: {user['user_id']}")
            print(f"   - email: {user['email']}")
            print(f"   - is_verified: {user['is_verified']}")
            print(f"   - is_active: {user['is_active']}")
    else:
        print("❌ User account not created")
        return False
    
    # Step 5: Verify temp registration was cleaned up
    print("\n5️⃣ Verifying cleanup...")
    
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM temp_registrations WHERE temp_id = ?", (temp_id,))
        temp_count = cursor.fetchone()[0]
        
        if temp_count == 0:
            print("✅ Temporary registration cleaned up")
        else:
            print("❌ Temporary registration not cleaned up")
            return False
            
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    finally:
        conn.close()
    
    print("\n🎉 Complete signup flow test successful!")
    return True

def test_session_fallback():
    """Test the session fallback scenario"""
    print("\n🔄 Testing session fallback scenario...")
    
    # Test data
    test_email = f"fallback_{int(time.time())}@example.com"
    test_password = "FallbackPass123!"
    
    print(f"📧 Using test email: {test_email}")
    
    # Step 1: Send signup OTP (simulating session storage)
    user_manager = UserManager()
    success, message, temp_id = user_manager.send_signup_otp(test_email, test_password)
    
    if not success:
        print(f"❌ Failed to send signup OTP: {message}")
        return False
    
    # Step 2: Get OTP from database (simulating session loss)
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT otp_code FROM user_otp WHERE user_id = ? AND otp_type = 'signup'", (temp_id,))
        otp_record = cursor.fetchone()
        otp_code = otp_record[0] if otp_record else None
    finally:
        conn.close()
    
    if not otp_code:
        print("❌ Could not retrieve OTP from database")
        return False
    
    # Step 3: Test verification without session (simulating session failure)
    print("🔄 Simulating session failure and using database fallback...")
    
    success, message = user_manager.verify_signup_otp(temp_id, otp_code)
    
    if success:
        print("✅ Session fallback verification successful")
        print(f"   - message: {message}")
        
        if user_manager.user_exists(test_email):
            print("✅ User account created via fallback")
        else:
            print("❌ User account not created via fallback")
            return False
    else:
        print(f"❌ Session fallback verification failed: {message}")
        return False
    
    print("🎉 Session fallback test successful!")
    return True

if __name__ == "__main__":
    print("🚀 Starting signup flow tests...")
    
    # Test 1: Complete signup flow
    if test_signup_flow():
        print("✅ Complete signup flow test passed")
    else:
        print("❌ Complete signup flow test failed")
        exit(1)
    
    # Test 2: Session fallback
    if test_session_fallback():
        print("✅ Session fallback test passed")
    else:
        print("❌ Session fallback test failed")
        exit(1)
    
    print("\n🎉 All tests passed! The signup flow is working correctly.") 