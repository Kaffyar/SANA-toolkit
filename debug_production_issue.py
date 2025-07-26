#!/usr/bin/env python3
"""
Debug script for production database issue
"""

import sqlite3
import os
from datetime import datetime

def debug_database_state():
    """Debug the current database state"""
    print("🔍 Debugging Production Database Issue")
    print("=" * 50)
    
    db_path = 'data/sana_toolkit.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Database file not found: {db_path}")
        return
    
    print(f"📁 Database file: {db_path}")
    print(f"💾 File size: {os.path.getsize(db_path):,} bytes")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check temp_registrations table
        print("\n📋 temp_registrations table:")
        cursor.execute("SELECT COUNT(*) FROM temp_registrations")
        temp_count = cursor.fetchone()[0]
        print(f"   Total records: {temp_count}")
        
        if temp_count > 0:
            cursor.execute("SELECT temp_id, email, created_at FROM temp_registrations ORDER BY created_at DESC LIMIT 5")
            recent_records = cursor.fetchall()
            print("   Recent records:")
            for record in recent_records:
                print(f"     - {record[0]} -> {record[1]} ({record[2]})")
        
        # Check user_otp table
        print("\n📋 user_otp table:")
        cursor.execute("SELECT COUNT(*) FROM user_otp")
        otp_count = cursor.fetchone()[0]
        print(f"   Total records: {otp_count}")
        
        if otp_count > 0:
            cursor.execute("SELECT identifier, otp_code, otp_type, created_at FROM user_otp ORDER BY created_at DESC LIMIT 5")
            recent_otps = cursor.fetchall()
            print("   Recent OTPs:")
            for record in recent_otps:
                print(f"     - {record[0]} -> {record[1]} ({record[2]}) - {record[3]}")
        
        # Check table schema
        print("\n🔧 Table Schema:")
        cursor.execute("PRAGMA table_info(temp_registrations)")
        temp_columns = cursor.fetchall()
        print("   temp_registrations columns:")
        for col in temp_columns:
            print(f"     - {col[1]} ({col[2]})")
        
        cursor.execute("PRAGMA table_info(user_otp)")
        otp_columns = cursor.fetchall()
        print("   user_otp columns:")
        for col in otp_columns:
            print(f"     - {col[1]} ({col[2]})")
        
        # Check for specific temp_id from logs
        specific_temp_id = "temp_1753562395_5a2f0df8"
        print(f"\n🔍 Looking for specific temp_id: {specific_temp_id}")
        
        cursor.execute("SELECT temp_id, email, created_at FROM temp_registrations WHERE temp_id = ?", (specific_temp_id,))
        specific_record = cursor.fetchone()
        
        if specific_record:
            print(f"   ✅ Found: {specific_record}")
        else:
            print(f"   ❌ Not found in temp_registrations")
            
            # Check if it exists in user_otp
            cursor.execute("SELECT identifier, otp_code, otp_type FROM user_otp WHERE identifier = ?", (specific_temp_id,))
            otp_record = cursor.fetchone()
            if otp_record:
                print(f"   ⚠️ Found in user_otp: {otp_record}")
            else:
                print(f"   ❌ Not found in user_otp either")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Database error: {e}")

def test_database_insertion():
    """Test database insertion manually"""
    print("\n🧪 Testing Database Insertion")
    print("=" * 30)
    
    try:
        conn = sqlite3.connect('data/sana_toolkit.db')
        cursor = conn.cursor()
        
        # Test temp_registrations insertion
        test_temp_id = f"test_temp_{int(datetime.now().timestamp())}"
        test_email = "test@example.com"
        
        print(f"📝 Testing insertion with temp_id: {test_temp_id}")
        
        cursor.execute('''
            INSERT INTO temp_registrations 
            (temp_id, email, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (test_temp_id, test_email, datetime.now(), 
              datetime.now().replace(year=datetime.now().year + 1)))
        
        conn.commit()
        print("✅ Insertion successful")
        
        # Verify insertion
        cursor.execute("SELECT temp_id FROM temp_registrations WHERE temp_id = ?", (test_temp_id,))
        result = cursor.fetchone()
        
        if result:
            print("✅ Verification successful")
        else:
            print("❌ Verification failed")
        
        # Clean up
        cursor.execute("DELETE FROM temp_registrations WHERE temp_id = ?", (test_temp_id,))
        conn.commit()
        print("🧹 Cleanup completed")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Test error: {e}")

if __name__ == "__main__":
    debug_database_state()
    test_database_insertion() 