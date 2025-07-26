#!/usr/bin/env python3
"""
Test script to verify database schema updates
"""

import sqlite3
import os
from models.database_init import DatabaseInitializer

def test_database_schema():
    """Test the database schema updates"""
    print("🔍 Testing database schema updates...")
    
    # Initialize database
    db_init = DatabaseInitializer()
    success = db_init.initialize_database()
    
    if not success:
        print("❌ Failed to initialize database")
        return False
    
    # Test connection and check columns
    conn = sqlite3.connect('data/sana_toolkit.db')
    cursor = conn.cursor()
    
    try:
        # Check temp_registrations table structure
        cursor.execute("PRAGMA table_info(temp_registrations)")
        columns = cursor.fetchall()
        
        print("📋 temp_registrations table columns:")
        column_names = []
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
            column_names.append(col[1])
        
        # Check if required columns exist
        required_columns = ['temp_id', 'email', 'password_hash', 'created_at', 'expires_at']
        missing_columns = [col for col in required_columns if col not in column_names]
        
        if missing_columns:
            print(f"❌ Missing columns: {missing_columns}")
            return False
        else:
            print("✅ All required columns present")
        
        # Test inserting a record with password_hash
        test_temp_id = "temp_test_123"
        test_email = "test@example.com"
        test_password_hash = "test_hash"
        
        cursor.execute("""
            INSERT OR REPLACE INTO temp_registrations 
            (temp_id, email, password_hash, created_at, expires_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now', '+20 minutes'))
        """, (test_temp_id, test_email, test_password_hash))
        
        # Verify the record was inserted
        cursor.execute("SELECT * FROM temp_registrations WHERE temp_id = ?", (test_temp_id,))
        result = cursor.fetchone()
        
        if result:
            print("✅ Test record inserted successfully")
            print(f"  - temp_id: {result[0]}")
            print(f"  - email: {result[1]}")
            print(f"  - password_hash: {result[2]}")
        else:
            print("❌ Failed to insert test record")
            return False
        
        # Clean up test record
        cursor.execute("DELETE FROM temp_registrations WHERE temp_id = ?", (test_temp_id,))
        print("✅ Test record cleaned up")
        
        print("🎉 Database schema test completed successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    test_database_schema() 