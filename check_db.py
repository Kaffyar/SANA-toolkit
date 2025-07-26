import sqlite3
import os

def check_database():
    db_path = 'data/sana_toolkit.db'
    
    if not os.path.exists(db_path):
        print("Database file doesn't exist")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check existing tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("Existing tables:", [table[0] for table in tables])
        
        # Check if user_settings table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_settings'")
        settings_table = cursor.fetchone()
        
        if settings_table:
            print("✅ user_settings table exists")
            # Check columns
            cursor.execute("PRAGMA table_info(user_settings)")
            columns = cursor.fetchall()
            print("Columns:", [col[1] for col in columns])
            
            # Check if there's any data
            cursor.execute("SELECT COUNT(*) FROM user_settings")
            count = cursor.fetchone()[0]
            print(f"Number of settings records: {count}")
            
            if count > 0:
                cursor.execute("SELECT * FROM user_settings LIMIT 5")
                records = cursor.fetchall()
                print("Sample records:")
                for record in records:
                    print(f"  {record}")
        else:
            print("❌ user_settings table doesn't exist")
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database() 