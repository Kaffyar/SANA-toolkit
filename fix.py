import sqlite3

# Fix the constraint in the existing database
conn = sqlite3.connect('data/sana_toolkit.db')
cursor = conn.cursor()

try:
    # Drop and recreate the temp_registrations table with correct constraint
    cursor.execute("DROP TABLE IF EXISTS temp_registrations")
    cursor.execute("""
        CREATE TABLE temp_registrations (
            temp_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            
            CONSTRAINT chk_temp_id_format CHECK (temp_id LIKE 'temp_%'),
            CONSTRAINT chk_email_format CHECK (email LIKE '%@%.%')
        )
    """)
    conn.commit()
    print("✅ Fixed email constraint in temp_registrations table")
except Exception as e:
    print(f"❌ Error: {e}")
finally:
    conn.close()