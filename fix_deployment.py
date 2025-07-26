#!/usr/bin/env python3
"""
SANA Deployment Fix Script
Fixes database schema corruption for cloud deployment
"""

import os
import sys
import time
from models.database_init import DatabaseInitializer

def fix_render_deployment():
    """Fix database issues for Render deployment"""
    print("🔧 SANA Deployment Fix Starting...")
    
    # Force clean database rebuild
    db_path = 'data/sana_toolkit.db'
    
    if os.path.exists(db_path):
        backup_path = f"{db_path}.pre_fix_backup.{int(time.time())}"
        try:
            os.rename(db_path, backup_path)
            print(f"📦 Backed up existing database to: {backup_path}")
        except Exception as e:
            print(f"❌ Error backing up database: {e}")
            os.remove(db_path)
            print("🗑️ Removed corrupted database")
    
    # Initialize fresh database
    print("🔄 Creating fresh database with correct schema...")
    db_init = DatabaseInitializer()
    
    success = db_init.initialize_database()
    
    if success:
        print("✅ Database fix completed successfully!")
        print("🚀 SANA Toolkit is ready for deployment!")
        return True
    else:
        print("❌ Database fix failed!")
        return False

if __name__ == "__main__":
    fix_render_deployment() 