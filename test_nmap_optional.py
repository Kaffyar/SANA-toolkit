#!/usr/bin/env python3
"""
Test script to verify that the SANA Flask app starts without nmap
"""

import sys
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_nmap_optional():
    """Test that the app can start without nmap"""
    
    print("🧪 Testing SANA Flask app without nmap...")
    
    try:
        # Test importing the nmap utility
        print("1. Testing nmap utility import...")
        from utils.nmap_utils import is_nmap_available, get_nmap_unavailable_message
        
        nmap_available = is_nmap_available()
        print(f"   ✅ Nmap available: {nmap_available}")
        
        if not nmap_available:
            message = get_nmap_unavailable_message()
            print(f"   ✅ Unavailable message: {message['message']}")
        
        # Test importing the main app
        print("2. Testing main app import...")
        from app import app, create_app
        
        print("   ✅ App imported successfully")
        
        # Test creating the app
        print("3. Testing app creation...")
        test_app = create_app()
        print("   ✅ App created successfully")
        
        # Test nmap availability in app context
        print("4. Testing nmap availability in app context...")
        with test_app.app_context():
            from utils.nmap_utils import is_nmap_available
            nmap_available = is_nmap_available()
            print(f"   ✅ Nmap available in app context: {nmap_available}")
        
        print("\n🎉 All tests passed! The app can start without nmap.")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_database_schema():
    """Test database schema creation"""
    
    print("\n🗄️  Testing database schema...")
    
    try:
        from models.database_init import DatabaseInitializer
        
        # Create a test database in current directory
        test_db_path = os.path.join(os.getcwd(), 'test_sana.db')
        db_init = DatabaseInitializer(test_db_path)
        
        # Test database initialization
        success = db_init.initialize_database()
        
        if success:
            print("   ✅ Database schema created successfully")
            
            # Clean up test database
            if os.path.exists(test_db_path):
                os.remove(test_db_path)
                print("   ✅ Test database cleaned up")
            
            return True
        else:
            print("   ❌ Database schema creation failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Database error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 SANA Flask App - Nmap Optional Test")
    print("=" * 50)
    
    # Test nmap optional functionality
    nmap_test = test_nmap_optional()
    
    # Test database schema
    db_test = test_database_schema()
    
    print("\n" + "=" * 50)
    if nmap_test and db_test:
        print("✅ All tests passed! App is ready for deployment without nmap.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the errors above.")
        sys.exit(1) 