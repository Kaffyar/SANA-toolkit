#!/usr/bin/env python3
"""
Test script to verify session configuration for cloud deployment
"""

import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_session_configuration():
    """Test that the session configuration is properly set up"""
    
    print("🧪 Testing session configuration for cloud deployment...")
    
    try:
        # Test importing the app
        print("1. Testing app import...")
        from app import create_app
        
        print("   ✅ App imported successfully")
        
        # Test creating the app
        print("2. Testing app creation...")
        app = create_app()
        
        print("   ✅ App created successfully")
        
        # Test session configuration
        print("3. Testing session configuration...")
        
        # Check secret key
        if app.secret_key:
            print(f"   ✅ Secret key is set (length: {len(app.secret_key)})")
        else:
            print("   ❌ Secret key is not set")
            return False
        
        # Check session configuration
        session_config = {
            'SESSION_TYPE': app.config.get('SESSION_TYPE'),
            'SESSION_PERMANENT': app.config.get('SESSION_PERMANENT'),
            'SESSION_USE_SIGNER': app.config.get('SESSION_USE_SIGNER'),
            'SESSION_COOKIE_SECURE': app.config.get('SESSION_COOKIE_SECURE'),
            'SESSION_COOKIE_HTTPONLY': app.config.get('SESSION_COOKIE_HTTPONLY'),
            'SESSION_COOKIE_SAMESITE': app.config.get('SESSION_COOKIE_SAMESITE'),
            'PERMANENT_SESSION_LIFETIME': app.config.get('PERMANENT_SESSION_LIFETIME'),
        }
        
        print("   ✅ Session configuration:")
        for key, value in session_config.items():
            print(f"      {key}: {value}")
        
        # Test session functionality
        print("4. Testing session functionality...")
        with app.test_client() as client:
            with app.app_context():
                # Test setting session data
                with client.session_transaction() as sess:
                    sess['test_key'] = 'test_value'
                    sess['otp_email'] = 'test@example.com'
                    sess['otp_type'] = 'login'
                
                # Test reading session data
                response = client.get('/auth/session-debug')
                if response.status_code == 200:
                    print("   ✅ Session debug endpoint works")
                else:
                    print(f"   ❌ Session debug endpoint failed: {response.status_code}")
                    return False
        
        print("\n🎉 All session configuration tests passed!")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_environment_variables():
    """Test environment variable configuration"""
    
    print("\n🌍 Testing environment variable configuration...")
    
    # Test FLASK_ENV
    flask_env = os.environ.get('FLASK_ENV', 'development')
    print(f"   FLASK_ENV: {flask_env}")
    
    # Test FLASK_SECRET_KEY
    flask_secret = os.environ.get('FLASK_SECRET_KEY')
    if flask_secret:
        print(f"   ✅ FLASK_SECRET_KEY is set (length: {len(flask_secret)})")
    else:
        print("   ⚠️  FLASK_SECRET_KEY not set (will use file-based key)")
    
    # Test PORT
    port = os.environ.get('PORT')
    if port:
        print(f"   ✅ PORT is set: {port}")
    else:
        print("   ⚠️  PORT not set (will use default 5000)")
    
    return True

if __name__ == "__main__":
    print("🚀 SANA Flask App - Session Configuration Test")
    print("=" * 60)
    
    # Test environment variables
    env_test = test_environment_variables()
    
    # Test session configuration
    session_test = test_session_configuration()
    
    print("\n" + "=" * 60)
    if env_test and session_test:
        print("✅ All tests passed! Session configuration is ready for cloud deployment.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the errors above.")
        sys.exit(1) 