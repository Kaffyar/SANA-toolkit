#!/usr/bin/env python3
"""
Test script to verify Render environment configuration
"""

import os
import secrets

def test_render_config():
    """Test Render-specific configuration"""
    print("🚀 Testing Render Environment Configuration")
    print("=" * 50)
    
    # Test environment variables
    print("🌍 Environment Variables:")
    print(f"   FLASK_ENV: {os.environ.get('FLASK_ENV', 'Not set')}")
    print(f"   RENDER: {os.environ.get('RENDER', 'Not set')}")
    print(f"   PORT: {os.environ.get('PORT', 'Not set')}")
    print(f"   FLASK_SECRET_KEY: {'Set' if os.environ.get('FLASK_SECRET_KEY') else 'Not set'}")
    
    # Test production detection
    is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER') == 'true'
    print(f"\n🔧 Production Detection:")
    print(f"   Is Production: {is_production}")
    
    # Test secret key generation
    print(f"\n🔑 Secret Key Test:")
    if os.environ.get('RENDER') == 'true':
        secret_key = secrets.token_hex(32)
        print(f"   Generated Render secret key: {secret_key[:16]}...")
    else:
        print(f"   Using file-based secret key for local development")
    
    # Test session configuration
    print(f"\n🍪 Session Configuration:")
    print(f"   SESSION_COOKIE_SECURE: {is_production}")
    print(f"   SESSION_COOKIE_HTTPONLY: True")
    print(f"   SESSION_COOKIE_SAMESITE: Lax")
    print(f"   SESSION_COOKIE_NAME: sana_session")
    
    print(f"\n✅ Render configuration test completed!")

if __name__ == "__main__":
    test_render_config() 