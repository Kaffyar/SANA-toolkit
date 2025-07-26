from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash
import logging
import re
from datetime import datetime, timedelta
from functools import wraps
import secrets
from typing import Dict, Any, Tuple, Optional, Union
from urllib.parse import urlparse

# Import your models
try:
    from models.user_model import UserManager
    from models.database_init import DatabaseInitializer
except ImportError:
    # Fallback for testing
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from models.user_model import UserManager
    from models.database_init import DatabaseInitializer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
auth_bp = Blueprint('auth', __name__)

# Initialize User Manager
user_manager = UserManager()

# FIXED: Add configuration constants
class AuthConfig:
    OTP_EXPIRY_MINUTES = 20
    RESEND_COOLDOWN_SECONDS = 60
    SESSION_TIMEOUT_HOURS = 24
    MAX_SESSION_INACTIVITY_HOURS = 2
    
    # Rate limiting
    MAX_LOGIN_ATTEMPTS_PER_HOUR = 10
    MAX_OTP_REQUESTS_PER_HOUR = 5

# FIXED: Enhanced authentication decorator
def login_required(f):
    """Decorator to require login for protected routes with session validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check basic session authentication
        if 'user_id' not in session or not session.get('authenticated'):
            return handle_unauthenticated_request()
        
        # Validate session freshness
        if not is_session_valid():
            session.clear()
            return handle_unauthenticated_request()
        
        # Check if user still exists and is active
        user = user_manager.get_user_by_id(session['user_id'])
        if not user or not user['is_active']:
            session.clear()
            logger.warning(f"Invalid or inactive user in session: {session.get('user_id')}")
            return handle_unauthenticated_request()
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        
        return f(*args, **kwargs)
    return decorated_function

def handle_unauthenticated_request():
    """Handle unauthenticated requests consistently"""
    if request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'Authentication required',
            'redirect': url_for('auth.login')
        }), 401
    
    # Store the URL they were trying to access
    if request.method == 'GET':
        session['next_url'] = request.url
    return redirect(url_for('auth.login'))

def is_session_valid() -> bool:
    """Check if current session is valid and not expired"""
    try:
        # Check session timeout
        login_time_str = session.get('login_time')
        if login_time_str:
            login_time = datetime.fromisoformat(login_time_str)
            if datetime.now() - login_time > timedelta(hours=AuthConfig.SESSION_TIMEOUT_HOURS):
                logger.info("Session expired due to timeout")
                return False
        
        # Check inactivity timeout
        last_activity_str = session.get('last_activity')
        if last_activity_str:
            last_activity = datetime.fromisoformat(last_activity_str)
            if datetime.now() - last_activity > timedelta(hours=AuthConfig.MAX_SESSION_INACTIVITY_HOURS):
                logger.info("Session expired due to inactivity")
                return False
        
        return True
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid session timestamp: {e}")
        return False

# FIXED: Enhanced helper functions
def is_safe_url(target: str) -> bool:
    """Check if redirect URL is safe to prevent open redirect attacks"""
    if not target:
        return False
    
    try:
        # Parse the URL
        parsed = urlparse(target)
        
        # Only allow relative URLs or same-origin URLs
        if parsed.netloc and parsed.netloc != request.host:
            return False
        
        # Prevent javascript: and data: URLs
        if parsed.scheme and parsed.scheme.lower() not in ['http', 'https', '']:
            return False
        
        return True
    except Exception:
        return False

def get_client_info() -> Dict[str, str]:
    """Get client information for security logging"""
    return {
        'ip_address': get_client_ip(),
        'user_agent': request.headers.get('User-Agent', 'Unknown')[:255],  # Limit length
        'timestamp': datetime.now().isoformat()
    }

def get_client_ip() -> str:
    """Get client IP address handling proxies"""
    # Check for forwarded headers (in order of preference)
    forwarded_headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED'
    ]
    
    for header in forwarded_headers:
        if header in request.environ:
            # Get first IP if multiple are present
            ip = request.environ[header].split(',')[0].strip()
            if ip:
                return ip
    
    return request.environ.get('REMOTE_ADDR', 'Unknown')

def validate_otp_session() -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """Validate OTP session with enhanced debugging for cloud deployment"""
    
    # Enhanced debugging with session ID and client info
    client_info = get_client_info()
    logger.info(f"🔍 Session validation for {client_info['ip_address']}")
    logger.info(f"🔍 Session debug - All keys: {list(session.keys())}")
    logger.info(f"🔍 Session debug - otp_email: {session.get('otp_email')}")
    logger.info(f"🔍 Session debug - otp_type: {session.get('otp_type')}")
    logger.info(f"🔍 Session debug - otp_sent_at: {session.get('otp_sent_at')}")
    logger.info(f"🔍 Session debug - Session ID: {session.get('_id', 'No session ID')}")
    logger.info(f"🔍 Session debug - Session modified: {session.modified}")
    logger.info(f"🔍 Session debug - Session permanent: {session.permanent}")
    
    # Check if session is completely empty (common issue in cloud deployments)
    if not session:
        logger.warning(f"❌ Empty session for {client_info['ip_address']}")
        return False, 'Session not found. Please start over.', {}
    
    required_keys = ['otp_email', 'otp_type']
    
    for key in required_keys:
        if key not in session:
            logger.warning(f"❌ Missing {key} in session for {client_info['ip_address']}")
            logger.warning(f"❌ Available session keys: {list(session.keys())}")
            return False, 'Verification session not found. Please start over.', {}
    
    # Check session expiry
    if 'otp_sent_at' in session:
        try:
            sent_time = datetime.fromisoformat(session['otp_sent_at'])
            if datetime.now() - sent_time > timedelta(minutes=AuthConfig.OTP_EXPIRY_MINUTES):
                # Clear expired session data
                clear_otp_session()
                return False, 'Verification code has expired. Please request a new one.', {}
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid OTP timestamp in session: {e}")
            clear_otp_session()
            return False, 'Invalid session data. Please start over.', {}
    
    # Mark session as modified to ensure it gets saved
    session.modified = True
    
    return True, None, {
        'email': session['otp_email'],
        'otp_type': session.get('otp_type', 'login'),
        'temp_user_id': session.get('temp_user_id'),
        'signup_password': session.get('signup_password')
    }

def clear_otp_session() -> None:
    """Clear OTP-related session data"""
    otp_keys = ['otp_email', 'otp_type', 'otp_sent_at', 'temp_user_id', 'signup_password']
    for key in otp_keys:
        session.pop(key, None)

def create_success_response(message: str, redirect_url: Optional[str] = None, data: Optional[Dict] = None) -> Dict[str, Any]:
    """Create standardized success response"""
    response = {
        'status': 'success',
        'message': message
    }
    if redirect_url:
        response['redirect'] = redirect_url
    if data:
        response.update(data)
    return response

def create_error_response(message: str, redirect_url: Optional[str] = None, error_code: Optional[str] = None) -> Dict[str, Any]:
    """Create standardized error response"""
    response = {
        'status': 'error',
        'message': message
    }
    if redirect_url:
        response['redirect'] = redirect_url
    if error_code:
        response['error_code'] = error_code
    return response

# FIXED: Enhanced route handlers
@auth_bp.route('/login')
def login():
    """Display login page with redirect handling"""
    if 'user_id' in session and session.get('authenticated') and is_session_valid():
        next_url = session.pop('next_url', None)
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for('index'))
    
    # Clear any stale session data
    session.clear()
    return render_template('auth/login.html')

@auth_bp.route('/signup')
def signup():
    """Display signup page with redirect handling"""
    if 'user_id' in session and session.get('authenticated') and is_session_valid():
        return redirect(url_for('index'))
    
    return render_template('auth/signup.html')

@auth_bp.route('/verify-otp')
def verify_otp_page():
    """Display OTP verification page with session validation and fallback"""
    is_valid, error_msg, session_data = validate_otp_session()
    
    if is_valid:
        # Session is valid, use session data
        temp_user_id = session.get('temp_user_id')
        return render_template('auth/verify_otp.html', 
                             email=session_data['email'],
                             otp_type=session_data['otp_type'],
                             temp_user_id=temp_user_id)
    else:
        # Session is invalid, but don't redirect immediately
        # Instead, render the page with minimal data and let frontend handle fallback
        logger.warning(f"⚠️ Session validation failed for verify-otp page: {error_msg}")
        
        # Try to get email from query parameters (if user clicked email link)
        email = request.args.get('email', '').strip()
        otp_type = request.args.get('type', 'signup')  # Default to signup
        
        if email and user_manager.validate_email(email):
            # We have a valid email, render the page
            # The frontend will handle the database fallback
            return render_template('auth/verify_otp.html', 
                                 email=email,
                                 otp_type=otp_type,
                                 temp_user_id=None)  # Will be retrieved via database fallback
        else:
            # No valid email, redirect to login
            flash('Please start the verification process from the beginning.', 'error')
            return redirect(url_for('auth.login'))

@auth_bp.route('/api/send-login-otp', methods=['POST'])
def send_login_otp():
    """Send OTP for login with enhanced validation and rate limiting"""
    try:
        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify(create_error_response('Email is required')), 400
        
        # Validate email format
        if not user_manager.validate_email(email):
            return jsonify(create_error_response('Invalid email format')), 400
        
        # Check for duplicate requests
        current_email_in_session = session.get('otp_email')
        if current_email_in_session == email and 'otp_sent_at' in session:
            try:
                sent_time = datetime.fromisoformat(session['otp_sent_at'])
                if datetime.now() - sent_time < timedelta(seconds=AuthConfig.RESEND_COOLDOWN_SECONDS):
                    logger.info(f"🔄 Ignoring duplicate OTP request for {email}")
                    return jsonify(create_success_response(
                        'Verification code already sent to your email',
                        url_for('auth.verify_otp_page')
                    ))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking OTP timestamp: {e}")
        
        # Send OTP
        success, message = user_manager.send_login_otp(email)
        
        if success:
            # Enhanced session debugging
            client_info = get_client_info()
            logger.info(f"🔐 Login OTP sent to {email} from {client_info['ip_address']}")
            
            # Try to update session with comprehensive debugging
            try:
                # Clear any existing session data first
                clear_otp_session()
                
                # Set new session data
                session['otp_email'] = email
                session['otp_type'] = 'login'
                session['otp_sent_at'] = datetime.now().isoformat()
                session['session_created'] = datetime.now().isoformat()
                session['client_ip'] = client_info['ip_address']
                session['user_agent'] = client_info['user_agent']
                
                # Force session to be modified and permanent
                session.modified = True
                session.permanent = True
                
                # Log detailed session information
                logger.info(f"🔐 Session data set successfully:")
                logger.info(f"   - Session keys: {list(session.keys())}")
                logger.info(f"   - Session modified: {session.modified}")
                logger.info(f"   - Session permanent: {session.permanent}")
                logger.info(f"   - otp_email: {session.get('otp_email')}")
                logger.info(f"   - otp_type: {session.get('otp_type')}")
                
                # Test session persistence immediately
                test_session_data = {
                    'otp_email': session.get('otp_email'),
                    'otp_type': session.get('otp_type'),
                    'session_created': session.get('session_created')
                }
                logger.info(f"🔐 Session test data: {test_session_data}")
                
            except Exception as session_error:
                logger.error(f"❌ Session error during OTP send: {session_error}")
                # Continue anyway - we'll use database fallback
            
            return jsonify(create_success_response(
                'Verification code sent to your email',
                url_for('auth.verify_otp_page')
            ))
        else:
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error sending login OTP: {str(e)}")
        return jsonify(create_error_response('An error occurred. Please try again.')), 500

@auth_bp.route('/api/send-signup-otp', methods=['POST'])
def send_signup_otp():
    """Send OTP for signup with comprehensive validation"""
    try:
        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '').strip()
        
        # Input validation
        if not email:
            return jsonify(create_error_response('Email is required')), 400
            
        if not password:
            return jsonify(create_error_response('Password is required')), 400
        
        # Validate email format
        if not user_manager.validate_email(email):
            return jsonify(create_error_response('Invalid email format')), 400
            
        # Validate password strength
        is_valid, message = user_manager.validate_password(password)
        if not is_valid:
            return jsonify(create_error_response(message)), 400
        
        # Check if user already exists
        if user_manager.user_exists(email):
            return jsonify(create_error_response('An account with this email already exists')), 409
        
        # Check for duplicate requests
        current_email_in_session = session.get('otp_email')
        if current_email_in_session == email and 'otp_sent_at' in session:
            try:
                sent_time = datetime.fromisoformat(session['otp_sent_at'])
                if datetime.now() - sent_time < timedelta(seconds=AuthConfig.RESEND_COOLDOWN_SECONDS):
                    logger.info(f"🔄 Ignoring duplicate signup OTP request for {email}")
                    return jsonify(create_success_response(
                        'Verification code already sent to your email',
                        url_for('auth.verify_otp_page')
                    ))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking OTP timestamp: {e}")
        
        # Clear any old session data before sending new OTP
        clear_otp_session()
        
        # Send signup OTP
        success, message, temp_id = user_manager.send_signup_otp(email, password)
        
        if success:
            # Enhanced session debugging for signup
            client_info = get_client_info()
            logger.info(f"📧 Signup OTP sent to {email} from {client_info['ip_address']}")
            
            # Try to update session with comprehensive debugging
            try:
                # Clear any existing session data first
                clear_otp_session()
                
                # Set new session data
                session['otp_email'] = email
                session['otp_type'] = 'signup'
                session['otp_sent_at'] = datetime.now().isoformat()
                session['temp_user_id'] = temp_id
                session['signup_password'] = password
                session['session_created'] = datetime.now().isoformat()
                session['client_ip'] = client_info['ip_address']
                session['user_agent'] = client_info['user_agent']
                
                # Force session to be modified and permanent
                session.modified = True
                session.permanent = True
                
                # Log detailed session information
                logger.info(f"📧 Session data set successfully:")
                logger.info(f"   - Session keys: {list(session.keys())}")
                logger.info(f"   - Session modified: {session.modified}")
                logger.info(f"   - Session permanent: {session.permanent}")
                logger.info(f"   - otp_email: {session.get('otp_email')}")
                logger.info(f"   - otp_type: {session.get('otp_type')}")
                logger.info(f"   - temp_user_id: {session.get('temp_user_id')}")
                
                # Test session persistence immediately
                test_session_data = {
                    'otp_email': session.get('otp_email'),
                    'otp_type': session.get('otp_type'),
                    'temp_user_id': session.get('temp_user_id'),
                    'session_created': session.get('session_created')
                }
                logger.info(f"📧 Session test data: {test_session_data}")
                
            except Exception as session_error:
                logger.error(f"❌ Session error during signup OTP send: {session_error}")
                # Continue anyway - we'll use database fallback
            
            return jsonify(create_success_response(
                'Verification code sent to your email',
                url_for('auth.verify_otp_page')
            ))
        else:
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error sending signup OTP: {str(e)}")
        return jsonify(create_error_response('An error occurred. Please try again.')), 500

@auth_bp.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP code with comprehensive validation, security logging, and database fallback"""
    try:
        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        otp_code = data.get('otp_code', '').strip()
        
        if not otp_code:
            return jsonify(create_error_response('Verification code is required')), 400
        
        # Validate OTP format
        if not otp_code.isdigit() or len(otp_code) != 6:
            return jsonify(create_error_response('Invalid verification code format')), 400
        
        client_info = get_client_info()
        logger.info(f"🔍 OTP verification attempt from {client_info['ip_address']}")
        logger.info(f"🔍 Session debug - All keys: {list(session.keys())}")
        logger.info(f"🔍 Session debug - Session modified: {session.modified}")
        logger.info(f"🔍 Session debug - Session permanent: {session.permanent}")
        
        # Try session-based verification first
        is_valid, error_msg, session_data = validate_otp_session()
        
        if is_valid:
            logger.info(f"✅ Session-based verification successful for {session_data['email']}")
            email = session_data['email']
            otp_type = session_data['otp_type']
        else:
            logger.warning(f"⚠️ Session verification failed: {error_msg}")
            logger.info(f"🔄 Attempting database fallback verification...")
            
            # Database fallback: try to find recent OTP for this IP
            email = data.get('email', '').strip().lower()
            if not email:
                return jsonify(create_error_response('Email is required for verification')), 400
            
            # Try to determine OTP type from database
            otp_type = 'login'  # Default to login
            try:
                # Check if user exists to determine type
                if user_manager.user_exists(email):
                    otp_type = 'login'
                else:
                    # Check for recent signup OTP
                    otp_type = 'signup'
                logger.info(f"🔄 Database fallback: Using {otp_type} verification for {email}")
            except Exception as db_error:
                logger.error(f"❌ Database fallback error: {db_error}")
                return jsonify(create_error_response('Verification failed. Please request a new code.')), 400
        
        # Handle login OTP verification
        if otp_type == 'login':
            success, message = user_manager.verify_login_otp(email, otp_code)
            
            if success:
                # Get user info
                user = user_manager.get_user_by_email(email)
                if user:
                    # Create secure session with enhanced cloud deployment support
                    session.clear()  # Clear all previous session data
                    session['user_id'] = user['user_id']
                    session['user_email'] = user['email']
                    session['authenticated'] = True
                    session['login_time'] = datetime.now().isoformat()
                    session['last_activity'] = datetime.now().isoformat()
                    session['session_id'] = secrets.token_urlsafe(32)
                    
                    # Ensure session is marked as modified and permanent
                    session.modified = True
                    session.permanent = True
                    
                    # Get safe redirect URL
                    next_url = session.pop('next_url', None)
                    if next_url and is_safe_url(next_url):
                        redirect_url = next_url
                    else:
                        redirect_url = url_for('index')
                    
                    logger.info(f"✅ User {email} logged in successfully from {client_info['ip_address']}")
                    return jsonify(create_success_response('Login successful', redirect_url))
                else:
                    logger.error(f"User not found after successful OTP verification: {email}")
                    return jsonify(create_error_response('User account not found')), 500
            else:
                logger.warning(f"🔒 Failed OTP verification for {email} from {client_info['ip_address']}")
                return jsonify(create_error_response(message)), 400
            
        # Handle signup OTP verification
        elif otp_type == 'signup':
            temp_id = session_data.get('temp_user_id')
            password = session_data.get('signup_password')
            
            if not temp_id or not password:
                return jsonify(create_error_response(
                    'Invalid registration session. Please start over.',
                    url_for('auth.signup')
                )), 400
                
            # Verify OTP and create user
            success, message = user_manager.verify_signup_otp(temp_id, otp_code, password)
            
            if success:
                # Clear all session data
                session.clear()
                
                logger.info(f"✅ User {email} signup completed from {client_info['ip_address']}")
                return jsonify(create_success_response(
                    'Account created successfully! Please login.',
                    url_for('auth.login')
                ))
            else:
                logger.warning(f"🔒 Failed signup OTP verification for {email} from {client_info['ip_address']}")
                return jsonify(create_error_response(message)), 400
        
        else:
            return jsonify(create_error_response('Invalid verification type')), 400
            
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        return jsonify(create_error_response('An error occurred during verification. Please try again.')), 500

@auth_bp.route('/api/verify-otp-db', methods=['POST'])
def verify_otp_database_fallback():
    """Database-backed OTP verification fallback when sessions fail"""
    logger.info("🔄 DEBUG: verify_otp_database_fallback function called - NEW VERSION")
    try:
        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        email = data.get('email', '').strip().lower()
        otp_code = data.get('otp_code', '').strip()
        
        if not email or not otp_code:
            return jsonify(create_error_response('Email and verification code are required')), 400
        
        # Validate OTP format
        if not otp_code.isdigit() or len(otp_code) != 6:
            return jsonify(create_error_response('Invalid verification code format')), 400
        
        client_info = get_client_info()
        logger.info(f"🔄 Database fallback OTP verification for {email} from {client_info['ip_address']}")
        
        # Determine OTP type
        logger.info(f"🔄 Checking if user exists for {email}")
        user_exists = user_manager.user_exists(email)
        logger.info(f"🔄 User exists result: {user_exists}")
        
        if user_exists:
            logger.info(f"🔄 User exists, treating as login")
            otp_type = 'login'
            success, message = user_manager.verify_login_otp(email, otp_code)
        else:
            # Check if this is a signup attempt for an existing user
            if data.get('temp_user_id') and not user_manager.find_temp_id_by_email(email):
                logger.warning(f"⚠️ Signup attempt for existing user {email}")
                return jsonify(create_error_response('Account already exists. Please use login instead.')), 400
            logger.info(f"🔄 User does not exist, treating as signup")
            otp_type = 'signup'
            # For signup, we need temp_id - try to get from request or database
            temp_id = data.get('temp_user_id')
            logger.info(f"🔄 temp_id from request: {temp_id}")
            
            if not temp_id:
                # Try to find temp_id from database using email
                logger.info(f"🔄 No temp_id provided for {email}, searching database...")
                temp_id = user_manager.find_temp_id_by_email(email)
                logger.info(f"🔄 find_temp_id_by_email result: {temp_id}")
                
                if not temp_id:
                    logger.warning(f"⚠️ No temp_id found for signup verification of {email}")
                    return jsonify(create_error_response('Account already exists. Please use login instead.')), 400
                else:
                    logger.info(f"✅ Found temp_id {temp_id} for {email} in database")
            
            # Try to verify OTP with stored password from database
            success, message = user_manager.verify_signup_otp(temp_id, otp_code)
        
        if success:
            if otp_type == 'login':
                # Get user info and create session
                user = user_manager.get_user_by_email(email)
                if user:
                    session.clear()
                    session['user_id'] = user['user_id']
                    session['user_email'] = user['email']
                    session['authenticated'] = True
                    session['login_time'] = datetime.now().isoformat()
                    session['last_activity'] = datetime.now().isoformat()
                    session['session_id'] = secrets.token_urlsafe(32)
                    session.modified = True
                    session.permanent = True
                    
                    logger.info(f"✅ Database fallback login successful for {email}")
                    return jsonify(create_success_response('Login successful', url_for('index')))
                else:
                    return jsonify(create_error_response('User account not found')), 500
            else:
                # Signup successful
                logger.info(f"✅ Database fallback signup successful for {email}")
                return jsonify(create_success_response(
                    'Account created successfully! Please login.',
                    url_for('auth.login')
                ))
        else:
            logger.warning(f"🔒 Database fallback OTP verification failed for {email}")
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error in database fallback OTP verification: {str(e)}")
        return jsonify(create_error_response('An error occurred during verification. Please try again.')), 500

@auth_bp.route('/api/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP code with rate limiting and validation"""
    try:
        # Validate session
        is_valid, error_msg, session_data = validate_otp_session()
        if not is_valid:
            return jsonify(create_error_response(error_msg, url_for('auth.login'))), 400
        
        email = session_data['email']
        otp_type = session_data['otp_type']
        
        # Check rate limiting
        if 'otp_sent_at' in session:
            try:
                sent_time = datetime.fromisoformat(session['otp_sent_at'])
                time_since_last = datetime.now() - sent_time
                
                # Require at least 60 seconds between requests
                if time_since_last < timedelta(seconds=AuthConfig.RESEND_COOLDOWN_SECONDS):
                    remaining_seconds = AuthConfig.RESEND_COOLDOWN_SECONDS - int(time_since_last.total_seconds())
                    return jsonify(create_error_response(
                        f'Please wait {remaining_seconds} seconds before requesting a new code'
                    )), 429
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking resend timing: {e}")
        
        # Resend OTP based on type
        if otp_type == 'login':
            success, message = user_manager.send_login_otp(email)
        elif otp_type == 'signup':
            # For signup, we need to create a new temporary ID
            password = session_data.get('signup_password', '')
            if not password:
                return jsonify(create_error_response('Invalid signup session')), 400
                
            success, message, temp_id = user_manager.send_signup_otp(email)
            if success:
                # Update the temporary ID in the session
                session['temp_user_id'] = temp_id
        else:
            return jsonify(create_error_response('Invalid verification type')), 400
        
        if success:
            session['otp_sent_at'] = datetime.now().isoformat()
            
            client_info = get_client_info()
            logger.info(f"🔄 OTP resent to {email} from {client_info['ip_address']}")
            
            return jsonify(create_success_response('New verification code sent'))
        else:
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error resending OTP: {str(e)}")
        return jsonify(create_error_response('Failed to resend verification code')), 500

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout user with security logging"""
    user_email = session.get('user_email', 'Unknown')
    client_info = get_client_info()
    
    # Clear all session data
    session.clear()
    
    logger.info(f"👋 User {user_email} logged out from {client_info['ip_address']}")
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/check-auth')
def check_auth():
    """Check authentication status with session validation"""
    if ('user_id' in session and 
        session.get('authenticated') and 
        is_session_valid()):
        
        user = user_manager.get_user_by_id(session['user_id'])
        if user and user['is_active']:
            # Update last activity
            session['last_activity'] = datetime.now().isoformat()
            
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': user['user_id'],
                    'email': user['email'],
                    'verified': user['is_verified']
                }
            })
    
    return jsonify({'authenticated': False}), 401

@auth_bp.route('/api/user-info')
@login_required
def get_user_info():
    """Get current user information"""
    user = user_manager.get_user_by_id(session['user_id'])
    if user:
        return jsonify(create_success_response('User information retrieved', data={
            'user': {
                'id': user['user_id'],
                'email': user['email'],
                'verified': user['is_verified'],
                'created_at': user['created_at'],
                'last_login': user['last_login']
            }
        }))
    
    return jsonify(create_error_response('User not found')), 404

@auth_bp.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password with comprehensive validation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Input validation
        if not all([current_password, new_password, confirm_password]):
            return jsonify(create_error_response('All password fields are required')), 400
        
        if new_password != confirm_password:
            return jsonify(create_error_response('New passwords do not match')), 400
        
        # Change password
        success, message = user_manager.change_password(
            session['user_id'], current_password, new_password
        )
        
        if success:
            client_info = get_client_info()
            logger.info(f"🔑 Password changed for user {session.get('user_email')} from {client_info['ip_address']}")
            return jsonify(create_success_response(message))
        else:
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        return jsonify(create_error_response('An error occurred while changing password')), 500

@auth_bp.route('/api/verify-password', methods=['POST'])
def verify_password():
    """Verify user password and send OTP for login (legacy endpoint)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(create_error_response('Invalid request data')), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify(create_error_response('Email and password are required')), 400
        
        # Validate email format
        if not user_manager.validate_email(email):
            return jsonify(create_error_response('Invalid email format')), 400
        
        # Verify password
        success, message = user_manager.verify_password(email, password)
        
        if not success:
            client_info = get_client_info()
            logger.warning(f"🔒 Failed password verification for {email} from {client_info['ip_address']}: {message}")
            return jsonify(create_error_response(message)), 401
        
        # Password is correct, now send OTP
        current_email_in_session = session.get('otp_email')
        if current_email_in_session == email and 'otp_sent_at' in session:
            try:
                sent_time = datetime.fromisoformat(session['otp_sent_at'])
                if datetime.now() - sent_time < timedelta(seconds=AuthConfig.RESEND_COOLDOWN_SECONDS):
                    logger.info(f"🔄 Using existing OTP for {email}")
                    
                    session['otp_email'] = email
                    session['otp_type'] = 'login'
                    
                    return jsonify(create_success_response(
                        'Verification code sent to your email',
                        url_for('auth.verify_otp_page')
                    ))
            except (ValueError, TypeError) as e:
                logger.warning(f"Error checking OTP timestamp: {e}")
        
        # Send OTP
        success, message = user_manager.send_login_otp(email)
        
        if success:
            session['otp_email'] = email
            session['otp_type'] = 'login'
            session['otp_sent_at'] = datetime.now().isoformat()
            
            client_info = get_client_info()
            logger.info(f"🔐 Login OTP sent to {email} after password verification from {client_info['ip_address']}")
            
            return jsonify(create_success_response(
                'Verification code sent to your email',
                url_for('auth.verify_otp_page')
            ))
        else:
            return jsonify(create_error_response(message)), 400
            
    except Exception as e:
        logger.error(f"Error during password verification: {str(e)}")
        return jsonify(create_error_response('An error occurred. Please try again.')), 500

# Admin and utility routes
@auth_bp.route('/admin/stats')
@login_required
def admin_stats():
    """Get user statistics (enhanced with security checks)"""
    # FIXED: Add basic admin check (you can enhance this)
    user = user_manager.get_user_by_id(session['user_id'])
    if not user:
        return jsonify(create_error_response('User not found')), 404
    
    # In a real app, you'd check for admin role here
    # if not user.get('is_admin', False):
    #     return jsonify(create_error_response('Insufficient permissions')), 403
    
    stats = user_manager.get_user_stats()
    cleanup_stats = user_manager.cleanup_expired_data()
    
    return jsonify(create_success_response('Statistics retrieved', data={
        'stats': stats,
        'cleanup': cleanup_stats,
        'generated_at': datetime.now().isoformat()
    }))

@auth_bp.route('/admin/init-db')
def init_database():
    """Initialize database (development only - should be secured in production)"""
    try:
        # FIXED: Add security check for production
        if not request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
            return jsonify(create_error_response('Access denied')), 403
        
        db_init = DatabaseInitializer()
        success = db_init.initialize_database()
        
        if success:
            return jsonify(create_success_response('Database initialized successfully'))
        else:
            return jsonify(create_error_response('Database initialization failed')), 500
            
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return jsonify(create_error_response(f'Database initialization error: {str(e)}')), 500

# Enhanced error handlers
@auth_bp.errorhandler(400)
def bad_request(error):
    """Handle bad request errors"""
    if request.is_json:
        return jsonify(create_error_response('Bad request')), 400
    return render_template('auth/400.html'), 400

@auth_bp.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized errors"""
    if request.is_json:
        return jsonify(create_error_response('Unauthorized', url_for('auth.login'))), 401
    return redirect(url_for('auth.login'))

@auth_bp.errorhandler(403)
def forbidden(error):
    """Handle forbidden errors"""
    if request.is_json:
        return jsonify(create_error_response('Access forbidden')), 403
    return render_template('auth/403.html'), 403

@auth_bp.errorhandler(404)
def auth_not_found(error):
    """Handle not found errors"""
    if request.is_json:
        return jsonify(create_error_response('Resource not found')), 404
    return render_template('auth/404.html'), 404

@auth_bp.errorhandler(429)
def rate_limited(error):
    """Handle rate limiting errors"""
    if request.is_json:
        return jsonify(create_error_response('Too many requests. Please try again later.')), 429
    return render_template('auth/429.html'), 429

@auth_bp.errorhandler(500)
def auth_server_error(error):
    """Handle internal server errors"""
    logger.error(f"Internal server error in auth: {error}")
    if request.is_json:
        return jsonify(create_error_response('Internal server error')), 500
    return render_template('auth/500.html'), 500

# Test and info routes
@auth_bp.route('/test')
def test_auth():
    """Test authentication system (development only)"""
    return jsonify({
        'message': 'SANA Toolkit Authentication System',
        'status': 'running',
        'version': '2.0',
        'endpoints': {
            'login': url_for('auth.login'),
            'signup': url_for('auth.signup'),
            'logout': url_for('auth.logout'),
            'verify_otp': url_for('auth.verify_otp_page')
        },
        'config': {
            'otp_expiry_minutes': AuthConfig.OTP_EXPIRY_MINUTES,
            'session_timeout_hours': AuthConfig.SESSION_TIMEOUT_HOURS,
            'resend_cooldown_seconds': AuthConfig.RESEND_COOLDOWN_SECONDS
        }
    })

@auth_bp.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        stats = user_manager.get_user_stats()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'user_count': stats.get('total_users', 0)
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': 'Database connection failed'
        }), 500

@auth_bp.route('/session-debug')
def session_debug():
    """Debug endpoint to check session status"""
    client_info = get_client_info()
    
    debug_info = {
        'session_id': session.get('_id', 'No session ID'),
        'session_keys': list(session.keys()),
        'otp_email': session.get('otp_email'),
        'otp_type': session.get('otp_type'),
        'otp_sent_at': session.get('otp_sent_at'),
        'user_id': session.get('user_id'),
        'authenticated': session.get('authenticated'),
        'client_ip': client_info['ip_address'],
        'user_agent': client_info['user_agent'],
        'session_modified': session.modified,
        'session_permanent': session.permanent,
        'session_created': session.get('session_created')
    }
    
    logger.info(f"Session debug info for {client_info['ip_address']}: {debug_info}")
    return jsonify(debug_info)

@auth_bp.route('/test-session', methods=['POST'])
def test_session():
    """Test endpoint to set and retrieve session data"""
    try:
        data = request.get_json()
        test_key = data.get('test_key', 'test_value')
        test_email = data.get('test_email', 'test@example.com')
        
        # Set test session data
        session['test_key'] = test_key
        session['test_email'] = test_email
        session['test_timestamp'] = datetime.now().isoformat()
        session['otp_email'] = test_email  # Simulate OTP email
        session['otp_type'] = 'login'  # Simulate OTP type
        
        # Force session to be modified and permanent
        session.modified = True
        session.permanent = True
        
        logger.info(f"✅ Test session data set: {list(session.keys())}")
        logger.info(f"✅ Session modified: {session.modified}")
        logger.info(f"✅ Session permanent: {session.permanent}")
        
        return jsonify({
            'status': 'success',
            'message': 'Test session data set',
            'session_keys': list(session.keys()),
            'session_modified': session.modified,
            'session_permanent': session.permanent,
            'test_data': {
                'test_key': session.get('test_key'),
                'test_email': session.get('test_email'),
                'test_timestamp': session.get('test_timestamp'),
                'otp_email': session.get('otp_email'),
                'otp_type': session.get('otp_type')
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Test session error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@auth_bp.route('/test-session-get')
def test_session_get():
    """Test endpoint to retrieve session data"""
    try:
        logger.info(f"🔍 Testing session retrieval: {list(session.keys())}")
        
        return jsonify({
            'status': 'success',
            'session_keys': list(session.keys()),
            'session_modified': session.modified,
            'session_permanent': session.permanent,
            'test_data': {
                'test_key': session.get('test_key'),
                'test_email': session.get('test_email'),
                'test_timestamp': session.get('test_timestamp'),
                'otp_email': session.get('otp_email'),
                'otp_type': session.get('otp_type')
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Test session get error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Initialize database on first import with error handling
try:
    db_init = DatabaseInitializer()
    if not db_init.initialize_database():
        logger.warning("⚠️  Database initialization failed on startup")
    else:
        logger.info("✅ Database initialized successfully on startup")
except Exception as e:
    logger.error(f"❌ Error during database initialization: {str(e)}")