import sqlite3
import hashlib
import secrets
import re
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import time
from typing import Tuple, Optional, Dict, Any
import os

# Import your EmailOTPService
try:
    from .email_otp_service import EmailOTPService
except ImportError:
    # Fallback for testing
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from email_otp_service import EmailOTPService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserManager:
    def __init__(self, db_path='data/sana_toolkit.db'):
        # FIXED: Enhanced path handling for production environments
        if os.environ.get('RENDER') == 'true' or os.environ.get('FLASK_ENV') == 'production':
            # For production, ensure we use absolute paths
            if not os.path.isabs(db_path):
                # Use current working directory for production
                self.db_path = os.path.join(os.getcwd(), db_path)
            logger.info(f"🌐 Production environment detected - UserManager using database path: {self.db_path}")
        else:
            # For development, use relative path
            self.db_path = db_path
            logger.info(f"🔧 Development environment - UserManager using database path: {self.db_path}")
        
        self.otp_service = EmailOTPService(self.db_path)
        
        # FIXED: Compile regex patterns once for better performance
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        self.password_patterns = {
            'uppercase': re.compile(r'[A-Z]'),
            'lowercase': re.compile(r'[a-z]'),
            'digit': re.compile(r'\d'),
            'special': re.compile(r'[!@#$%^&*(),.?":{}|<>]')
        }
        
        # Configuration
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        self.otp_rate_limit_seconds = 60
        
    def create_connection(self) -> Optional[sqlite3.Connection]:
        """Create database connection with proper error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            return None
    
    def validate_email(self, email: str) -> bool:
        """Validate email format using compiled regex"""
        return bool(self.email_pattern.match(email.strip().lower()))
    
    def validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength with detailed feedback"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:  # FIXED: Add maximum length
            return False, "Password must be less than 128 characters"
        
        checks = [
            (self.password_patterns['uppercase'], "Password must contain at least one uppercase letter"),
            (self.password_patterns['lowercase'], "Password must contain at least one lowercase letter"),
            (self.password_patterns['digit'], "Password must contain at least one digit"),
            (self.password_patterns['special'], "Password must contain at least one special character")
        ]
        
        for pattern, error_msg in checks:
            if not pattern.search(password):
                return False, error_msg
        
        return True, "Password is valid"
    
    def user_exists(self, email: str) -> bool:
        """Check if user exists by email with proper error handling"""
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE email = ? LIMIT 1", (email.lower(),))
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error(f"Error checking if user exists: {e}")
            return False
        finally:
            conn.close()
    
    def create_user(self, email: str, password: str) -> Tuple[bool, str]:
        """Create a new user account with comprehensive validation"""
        email = email.lower().strip()
        
        # Input validation
        if not email:
            return False, "Email is required"
            
        if not password:
            return False, "Password is required"
        
        if not self.validate_email(email):
            return False, "Invalid email format"
        
        is_valid, message = self.validate_password(password)
        if not is_valid:
            return False, message
        
        if self.user_exists(email):
            return False, "User with this email already exists"
        
        # Create user
        conn = self.create_connection()
        if not conn:
            return False, "Database connection failed"
            
        try:
            with conn:  # FIXED: Use context manager for transaction
                cursor = conn.cursor()
                password_hash = generate_password_hash(password)
                
                cursor.execute("""
                    INSERT INTO users (email, password_hash, is_verified, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (email, password_hash, False, True, datetime.now()))
                
                user_id = cursor.lastrowid
                
                logger.info(f"✅ User created successfully: {email} (ID: {user_id})")
                return True, f"User created successfully with ID: {user_id}"
                
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                return False, "User with this email already exists"
            logger.error(f"Integrity error creating user: {e}")
            return False, "Failed to create user - data integrity error"
        except sqlite3.Error as e:
            logger.error(f"Database error creating user: {e}")
            return False, "Database error occurred"
        finally:
            conn.close()
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user information by email with proper error handling"""
        conn = self.create_connection()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, email, password_hash, is_verified, is_active, 
                       created_at, last_login, login_attempts, locked_until
                FROM users WHERE email = ? LIMIT 1
            """, (email.lower(),))
            
            user = cursor.fetchone()
            return dict(user) if user else None
            
        except sqlite3.Error as e:
            logger.error(f"Error getting user by email: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user information by ID with proper error handling"""
        conn = self.create_connection()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT user_id, email, is_verified, is_active, 
                       created_at, last_login, login_attempts, locked_until
                FROM users WHERE user_id = ? LIMIT 1
            """, (user_id,))
            
            user = cursor.fetchone()
            return dict(user) if user else None
            
        except sqlite3.Error as e:
            logger.error(f"Error getting user by ID: {e}")
            return None
        finally:
            conn.close()
    
    def is_account_locked(self, user: Dict[str, Any]) -> bool:
        """Check if account is currently locked"""
        if not user.get('locked_until'):
            return False
        
        try:
            locked_until = datetime.fromisoformat(user['locked_until'])
            return datetime.now() < locked_until
        except (ValueError, TypeError):
            return False
    
    def verify_password(self, email: str, password: str) -> Tuple[bool, str]:
        """Verify user password with account lockout protection"""
        user = self.get_user_by_email(email)
        if not user:
            return False, "User not found"
        
        if not user['is_active']:
            return False, "Account is deactivated"
        
        # Check if account is locked
        if self.is_account_locked(user):
            return False, f"Account is temporarily locked due to multiple failed login attempts"
        
        # Verify password
        if check_password_hash(user['password_hash'], password):
            # Reset login attempts on successful verification
            self.reset_login_attempts(user['user_id'])
            return True, "Password verified"
        else:
            # Increment login attempts
            self.increment_login_attempts(user['user_id'])
            return False, "Invalid password"
    
    def increment_login_attempts(self, user_id: int) -> None:
        """Increment failed login attempts with account lockout"""
        conn = self.create_connection()
        if not conn:
            return
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET login_attempts = login_attempts + 1,
                        locked_until = CASE 
                            WHEN login_attempts + 1 >= ? THEN datetime('now', '+{} minutes')
                            ELSE locked_until 
                        END
                    WHERE user_id = ?
                """.format(self.lockout_duration_minutes), (self.max_login_attempts, user_id))
                
                # Check new attempt count for logging
                cursor.execute("SELECT login_attempts FROM users WHERE user_id = ? LIMIT 1", (user_id,))
                result = cursor.fetchone()
                if result and result['login_attempts'] >= self.max_login_attempts:
                    logger.warning(f"🔒 User {user_id} account locked due to {self.max_login_attempts}+ failed attempts")
                
        except sqlite3.Error as e:
            logger.error(f"Error incrementing login attempts: {e}")
        finally:
            conn.close()
    
    def reset_login_attempts(self, user_id: int) -> None:
        """Reset failed login attempts"""
        conn = self.create_connection()
        if not conn:
            return
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET login_attempts = 0, locked_until = NULL 
                    WHERE user_id = ?
                """, (user_id,))
        except sqlite3.Error as e:
            logger.error(f"Error resetting login attempts: {e}")
        finally:
            conn.close()
    
    def update_last_login(self, user_id: int) -> None:
        """Update user's last login timestamp"""
        conn = self.create_connection()
        if not conn:
            return
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET last_login = ? WHERE user_id = ?
                """, (datetime.now(), user_id))
        except sqlite3.Error as e:
            logger.error(f"Error updating last login: {e}")
        finally:
            conn.close()
    
    def verify_user_email(self, user_id: int) -> bool:
        """Mark user email as verified"""
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users SET is_verified = TRUE WHERE user_id = ?
                """, (user_id,))
                logger.info(f"✅ User {user_id} email verified")
                return True
        except sqlite3.Error as e:
            logger.error(f"Error verifying user email: {e}")
            return False
        finally:
            conn.close()

    def send_login_otp(self, email: str) -> Tuple[bool, str]:
        """Send OTP for login with comprehensive validation"""
        user = self.get_user_by_email(email)
        if not user:
            return False, "User not found"
        
        if not user['is_active']:
            return False, "Account is deactivated"
        
        if not user['is_verified']:
            return False, "Please verify your email first"
        
        # Check if account is locked
        if self.is_account_locked(user):
            return False, "Account is temporarily locked"
        
        try:
            # FIXED: Use identifier column instead of user_id
            user_identifier = str(user['user_id'])  # Convert user_id to string for identifier
            
            # Check for recent OTP to prevent spam
            conn = self.create_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT created_at FROM user_otp 
                        WHERE identifier = ? AND otp_type = 'login' AND is_used = FALSE AND expires_at > ?
                        ORDER BY created_at DESC LIMIT 1
                    ''', (user_identifier, datetime.now()))
                    
                    recent_otp = cursor.fetchone()
                    if recent_otp:
                        otp_time = datetime.fromisoformat(recent_otp[0])  # created_at is first column
                        if datetime.now() - otp_time < timedelta(seconds=60):  # 1 minute cooldown
                            logger.info(f"🔄 Recent login OTP exists for {email}, not sending duplicate")
                            return True, "OTP sent successfully"
                finally:
                    conn.close()
            
            # Generate and send OTP
            otp_code = self.otp_service.generate_otp()
            
            # FIXED: Save OTP to database using identifier
            if not self.otp_service.save_otp_to_db(user_identifier, otp_code, 'login'):
                return False, "Failed to save OTP"
            
            # Send OTP email
            if not self.otp_service.send_otp_email(email, otp_code, 'login'):
                return False, "Failed to send OTP email"
            
            logger.info(f"📧 Login OTP sent to {email}")
            return True, "OTP sent successfully"
                
        except Exception as e:
            logger.error(f"Error sending login OTP: {e}")
            return False, "An error occurred while sending OTP"
    
    def send_signup_otp(self, email: str, password: str = None) -> Tuple[bool, str, Optional[str]]:
        """Send OTP for signup with password storage for session fallback and enhanced logging"""
        email = email.lower().strip()
        
        logger.info(f"🔍 Starting send_signup_otp for email: {email}")
        
        # Validate email
        if not self.validate_email(email):
            logger.warning(f"❌ Invalid email format: {email}")
            return False, "Invalid email format", None
            
        # Check if user already exists
        if self.user_exists(email):
            logger.warning(f"❌ User already exists: {email}")
            return False, "An account with this email already exists", None
        
        # FIXED: Enhanced database connection with better error handling
        logger.info(f"🔌 Creating database connection for {email}")
        conn = self.create_connection()
        if not conn:
            logger.error(f"❌ Database connection failed for {email}")
            return False, "Database connection failed", None
            
        try:
            cursor = conn.cursor()
            
            # Clean up any existing temporary registrations for this email
            logger.info(f"🧹 Cleaning up existing temp registrations for {email}")
            cursor.execute('DELETE FROM temp_registrations WHERE email = ?', (email,))
            deleted_count = cursor.rowcount
            logger.info(f"🧹 Deleted {deleted_count} existing temp registrations for {email}")
            
            # Generate temporary ID
            temp_id = f"temp_{int(time.time())}_{secrets.token_hex(4)}"
            logger.info(f"🆔 Generated temp_id: {temp_id} for {email}")
            
            # FIXED: Enhanced temp_registrations insertion with better error handling
            try:
                # Store temporary registration with password (if provided)
                if password:
                    logger.info(f"🔐 Storing temp registration with password for {email}")
                    # Hash the password temporarily for storage
                    temp_password_hash = generate_password_hash(password)
                    cursor.execute('''
                        INSERT INTO temp_registrations 
                        (temp_id, email, password_hash, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (temp_id, email, temp_password_hash, datetime.now(), 
                          datetime.now() + timedelta(minutes=20)))
                else:
                    logger.info(f"🔐 Storing temp registration without password for {email}")
                    cursor.execute('''
                        INSERT INTO temp_registrations 
                        (temp_id, email, created_at, expires_at)
                        VALUES (?, ?, ?, ?)
                    ''', (temp_id, email, datetime.now(), 
                          datetime.now() + timedelta(minutes=20)))
                
                # Commit the transaction immediately
                logger.info(f"💾 Committing temp_registrations insert for {email}")
                conn.commit()
                logger.info(f"✅ Temp registration committed successfully for {email}")
                
            except sqlite3.IntegrityError as e:
                logger.error(f"❌ Integrity error during temp_registrations insert for {email}: {e}")
                conn.rollback()
                return False, "Database integrity error during signup", None
            except sqlite3.Error as e:
                logger.error(f"❌ SQLite error during temp_registrations insert for {email}: {e}")
                conn.rollback()
                return False, "Database error during signup", None
            
            # FIXED: Enhanced verification with multiple checks
            logger.info(f"🔍 Verifying database insertion for temp_id: {temp_id}")
            
            # Check 1: Direct temp_id lookup
            cursor.execute('SELECT temp_id FROM temp_registrations WHERE temp_id = ?', (temp_id,))
            verification_result = cursor.fetchone()
            if verification_result:
                logger.info(f"✅ Database verification 1: temp_id {temp_id} found in temp_registrations")
            else:
                logger.error(f"❌ CRITICAL: Database verification 1 failed - temp_id {temp_id} not found after insert!")
                return False, "Database verification failed", None
            
            # Check 2: Email lookup
            cursor.execute('SELECT temp_id FROM temp_registrations WHERE email = ?', (email,))
            email_verification = cursor.fetchone()
            if email_verification:
                logger.info(f"✅ Database verification 2: email {email} found in temp_registrations")
            else:
                logger.error(f"❌ CRITICAL: Database verification 2 failed - email {email} not found after insert!")
                return False, "Database verification failed", None
            
            # Check 3: Count verification
            cursor.execute('SELECT COUNT(*) FROM temp_registrations WHERE email = ?', (email,))
            count_verification = cursor.fetchone()[0]
            if count_verification > 0:
                logger.info(f"✅ Database verification 3: {count_verification} temp_registrations found for {email}")
            else:
                logger.error(f"❌ CRITICAL: Database verification 3 failed - no temp_registrations found for {email}")
                return False, "Database verification failed", None
            
            # Close the connection before OTP operations
            conn.close()
            conn = None
            logger.info(f"🔌 Database connection closed for {email}")
            
            # Generate and save OTP
            logger.info(f"🔢 Generating OTP for {email}")
            otp_code = self.otp_service.generate_otp()
            logger.info(f"🔢 Generated OTP code: {otp_code} for {email}")
            
            if not self.otp_service.save_otp_to_db(temp_id, otp_code, 'signup'):
                logger.error(f"❌ Failed to save OTP to database for {email}")
                # Clean up on failure
                cleanup_conn = self.create_connection()
                if cleanup_conn:
                    try:
                        cleanup_conn.execute('DELETE FROM temp_registrations WHERE temp_id = ?', (temp_id,))
                        cleanup_conn.commit()
                        logger.info(f"🧹 Cleaned up temp_registration after OTP save failure for {email}")
                    finally:
                        cleanup_conn.close()
                return False, "Failed to save verification code", None
            
            logger.info(f"✅ OTP saved to database successfully for {email}")
            
            # Send OTP
            logger.info(f"📧 Sending OTP email to {email}")
            if self.otp_service.send_otp_email(email, otp_code, 'signup'):
                logger.info(f"✅ Signup OTP sent to {email} (temp_id: {temp_id})")
                return True, "Verification code sent successfully", temp_id
            else:
                logger.error(f"❌ Failed to send OTP email to {email}")
                # Clean up on failure
                cleanup_conn = self.create_connection()
                if cleanup_conn:
                    try:
                        cleanup_conn.execute('DELETE FROM temp_registrations WHERE temp_id = ?', (temp_id,))
                        cleanup_conn.commit()
                        logger.info(f"🧹 Cleaned up temp_registration after email send failure for {email}")
                    finally:
                        cleanup_conn.close()
                return False, "Failed to send verification code", None
                    
        except sqlite3.IntegrityError as e:
            logger.error(f"❌ Integrity error sending signup OTP for {email}: {e}")
            return False, "Database error during signup", None
        except sqlite3.Error as e:
            logger.error(f"❌ Database error sending signup OTP for {email}: {e}")
            return False, "Database error during signup", None
        except Exception as e:
            logger.error(f"❌ Unexpected error sending signup OTP for {email}: {e}")
            return False, "Unexpected error during signup", None
        finally:
            if conn:
                logger.info(f"🔌 Closing database connection in finally block for {email}")
                try:
                    conn.close()
                except Exception as e:
                    logger.error(f"❌ Error closing database connection: {e}")
    
    def verify_login_otp(self, email: str, otp_code: str) -> Tuple[bool, str]:
        """Verify OTP for login with comprehensive validation"""
        user = self.get_user_by_email(email)
        if not user:
            return False, "User not found"
        
        # FIXED: Use identifier instead of user_id for OTP verification
        user_identifier = str(user['user_id'])  # Convert user_id to string for identifier
        
        # Verify OTP using service
        if self.otp_service.verify_otp(user_identifier, otp_code, 'login'):
            # Update last login and reset failed attempts
            self.update_last_login(user['user_id'])
            self.reset_login_attempts(user['user_id'])  # FIXED: Reset on successful login
            logger.info(f"🔐 User {email} logged in successfully")
            return True, "Login successful"
        else:
            # Increment failed attempts for invalid OTP
            self.increment_login_attempts(user['user_id'])
            return False, "Invalid or expired OTP"
    
    def find_temp_id_by_email(self, email: str) -> Optional[str]:
        """Find temp_id for a given email from temp_registrations table with enhanced logging"""
        logger.info(f"🔍 Searching for temp_id by email: {email}")
        
        conn = self.create_connection()
        if not conn:
            logger.error(f"❌ Database connection failed in find_temp_id_by_email for {email}")
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT temp_id FROM temp_registrations WHERE email = ? LIMIT 1', (email,))
            result = cursor.fetchone()
            
            if result:
                temp_id = result['temp_id']
                logger.info(f"✅ Found temp_id: {temp_id} for email: {email}")
                return temp_id
            else:
                logger.warning(f"⚠️ No temp_id found for email: {email}")
                
                # Additional debugging: check if there are any temp registrations at all
                cursor.execute('SELECT COUNT(*) as count FROM temp_registrations')
                total_count = cursor.fetchone()['count']
                logger.info(f"📊 Total temp_registrations in database: {total_count}")
                
                # Check for any temp registrations with similar email
                cursor.execute('SELECT email, temp_id FROM temp_registrations WHERE email LIKE ? LIMIT 5', (f'%{email.split("@")[0]}%',))
                similar_results = cursor.fetchall()
                if similar_results:
                    logger.info(f"🔍 Found similar emails in temp_registrations: {[r['email'] for r in similar_results]}")
                
                return None
        except sqlite3.Error as e:
            logger.error(f"❌ Database error finding temp_id for {email}: {e}")
            return None
        finally:
            conn.close()
    
    def verify_signup_otp(self, temp_id: str, otp_code: str, new_password: str = None) -> Tuple[bool, str]:
        """Verify OTP for signup and create user account atomically"""
        logger.info(f"🔍 DEBUG: verify_signup_otp called with temp_id={temp_id}, otp_code={otp_code}, new_password={'provided' if new_password else 'None'}")
        
        conn = self.create_connection()
        if not conn:
            logger.error("❌ Database connection failed in verify_signup_otp")
            return False, "Database connection failed"
            
        try:
            with conn:  # FIXED: Use transaction for atomicity
                cursor = conn.cursor()
                
                # Get email and password associated with temp ID
                cursor.execute('SELECT email, password_hash FROM temp_registrations WHERE temp_id = ? LIMIT 1', (temp_id,))
                result = cursor.fetchone()
                if not result:
                    logger.error(f"❌ No temp_registration found for temp_id: {temp_id}")
                    return False, "Invalid verification session"
                    
                email = result['email']
                stored_password_hash = result['password_hash'] if result['password_hash'] else None
                logger.info(f"🔍 Found email: {email}, stored_password_hash: {'present' if stored_password_hash else 'None'}")
                
                # Double-check user doesn't exist (race condition protection)
                if self.user_exists(email):
                    logger.warning(f"⚠️ User already exists: {email}")
                    return False, "An account with this email already exists"
                
                # Verify the OTP
                logger.info(f"🔍 Verifying OTP: temp_id={temp_id}, otp_code={otp_code}")
                if not self.otp_service.verify_otp(temp_id, otp_code, 'signup'):
                    logger.warning(f"❌ OTP verification failed for temp_id={temp_id}, otp_code={otp_code}")
                    return False, "Invalid or expired verification code"
                
                logger.info(f"✅ OTP verified successfully for {email}")
                
                # Handle password - use provided password or stored password
                if new_password:
                    logger.info(f"🔍 Using provided password for {email}")
                    # Validate provided password
                    is_valid, message = self.validate_password(new_password)
                    if not is_valid:
                        logger.warning(f"❌ Password validation failed: {message}")
                        return False, message
                    password_hash = generate_password_hash(new_password)
                elif stored_password_hash:
                    logger.info(f"🔍 Using stored password hash for {email}")
                    # Use stored password from database
                    password_hash = stored_password_hash
                else:
                    logger.error(f"❌ No password available for {email}")
                    return False, "Password is required to complete registration"
                
                # Create the user account
                cursor.execute('''
                    INSERT INTO users (email, password_hash, is_verified, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email, password_hash, True, True, datetime.now()))
                
                user_id = cursor.lastrowid
                
                # Clean up temporary registration
                cursor.execute('DELETE FROM temp_registrations WHERE temp_id = ?', (temp_id,))
                
                logger.info(f"✅ User {email} signup completed successfully (ID: {user_id})")
                return True, "Account verified and activated"
                
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                return False, "An account with this email already exists"
            logger.error(f"Integrity error completing signup: {e}")
            return False, "Failed to create account - data integrity error"
        except sqlite3.Error as e:
            logger.error(f"Database error completing signup: {e}")
            return False, "Database error during verification"
        finally:
            conn.close()
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password with comprehensive validation"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False, "User not found"
        
        # Get full user with password hash
        full_user = self.get_user_by_email(user['email'])
        if not full_user:
            return False, "User not found"
        
        # Verify old password
        if not check_password_hash(full_user['password_hash'], old_password):
            return False, "Current password is incorrect"
        
        # Validate new password
        is_valid, message = self.validate_password(new_password)
        if not is_valid:
            return False, message
        
        # Don't allow same password
        if check_password_hash(full_user['password_hash'], new_password):
            return False, "New password must be different from current password"
        
        conn = self.create_connection()
        if not conn:
            return False, "Database connection failed"
            
        try:
            with conn:
                cursor = conn.cursor()
                password_hash = generate_password_hash(new_password)
                cursor.execute("""
                    UPDATE users SET password_hash = ? WHERE user_id = ?
                """, (password_hash, user_id))
                
                logger.info(f"✅ Password changed for user {user_id}")
                return True, "Password changed successfully"
        except sqlite3.Error as e:
            logger.error(f"Error changing password: {e}")
            return False, "Failed to change password"
        finally:
            conn.close()
    
    def get_user_stats(self) -> Dict[str, int]:
        """Get user statistics with proper error handling"""
        conn = self.create_connection()
        if not conn:
            return {}
            
        try:
            cursor = conn.cursor()
            
            # Use efficient aggregate queries
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_users,
                    SUM(CASE WHEN is_verified = 1 THEN 1 ELSE 0 END) as verified_users,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users,
                    SUM(CASE WHEN last_login > datetime('now', '-30 days') THEN 1 ELSE 0 END) as recent_users,
                    SUM(CASE WHEN locked_until > datetime('now') THEN 1 ELSE 0 END) as locked_users
                FROM users
            """)
            
            result = cursor.fetchone()
            if result:
                return {
                    'total_users': result['total_users'],
                    'verified_users': result['verified_users'],
                    'active_users': result['active_users'],
                    'recent_users': result['recent_users'],
                    'locked_users': result['locked_users'],
                    'pending_verification': result['total_users'] - result['verified_users']
                }
            
            return {}
                
        except sqlite3.Error as e:
            logger.error(f"Error getting user stats: {e}")
            return {}
        finally:
            conn.close()

    def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up expired OTPs and temporary registrations"""
        conn = self.create_connection()
        if not conn:
            return {}
            
        try:
            with conn:
                cursor = conn.cursor()
                
                # Clean expired OTPs
                cursor.execute("DELETE FROM user_otp WHERE expires_at < datetime('now')")
                expired_otps = cursor.rowcount
                
                # Clean old temp registrations (older than 1 hour)
                cursor.execute("DELETE FROM temp_registrations WHERE created_at < datetime('now', '-1 hour')")
                expired_temps = cursor.rowcount
                
                if expired_otps > 0 or expired_temps > 0:
                    logger.info(f"🧹 Cleaned up {expired_otps} expired OTPs and {expired_temps} old temp registrations")
                
                return {
                    'expired_otps': expired_otps,
                    'expired_temp_registrations': expired_temps
                }
                
        except sqlite3.Error as e:
            logger.error(f"Error during cleanup: {e}")
            return {}
        finally:
            conn.close()
    
    def check_database_schema(self) -> Dict[str, Any]:
        """Check database schema and table structure for debugging"""
        schema_info = {
            'temp_registrations_exists': False,
            'temp_registrations_columns': [],
            'temp_registrations_count': 0,
            'database_path': self.db_path
        }
        
        conn = self.create_connection()
        if not conn:
            logger.error("❌ Cannot check schema - database connection failed")
            return schema_info
            
        try:
            cursor = conn.cursor()
            
            # Check if temp_registrations table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='temp_registrations'
            """)
            table_exists = cursor.fetchone() is not None
            schema_info['temp_registrations_exists'] = table_exists
            
            if table_exists:
                # Get table schema
                cursor.execute("PRAGMA table_info(temp_registrations)")
                columns = cursor.fetchall()
                schema_info['temp_registrations_columns'] = [col['name'] for col in columns]
                
                # Get row count
                cursor.execute("SELECT COUNT(*) as count FROM temp_registrations")
                count_result = cursor.fetchone()
                schema_info['temp_registrations_count'] = count_result['count'] if count_result else 0
                
                logger.info(f"✅ temp_registrations table exists with {schema_info['temp_registrations_count']} rows")
                logger.info(f"📋 Columns: {schema_info['temp_registrations_columns']}")
            else:
                logger.error("❌ temp_registrations table does not exist!")
                
        except sqlite3.Error as e:
            logger.error(f"❌ Error checking database schema: {e}")
        finally:
            conn.close()
            
        return schema_info

# Test function
def test_user_manager():
    """Comprehensive test of the UserManager class"""
    print("🛡️  Testing SANA User Manager")
    print("=" * 40)
    
    user_mgr = UserManager()
    
    # Test email validation
    test_emails = ["test@example.com", "invalid-email", "user@domain.co.uk"]
    print("\n1. Email validation tests:")
    for email in test_emails:
        is_valid = user_mgr.validate_email(email)
        print(f"  {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    # Test password validation
    test_passwords = ["weak", "StrongPass123!", "NoSpecial123", "short"]
    print("\n2. Password validation tests:")
    for password in test_passwords:
        is_valid, message = user_mgr.validate_password(password)
        print(f"  {password}: {'✅' if is_valid else '❌'} {message}")
    
    # Test user creation
    test_email = "test@example.com"
    test_password = "TestPass123!"
    print(f"\n3. Creating user: {test_email}")
    success, message = user_mgr.create_user(test_email, test_password)
    print(f"Result: {message}")
    
    if success:
        print(f"\n4. Getting user info...")
        user = user_mgr.get_user_by_email(test_email)
        if user:
            print(f"User ID: {user['user_id']}")
            print(f"Email: {user['email']}")
            print(f"Verified: {user['is_verified']}")
    
    print(f"\n5. User statistics:")
    stats = user_mgr.get_user_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print(f"\n6. Cleanup results:")
    cleanup_results = user_mgr.cleanup_expired_data()
    for key, value in cleanup_results.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    test_user_manager()