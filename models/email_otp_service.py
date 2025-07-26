import smtplib
import random
import string
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import sqlite3
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmailOTPService:
    def __init__(self, db_path='data/sana_toolkit.db'):
        self.db_path = db_path
        
        # FIXED: Use environment variables for security
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME', 'hamzacerts@gmail.com')
        self.smtp_password = os.getenv('SMTP_PASSWORD', 'vpke ouyl wqmd gbdz')
        self.sender_email = os.getenv('SENDER_EMAIL', 'hamzacerts@gmail.com')
        self.sender_name = os.getenv('SENDER_NAME', 'SANA Toolkit')
        
        # Rate limiting
        self.rate_limit_seconds = 60  # Increased to 60 seconds
        
        # Email validation pattern
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def generate_otp(self):
        """Generate a random 6-digit OTP"""
        return ''.join(random.choices(string.digits, k=6))
    
    def validate_email(self, email):
        """Validate email format"""
        return bool(self.email_pattern.match(email.strip().lower()))
    
    def create_connection(self):
        """Create database connection with proper error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            return None
    
    def save_otp_to_db(self, user_id, otp_code, otp_type='login'):
        """Save OTP to database with improved transaction handling"""
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            with conn:  # FIXED: Use context manager for transaction handling
                cursor = conn.cursor()
                
                # Check for recent OTPs first to avoid duplicates
                cursor.execute('''
                    SELECT otp_id, created_at FROM user_otp 
                    WHERE user_id = ? AND otp_type = ? AND is_used = FALSE AND expires_at > ?
                    ORDER BY created_at DESC LIMIT 1
                ''', (user_id, otp_type, datetime.now()))
                
                recent_otp = cursor.fetchone()
                
                if recent_otp and recent_otp['created_at']:
                    otp_time = datetime.fromisoformat(recent_otp['created_at'])
                    if datetime.now() - otp_time < timedelta(seconds=self.rate_limit_seconds):
                        logger.info(f"Rate limited: Recent OTP exists for user {user_id}, type {otp_type}")
                        return True
                
                # Clean up expired and old OTPs
                cursor.execute('''
                    DELETE FROM user_otp 
                    WHERE (user_id = ? AND otp_type = ? AND is_used = FALSE) 
                    OR expires_at < datetime('now')
                ''', (user_id, otp_type))
                
                # Create new OTP
                expires_at = datetime.now() + timedelta(minutes=10)
                cursor.execute('''
                    INSERT INTO user_otp (user_id, otp_code, otp_type, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, otp_code, otp_type, expires_at, datetime.now()))
                
                logger.info(f"OTP saved for user {user_id}, type {otp_type}")
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Database error saving OTP: {e}")
            return False
        finally:
            conn.close()
    
    def send_otp_email(self, to_email, otp_code, purpose='login'):
        """Send OTP via email with validation and improved error handling"""
        # FIXED: Validate email before sending
        if not self.validate_email(to_email):
            logger.error(f"Invalid email format: {to_email}")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = f"{self.sender_name} <{self.sender_email}>"
            msg['To'] = to_email
            
            # Generate template based on purpose
            if purpose == 'signup':
                msg['Subject'] = "🛡️ SANA Toolkit - Verify Your Account"
                html_body = self.get_signup_template(otp_code, to_email)
            else:  # login
                msg['Subject'] = "🔐 SANA Toolkit - Login Verification"
                html_body = self.get_login_template(otp_code, to_email)
            
            msg.attach(MIMEText(html_body, 'html'))
            
            # Connect and send with timeout
            logger.info(f"Connecting to SMTP server {self.smtp_server}:{self.smtp_port}")
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"SUCCESS: {purpose.title()} email sent to {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP Authentication failed - check credentials")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending {purpose} email: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending {purpose} email: {str(e)}")
            return False

    def get_signup_template(self, otp_code, email):
        """Professional signup verification email template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Welcome to SANA Toolkit</title>
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f6f9fc;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center; color: white;">
                    <h1 style="margin: 0; font-size: 28px; font-weight: 700;">🛡️ SANA Toolkit</h1>
                    <p style="margin: 8px 0 0; opacity: 0.9;">Cybersecurity Assessment Platform</p>
                </div>
                
                <!-- Content -->
                <div style="padding: 40px 30px;">
                    <h2 style="color: #2d3748; margin: 0 0 16px; font-size: 24px; text-align: center;">Welcome to SANA Toolkit!</h2>
                    <p style="color: #718096; font-size: 16px; line-height: 1.6; text-align: center; margin-bottom: 32px;">
                        Thank you for joining our cybersecurity platform. Please verify your email address using the code below to complete your registration.
                    </p>
                    
                    <!-- OTP Code -->
                    <div style="background: #f7fafc; border: 2px dashed #e2e8f0; border-radius: 8px; padding: 32px; text-align: center; margin: 32px 0;">
                        <div style="color: #4a5568; font-size: 14px; font-weight: 600; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px;">
                            Verification Code
                        </div>
                        <div style="background: #667eea; color: white; font-size: 32px; font-weight: 700; letter-spacing: 6px; padding: 16px 32px; border-radius: 6px; display: inline-block; font-family: 'Monaco', monospace;">
                            {otp_code}
                        </div>
                        <div style="color: #a0aec0; font-size: 14px; margin-top: 16px;">
                            ⏰ Expires in 10 minutes
                        </div>
                    </div>
                    
                    <p style="color: #718096; font-size: 16px; line-height: 1.5; text-align: center;">
                        Enter this code on the verification page to activate your account and start using SANA Toolkit's powerful cybersecurity features.
                    </p>
                </div>
                
                <!-- Footer -->
                <div style="background: #f7fafc; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                    <p style="color: #a0aec0; font-size: 14px; margin: 0;">
                        If you didn't create an account with SANA Toolkit, please ignore this email.<br>
                        © 2024 SANA Toolkit - Professional Cybersecurity Solutions
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

    def get_login_template(self, otp_code, email):
        """Professional login verification email template"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>SANA Toolkit Security Alert</title>
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f6f9fc;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%); padding: 40px 20px; text-align: center; color: white;">
                    <h1 style="margin: 0; font-size: 28px; font-weight: 700;">🛡️ SANA Toolkit</h1>
                    <p style="margin: 8px 0 0; opacity: 0.9;">Security Verification Required</p>
                </div>
                
                <!-- Content -->
                <div style="padding: 40px 30px;">
                    <div style="background: #fed7d7; color: #c53030; padding: 16px; border-radius: 8px; text-align: center; margin-bottom: 24px;">
                        <h3 style="margin: 0 0 8px; font-size: 18px;">🔐 Login Attempt Detected</h3>
                        <p style="margin: 0; font-size: 14px;">Someone attempted to access your SANA Toolkit account</p>
                    </div>
                    
                    <!-- Login Details -->
                    <div style="background: #f7fafc; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4299e1;">
                        <h4 style="color: #4299e1; margin: 0 0 12px; font-size: 16px;">📋 Login Details</h4>
                        <div style="font-size: 14px; line-height: 1.6;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                <span style="color: #718096;">Account:</span>
                                <span style="color: #2d3748; font-weight: 500;">{email}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                <span style="color: #718096;">Time:</span>
                                <span style="color: #2d3748; font-weight: 500;">{datetime.now().strftime("%B %d, %Y at %I:%M %p")}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between;">
                                <span style="color: #718096;">Platform:</span>
                                <span style="color: #2d3748; font-weight: 500;">SANA Toolkit Web Portal</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- OTP Code -->
                    <div style="background: #f0fff4; border: 2px solid #68d391; border-radius: 8px; padding: 32px; text-align: center; margin: 32px 0;">
                        <div style="color: #2f855a; font-size: 14px; font-weight: 600; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px;">
                            Security Verification Code
                        </div>
                        <div style="background: #38a169; color: white; font-size: 32px; font-weight: 700; letter-spacing: 6px; padding: 16px 32px; border-radius: 6px; display: inline-block; font-family: 'Monaco', monospace;">
                            {otp_code}
                        </div>
                        <div style="color: #2f855a; font-size: 14px; margin-top: 16px;">
                            ⏰ Valid for 10 minutes only
                        </div>
                    </div>
                    
                    <div style="background: #fffbeb; border: 1px solid #f6e05e; border-radius: 8px; padding: 16px; margin: 20px 0;">
                        <p style="color: #744210; font-size: 14px; margin: 0; text-align: center;">
                            <strong>⚠️ Security Reminder:</strong> If you didn't attempt to log in, please secure your account immediately.
                        </p>
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="background: #f7fafc; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
                    <p style="color: #a0aec0; font-size: 14px; margin: 0;">
                        This is an automated security notification - Do not reply<br>
                        © 2024 SANA Toolkit Security Operations Center
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def verify_otp(self, user_id, otp_code, otp_type='login'):
        """Verify OTP code with improved error handling"""
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            with conn:  # FIXED: Use context manager
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT otp_id FROM user_otp 
                    WHERE user_id = ? AND otp_code = ? AND otp_type = ? 
                    AND is_used = FALSE AND expires_at > ?
                ''', (user_id, otp_code, otp_type, datetime.now()))
                
                result = cursor.fetchone()
                
                if result:
                    # Mark OTP as used
                    cursor.execute('UPDATE user_otp SET is_used = TRUE WHERE otp_id = ?', (result['otp_id'],))
                    logger.info(f"OTP verified successfully for user {user_id}, type {otp_type}")
                    return True
                else:
                    logger.warning(f"OTP verification failed for user {user_id}, type {otp_type}")
                    return False
                    
        except sqlite3.Error as e:
            logger.error(f"Database error verifying OTP: {e}")
            return False
        finally:
            conn.close()
            
    def cleanup_expired_otps(self):
        """Clean up expired OTPs from database"""
        conn = self.create_connection()
        if not conn:
            return 0
            
        try:
            with conn:  # FIXED: Use context manager
                cursor = conn.cursor()
                cursor.execute("DELETE FROM user_otp WHERE expires_at < datetime('now')")
                deleted_count = cursor.rowcount
                logger.info(f"Cleaned up {deleted_count} expired OTPs")
                return deleted_count
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up expired OTPs: {e}")
            return 0
        finally:
            conn.close()

# Test function
def test_email_service():
    """Test the email service"""
    print("🛡️  Testing SANA Email OTP Service")
    print("=" * 40)
    
    service = EmailOTPService()
    
    # Generate test OTP
    test_otp = service.generate_otp()
    print(f"Generated OTP: {test_otp}")
    
    # Test email validation
    test_emails = ["test@example.com", "invalid-email", "user@domain.co.uk"]
    for email in test_emails:
        is_valid = service.validate_email(email)
        print(f"Email {email}: {'✅ Valid' if is_valid else '❌ Invalid'}")

if __name__ == "__main__":
    test_email_service()