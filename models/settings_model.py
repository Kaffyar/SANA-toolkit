"""
SANA Toolkit - Settings Management Model
Handles user preferences and settings using the existing key-value pair structure
"""

import sqlite3
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from models.user_model import UserManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SettingsManager:
    def __init__(self, db_path='data/sana_toolkit.db'):
        self.db_path = db_path
        self.default_settings = {
            'theme': 'dark',
            'scan_timeout': 60,
            'virustotal_api_key': '',
            'history_cleanup_days': 90,
            'notifications_enabled': True,
            'auto_save_results': True,
            'scan_verbosity': 'normal'
        }
        self.user_manager = UserManager(db_path)
    
    def create_connection(self):
        """Create a database connection"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            return None
    
    def get_user_settings(self, user_id):
        """Get user settings from the key-value pair table"""
        conn = self.create_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Get existing settings
            cursor.execute("""
                SELECT setting_key, setting_value 
                FROM user_settings 
                WHERE user_id = ?
            """, (user_id,))
            
            existing_settings = dict(cursor.fetchall())
            
            # Merge with defaults for missing settings
            settings = self.default_settings.copy()
            for key, value in existing_settings.items():
                if key in settings:
                    # Convert string values back to appropriate types
                    if key in ['scan_timeout', 'history_cleanup_days']:
                        try:
                            settings[key] = int(value)
                        except ValueError:
                            settings[key] = self.default_settings[key]
                    elif key in ['notifications_enabled', 'auto_save_results']:
                        settings[key] = value.lower() == 'true'
                    else:
                        settings[key] = value
            
            return settings
            
        except sqlite3.Error as e:
            logger.error(f"Error getting user settings: {e}")
            return None
        finally:
            conn.close()
    
    def update_user_settings(self, user_id, settings):
        """Update user settings in the key-value pair table"""
        if not self.validate_settings(settings):
            return False
        
        conn = self.create_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Update each setting
            for key, value in settings.items():
                if key in self.default_settings:
                    # Convert value to string for storage
                    str_value = str(value)
                    
                    # Check if setting exists
                    cursor.execute("""
                        SELECT setting_id FROM user_settings 
                        WHERE user_id = ? AND setting_key = ?
                    """, (user_id, key))
                    
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Update existing setting
                        cursor.execute("""
                            UPDATE user_settings 
                            SET setting_value = ?, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ? AND setting_key = ?
                        """, (str_value, user_id, key))
                    else:
                        # Insert new setting
                        cursor.execute("""
                            INSERT INTO user_settings (user_id, setting_key, setting_value, created_at, updated_at)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (user_id, key, str_value))
            
            conn.commit()
            logger.info(f"✅ User settings updated for user {user_id}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error updating user settings: {e}")
            return False
        finally:
            conn.close()
    
    def validate_settings(self, settings):
        """Validate settings values"""
        try:
            if 'theme' in settings and settings['theme'] not in ['dark', 'light', 'auto']:
                return False
            
            if 'scan_timeout' in settings:
                timeout = int(settings['scan_timeout'])
                if timeout < 30 or timeout > 3600:
                    return False
            
            if 'history_cleanup_days' in settings:
                days = int(settings['history_cleanup_days'])
                if days < 0:
                    return False
            
            if 'scan_verbosity' in settings and settings['scan_verbosity'] not in ['minimal', 'normal', 'verbose']:
                return False
            
            return True
        except (ValueError, TypeError):
            return False
    
    def reset_user_settings(self, user_id):
        """Reset user settings to defaults"""
        conn = self.create_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Delete existing settings
            cursor.execute("DELETE FROM user_settings WHERE user_id = ?", (user_id,))
            
            # Insert default settings
            for key, value in self.default_settings.items():
                cursor.execute("""
                    INSERT INTO user_settings (user_id, setting_key, setting_value, created_at, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (user_id, key, str(value)))
            
            conn.commit()
            logger.info(f"✅ User settings reset for user {user_id}")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error resetting user settings: {e}")
            return False
        finally:
            conn.close()
    
    def change_user_email(self, user_id, new_email):
        """Change user's email address"""
        return self.user_manager.update_user_email(user_id, new_email)
    
    def change_user_password(self, user_id, current_password, new_password):
        """Change user's password"""
        return self.user_manager.change_password(user_id, current_password, new_password)
    
    def get_user_stats(self, user_id):
        """Get user's scan statistics"""
        conn = self.create_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            
            # Get total scans
            cursor.execute("""
                SELECT COUNT(*) as total_scans,
                       COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans,
                       COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans,
                       MAX(timestamp) as last_scan_date
                FROM scan_history 
                WHERE user_id = ?
            """, (user_id,))
            
            result = cursor.fetchone()
            if result:
                return {
                    'total_scans': result['total_scans'],
                    'completed_scans': result['completed_scans'],
                    'failed_scans': result['failed_scans'],
                    'last_scan_date': result['last_scan_date']
                }
            
            return {
                'total_scans': 0,
                'completed_scans': 0,
                'failed_scans': 0,
                'last_scan_date': None
            }
            
        except sqlite3.Error as e:
            logger.error(f"Error getting user stats: {e}")
            return None
        finally:
            conn.close()
    
    def cleanup_old_scan_history(self, user_id, force_days=None):
        """Clean up old scan history based on user's settings or force cleanup"""
        settings = self.get_user_settings(user_id)
        
        # Use force_days if provided, otherwise use user settings
        cleanup_days = force_days if force_days is not None else settings.get('history_cleanup_days', 90)
        
        if cleanup_days <= 0:
            return False, "History cleanup is disabled (set to 0 days)", 0
        
        conn = self.create_connection()
        if not conn:
            return False, "Database connection failed", 0
        
        try:
            cursor = conn.cursor()
            
            # First, check how many scans would be deleted
            cursor.execute("""
                SELECT COUNT(*) FROM scan_history 
                WHERE user_id = ? 
                AND timestamp < datetime('now', '-{} days')
            """.format(cleanup_days), (user_id,))
            
            old_scans_count = cursor.fetchone()[0]
            
            if old_scans_count == 0:
                # Check total scans for this user
                cursor.execute("SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,))
                total_scans = cursor.fetchone()[0]
                
                if total_scans == 0:
                    return True, "No scan records found for this user", 0
                else:
                    # Get the oldest scan date
                    cursor.execute("SELECT MIN(timestamp) FROM scan_history WHERE user_id = ?", (user_id,))
                    oldest_scan = cursor.fetchone()[0]
                    return True, f"No scans older than {cleanup_days} days found. Oldest scan is from {oldest_scan}", 0
            
            # Delete old scans
            cursor.execute("""
                DELETE FROM scan_history 
                WHERE user_id = ? 
                AND timestamp < datetime('now', '-{} days')
            """.format(cleanup_days), (user_id,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                logger.info(f"✅ Cleaned up {deleted_count} old scans for user {user_id}")
                return True, f"Successfully cleaned up {deleted_count} scan records older than {cleanup_days} days", deleted_count
            else:
                return True, "No old scan records found to clean up", 0
            
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up scan history: {e}")
            return False, f"Database error: {str(e)}", 0
        finally:
            conn.close()

# Create global instance
settings_manager = SettingsManager() 