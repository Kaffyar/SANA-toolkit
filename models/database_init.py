"""
SANA Toolkit - Enhanced Database Initialization
Added comprehensive scan history tracking for all scan types
"""

import sqlite3
import os
import time
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseInitializer:
    def __init__(self, db_path='data/sana_toolkit.db'):
        self.db_path = db_path
        # FIXED: Enhanced path handling for production environments
        if os.environ.get('RENDER') == 'true' or os.environ.get('FLASK_ENV') == 'production':
            # For production, ensure we use absolute paths
            if not os.path.isabs(db_path):
                # Use current working directory for production
                self.db_path = os.path.join(os.getcwd(), db_path)
            logger.info(f"🌐 Production environment detected - using database path: {self.db_path}")
        else:
            # For development, use relative path
            logger.info(f"🔧 Development environment - using database path: {self.db_path}")
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        logger.info(f"📁 Ensured data directory exists: {os.path.dirname(self.db_path)}")
        
    def create_connection(self):
        """Create a database connection with proper error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")  # Better concurrency
            return conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            return None
    
    def create_users_table(self):
        """Create the users table with enhanced constraints"""
        create_users_sql = """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE NOT NULL,
            is_active BOOLEAN DEFAULT TRUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            last_login DATETIME,
            login_attempts INTEGER DEFAULT 0 NOT NULL CHECK (login_attempts >= 0),
            locked_until DATETIME,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            CONSTRAINT chk_email_format CHECK (email LIKE '%@%.%'),
            CONSTRAINT chk_password_length CHECK (length(password_hash) > 0)
        );
        """
        
        # Trigger to update updated_at timestamp
        update_trigger_sql = """
        CREATE TRIGGER IF NOT EXISTS users_updated_at 
        AFTER UPDATE ON users
        BEGIN
            UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id;
        END;
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:  # Use context manager for transaction
                    cursor = conn.cursor()
                    cursor.execute(create_users_sql)
                    cursor.execute(update_trigger_sql)
                logger.info("✅ Users table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating users table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def create_user_otp_table(self):
        """Create the user_otp table with enhanced constraints"""
        create_otp_sql = """
        CREATE TABLE IF NOT EXISTS user_otp (
            otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL,  -- Can be user_id OR temp_id
            otp_code TEXT NOT NULL CHECK (length(otp_code) = 6),
            otp_type TEXT DEFAULT 'login' NOT NULL CHECK (otp_type IN ('login', 'signup')),
            is_used BOOLEAN DEFAULT FALSE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            used_at DATETIME,
            
            CONSTRAINT chk_expires_future CHECK (expires_at > created_at),
            CONSTRAINT chk_otp_numeric CHECK (otp_code GLOB '[0-9][0-9][0-9][0-9][0-9][0-9]')
        );
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(create_otp_sql)
                    
                    # Migration: Handle existing databases with user_id column
                    try:
                        # Check if user_id column exists (old schema)
                        cursor.execute("PRAGMA table_info(user_otp)")
                        columns = [col[1] for col in cursor.fetchall()]
                        
                        if 'user_id' in columns and 'identifier' not in columns:
                            # Migrate from user_id to identifier
                            logger.info("🔄 Migrating user_otp table from user_id to identifier column")
                            cursor.execute("ALTER TABLE user_otp ADD COLUMN identifier TEXT")
                            cursor.execute("UPDATE user_otp SET identifier = user_id WHERE identifier IS NULL")
                            logger.info("✅ Successfully migrated user_otp table")
                        elif 'user_id' in columns and 'identifier' in columns:
                            # Both columns exist, clean up old user_id column
                            logger.info("🧹 Cleaning up old user_id column from user_otp table")
                            # Note: SQLite doesn't support DROP COLUMN directly, so we'll leave it for now
                            # The identifier column will be used going forward
                            logger.info("✅ user_otp table migration completed")
                            
                    except sqlite3.OperationalError as e:
                        logger.info(f"ℹ️ No migration needed for user_otp table: {e}")
                    
                logger.info("✅ User OTP table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating user_otp table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def create_temp_registrations_table(self):
        """Create table for temporary registration data with cleanup"""
        create_temp_reg_sql = """
        CREATE TABLE IF NOT EXISTS temp_registrations (
            temp_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT,  -- Store password hash for session fallback
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            expires_at DATETIME DEFAULT (datetime('now', '+20 minutes')) NOT NULL,
            
            CONSTRAINT chk_temp_id_format CHECK (temp_id LIKE 'temp_%'),
            CONSTRAINT chk_email_format CHECK (email LIKE '%@%.%'),
            CONSTRAINT chk_expires_future CHECK (expires_at > created_at)
        );
        """
        
        # Auto-cleanup trigger for old temp registrations
        cleanup_trigger_sql = """
        CREATE TRIGGER IF NOT EXISTS cleanup_old_temp_registrations
        AFTER INSERT ON temp_registrations
        BEGIN
            DELETE FROM temp_registrations 
            WHERE expires_at < datetime('now');
        END;
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(create_temp_reg_sql)
                    cursor.execute(cleanup_trigger_sql)
                    
                    # Add password_hash column if it doesn't exist (for existing databases)
                    try:
                        cursor.execute("ALTER TABLE temp_registrations ADD COLUMN password_hash TEXT")
                        logger.info("✅ Added password_hash column to temp_registrations table")
                    except sqlite3.OperationalError:
                        # Column already exists
                        pass
                    
                    # Add expires_at column if it doesn't exist (for existing databases)
                    try:
                        cursor.execute("ALTER TABLE temp_registrations ADD COLUMN expires_at DATETIME")
                        # Set default value for existing records
                        cursor.execute("UPDATE temp_registrations SET expires_at = datetime(created_at, '+20 minutes') WHERE expires_at IS NULL")
                        logger.info("✅ Added expires_at column to temp_registrations table")
                    except sqlite3.OperationalError:
                        # Column already exists
                        pass
                    
                logger.info("✅ Temporary registrations table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating temp_registrations table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def create_user_sessions_table(self):
        """Create table to track user sessions for security"""
        create_sessions_sql = """
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            expires_at DATETIME NOT NULL,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
            CONSTRAINT chk_session_id_length CHECK (length(session_id) >= 32),
            CONSTRAINT chk_expires_future CHECK (expires_at > created_at)
        );
        """
        
        # Auto-cleanup trigger for expired sessions
        cleanup_sessions_trigger = """
        CREATE TRIGGER IF NOT EXISTS cleanup_expired_sessions
        AFTER INSERT ON user_sessions
        BEGIN
            DELETE FROM user_sessions 
            WHERE expires_at < datetime('now');
        END;
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(create_sessions_sql)
                    cursor.execute(cleanup_sessions_trigger)
                logger.info("✅ User sessions table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating user_sessions table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def create_scan_history_table(self):
        """Create comprehensive scan history table for all scan types"""
        create_scan_history_sql = """
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scan_type TEXT NOT NULL CHECK (scan_type IN ('network', 'dns', 'virustotal', 'host_discovery')),
            target TEXT NOT NULL,
            scan_parameters TEXT,       -- JSON string of scan parameters
            scan_results TEXT,          -- JSON string of scan results
            scan_command TEXT,          -- Command executed (for nmap/network scans)
            status TEXT DEFAULT 'completed' CHECK (status IN ('completed', 'failed', 'in_progress')),
            duration INTEGER DEFAULT 0, -- Scan duration in seconds
            hosts_found INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0,
            vulnerabilities_found INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'low' CHECK (threat_level IN ('low', 'medium', 'high', 'critical')),
            notes TEXT,                 -- User notes about the scan
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
            
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
            CONSTRAINT chk_target_not_empty CHECK (length(trim(target)) > 0),
            CONSTRAINT chk_duration_positive CHECK (duration >= 0),
            CONSTRAINT chk_counts_positive CHECK (hosts_found >= 0 AND ports_found >= 0 AND vulnerabilities_found >= 0)
        );
        """
        
        # Auto-cleanup trigger for old scan history (optional - keep last 1000 scans per user)
        cleanup_old_scans_trigger = """
        CREATE TRIGGER IF NOT EXISTS cleanup_old_scan_history
        AFTER INSERT ON scan_history
        BEGIN
            DELETE FROM scan_history 
            WHERE user_id = NEW.user_id 
            AND scan_id NOT IN (
                SELECT scan_id FROM scan_history 
                WHERE user_id = NEW.user_id 
                ORDER BY timestamp DESC 
                LIMIT 1000
            );
        END;
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(create_scan_history_sql)
                    cursor.execute(cleanup_old_scans_trigger)
                logger.info("✅ Scan history table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating scan_history table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def create_user_settings_table(self):
        """Create the user_settings table for user preferences"""
        create_settings_sql = """
        CREATE TABLE IF NOT EXISTS user_settings (
            setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            setting_key TEXT NOT NULL,
            setting_value TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
            UNIQUE(user_id, setting_key)
        );
        """
        
        # Trigger to update updated_at timestamp
        update_trigger_sql = """
        CREATE TRIGGER IF NOT EXISTS user_settings_updated_at 
        AFTER UPDATE ON user_settings
        BEGIN
            UPDATE user_settings SET updated_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id;
        END;
        """
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(create_settings_sql)
                    cursor.execute(update_trigger_sql)
                logger.info("✅ User settings table created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating user_settings table: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def force_clean_database_rebuild(self):
        """Force complete database rebuild when schema is corrupted"""
        try:
            # Check if we can read basic schema
            conn = self.create_connection()
            if conn:
                cursor = conn.cursor()
                # Test critical tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_otp'")
                result = cursor.fetchone()
                if result:
                    # Test if identifier column exists properly
                    cursor.execute("PRAGMA table_info(user_otp)")
                    columns = [col[1] for col in cursor.fetchall()]
                    if 'identifier' not in columns:
                        logger.warning("⚠️ user_otp table missing identifier column")
                        raise sqlite3.Error("Schema corruption detected")
                conn.close()
        except sqlite3.Error as e:
            logger.error(f"❌ Database schema is corrupted: {e}")
            logger.info("🔄 Forcing complete database rebuild...")
            
            # Backup existing database
            if os.path.exists(self.db_path):
                backup_path = f"{self.db_path}.corrupted.{int(time.time())}"
                try:
                    import shutil
                    shutil.move(self.db_path, backup_path)
                    logger.info(f"📦 Backed up corrupted database to: {backup_path}")
                except Exception:
                    os.remove(self.db_path)
                    logger.info("🗑️ Removed corrupted database file")
            
            return True  # Indicate rebuild is needed
        return False  # No rebuild needed

    def force_clean_rebuild_if_corrupted(self):
        """Force clean database rebuild if schema is corrupted"""
        try:
            # Test if schema is valid
            conn = self.create_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM user_otp LIMIT 1")
                conn.close()
                logger.info("✅ Database schema validation passed")
                return False  # No corruption detected
        except sqlite3.Error as e:
            # Schema is corrupted, force rebuild
            logger.warning(f"⚠️ Database schema corruption detected: {e}")
            import os
            if os.path.exists(self.db_path):
                backup_path = f"{self.db_path}.backup.{int(time.time())}"
                try:
                    os.rename(self.db_path, backup_path)
                    logger.info(f"🗑️ Backed up corrupted database to: {backup_path}")
                except OSError:
                    os.remove(self.db_path)
                    logger.info("🗑️ Removed corrupted database for clean rebuild")
                logger.info("🔄 Database will be recreated with clean schema")
                return True  # Corruption detected, rebuild needed
        return False

    def recreate_indexes_if_needed(self):
        """Recreate indexes if they reference old schema columns"""
        try:
            conn = self.create_connection()
            if conn:
                cursor = conn.cursor()
                
                # Check if old indexes exist
                cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_otp_user_id%'")
                old_indexes = cursor.fetchall()
                
                if old_indexes:
                    logger.info("🔄 Found old OTP indexes, recreating with new schema...")
                    # Drop old indexes
                    for index in old_indexes:
                        cursor.execute(f"DROP INDEX IF EXISTS {index[0]}")
                    
                    # Recreate with new schema
                    self.create_indexes()
                    logger.info("✅ Indexes recreated successfully")
                
                conn.close()
                return True
        except sqlite3.Error as e:
            logger.error(f"❌ Error recreating indexes: {e}")
            return False

    def create_indexes(self):
        """Create optimized database indexes for better performance"""
        indexes = [
            # Users table indexes
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = TRUE;",
            "CREATE INDEX IF NOT EXISTS idx_users_verified ON users(is_verified);",
            "CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_until) WHERE locked_until IS NOT NULL;",
            # OTP table indexes - Updated to use identifier column
            "CREATE INDEX IF NOT EXISTS idx_otp_identifier ON user_otp(identifier);",
            "CREATE INDEX IF NOT EXISTS idx_otp_expires ON user_otp(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_otp_code_lookup ON user_otp(identifier, otp_code, otp_type, is_used, expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_otp_cleanup ON user_otp(expires_at) WHERE is_used = FALSE;",
            # Temp registrations indexes
            "CREATE INDEX IF NOT EXISTS idx_temp_email ON temp_registrations(email);",
            "CREATE INDEX IF NOT EXISTS idx_temp_created ON temp_registrations(created_at);",
            # Sessions indexes
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(user_id, is_active) WHERE is_active = TRUE;",
            # ===== NEW: Scan History Indexes for Fast Querying =====
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_timestamp ON scan_history(user_id, timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_scan_type ON scan_history(scan_type);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_type ON scan_history(user_id, scan_type);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_target ON scan_history(target);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_threat_level ON scan_history(threat_level);",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_user_search ON scan_history(user_id, scan_type, timestamp DESC);",
            # ===== NEW: User Settings Indexes =====
            "CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_user_settings_key ON user_settings(setting_key);",
            "CREATE INDEX IF NOT EXISTS idx_user_settings_updated_at ON user_settings(updated_at DESC);",
        ]
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    for index_sql in indexes:
                        cursor.execute(index_sql)
                logger.info("✅ Database indexes created successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Error creating indexes: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def initialize_database(self):
        """Initialize the complete database structure with corruption handling"""
        logger.info("🚀 Starting SANA Toolkit database initialization...")
        
        # FORCE CLEAN REBUILD FOR RENDER DEPLOYMENT
        if os.environ.get('RENDER') == 'true' or os.environ.get('FLASK_ENV') == 'production':
            logger.info("🌐 Production environment detected - forcing clean database rebuild")
            if os.path.exists(self.db_path):
                backup_path = f"{self.db_path}.backup.{int(time.time())}"
                try:
                    os.rename(self.db_path, backup_path)
                    logger.info(f"📦 Backed up existing database to: {backup_path}")
                except Exception:
                    os.remove(self.db_path)
                    logger.info("🗑️ Removed existing database for clean rebuild")
        
        # Check for corruption and rebuild if needed
        elif self.force_clean_database_rebuild():
            logger.info("🔄 Proceeding with clean database rebuild due to corruption...")
        
        # Check if database file exists
        db_exists = os.path.exists(self.db_path)
        if db_exists:
            logger.info(f"📁 Database file exists: {self.db_path}")
        else:
            logger.info(f"📁 Creating new database: {self.db_path}")
        
        # Create all tables in proper order
        success = True
        success &= self.create_users_table()
        success &= self.create_user_otp_table()
        success &= self.create_temp_registrations_table()
        success &= self.create_user_sessions_table()
        success &= self.create_scan_history_table()  # ✅ NEW: Added scan history table
        success &= self.create_user_settings_table()  # ✅ NEW: Added user settings table
        
        # Check for index recreation if needed
        if db_exists:
            self.recreate_indexes_if_needed()
        
        success &= self.create_indexes()
        
        if success:
            logger.info("🎉 SANA Toolkit database initialized successfully!")
            self.show_database_info()
            return True
        else:
            logger.error("❌ Database initialization failed!")
            return False
    
    def show_database_info(self):
        """Display database information and statistics"""
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                print("\n" + "="*60)
                print("📊 SANA Toolkit Database Information")
                print("="*60)
                
                # Database file info
                if os.path.exists(self.db_path):
                    file_size = os.path.getsize(self.db_path)
                    print(f"📁 Database file: {self.db_path}")
                    print(f"💾 File size: {file_size:,} bytes ({file_size/1024:.1f} KB)")
                
                # Table information
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                print(f"\n📋 Tables ({len(tables)}):")
                
                for table in tables:
                    table_name = table['name']
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table_name};")
                    count = cursor.fetchone()['count']
                    print(f"  • {table_name}: {count:,} records")
                
                # ✅ NEW: Scan history statistics
                cursor.execute("""
                    SELECT 
                        scan_type,
                        COUNT(*) as count,
                        MAX(timestamp) as last_scan
                    FROM scan_history 
                    GROUP BY scan_type
                    ORDER BY count DESC;
                """)
                scan_stats = cursor.fetchall()
                
                if scan_stats:
                    print(f"\n🔍 Scan History Statistics:")
                    for stat in scan_stats:
                        print(f"  • {stat['scan_type'].title()}: {stat['count']:,} scans (Last: {stat['last_scan'] or 'Never'})")
                
                print("="*60)
                
            except sqlite3.Error as e:
                logger.error(f"Error showing database info: {e}")
            finally:
                conn.close()
    
    def reset_database(self):
        """⚠️ DANGER: Reset database - removes all data"""
        logger.warning("⚠️  RESETTING DATABASE - ALL DATA WILL BE LOST!")
        
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    
                    # Drop all tables in reverse order to handle foreign keys
                    tables = ['user_settings', 'scan_history', 'user_sessions', 'temp_registrations', 'user_otp', 'users']  # ✅ Added user_settings and scan_history
                    for table in tables:
                        cursor.execute(f"DROP TABLE IF EXISTS {table}")
                
                logger.info("🗑️  All tables dropped")
                
                # Recreate tables
                return self.initialize_database()
                
            except sqlite3.Error as e:
                logger.error(f"Error resetting database: {e}")
                return False
            finally:
                conn.close()
        return False
    
    def backup_database(self, backup_path=None):
        """Create a backup of the database"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"data/sana_toolkit_backup_{timestamp}.db"
        
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"💾 Database backed up to: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"❌ Backup failed: {e}")
            return None
    
    def optimize_database(self):
        """Optimize database performance"""
        conn = self.create_connection()
        if conn:
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("VACUUM;")  # Rebuild database file
                    cursor.execute("ANALYZE;")  # Update query planner statistics
                logger.info("✅ Database optimized successfully")
                return True
            except sqlite3.Error as e:
                logger.error(f"❌ Database optimization failed: {e}")
                return False
            finally:
                conn.close()
        return False

def main():
    """Main function for testing database initialization"""
    print("🛡️  SANA Toolkit - Enhanced Database Initialization")
    print("=" * 60)
    
    # Initialize database
    db_init = DatabaseInitializer()
    
    # Ask user what to do
    print("\nOptions:")
    print("1. Initialize/Update database")
    print("2. Show database info")
    print("3. Reset database (DANGER!)")
    print("4. Create backup")
    print("5. Optimize database")
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    if choice == '1':
        db_init.initialize_database()
    elif choice == '2':
        db_init.show_database_info()
    elif choice == '3':
        confirm = input("⚠️  Are you sure? Type 'YES' to confirm: ").strip()
        if confirm == 'YES':
            db_init.reset_database()
        else:
            print("❌ Operation cancelled")
    elif choice == '4':
        backup_path = db_init.backup_database()
        if backup_path:
            print(f"✅ Backup created: {backup_path}")
    elif choice == '5':
        db_init.optimize_database()
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()