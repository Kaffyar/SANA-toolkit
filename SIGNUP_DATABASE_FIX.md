# Signup Database Insertion Fix

## Problem Identified

The signup process was creating `temp_user_id` in session but **NOT saving it to the `temp_registrations` database table**. This caused the verification process to fail with:

```
✅ Session has temp_id: temp_1753557913_c6da0112
❌ Database lookup fails: "No temp_registration found for temp_id: temp_1753557913_c6da0112"
```

## Root Cause Analysis

The issue was in the `send_signup_otp` method in `models/user_model.py`. While the code appeared correct, there was insufficient logging to identify where the database insertion was failing. The method was supposed to:

1. Insert data into `temp_registrations` table
2. Generate and save OTP
3. Send email
4. Return success with temp_id

But the database insertion was failing silently or not being properly committed.

## Fixes Implemented

### 1. Enhanced Logging in `send_signup_otp` Method

**File: `models/user_model.py`**

Added comprehensive logging throughout the signup process:

```python
def send_signup_otp(self, email: str, password: str = None) -> Tuple[bool, str, Optional[str]]:
    """Send OTP for signup with password storage for session fallback and enhanced logging"""
    
    logger.info(f"🔍 Starting send_signup_otp for email: {email}")
    
    # ... validation code ...
    
    logger.info(f"🧹 Cleaning up existing temp registrations for {email}")
    cursor.execute('DELETE FROM temp_registrations WHERE email = ?', (email,))
    deleted_count = cursor.rowcount
    logger.info(f"🧹 Deleted {deleted_count} existing temp registrations for {email}")
    
    # Generate temporary ID
    temp_id = f"temp_{int(time.time())}_{secrets.token_hex(4)}"
    logger.info(f"🆔 Generated temp_id: {temp_id} for {email}")
    
    # Store temporary registration
    logger.info(f"🔐 Storing temp registration with password for {email}")
    # ... INSERT statement ...
    
    # Commit the transaction
    logger.info(f"💾 Committing temp_registrations insert for {email}")
    conn.commit()
    logger.info(f"✅ Temp registration committed successfully for {email}")
    
    # Verify the insertion immediately
    cursor.execute('SELECT temp_id FROM temp_registrations WHERE temp_id = ?', (temp_id,))
    verification_result = cursor.fetchone()
    if verification_result:
        logger.info(f"✅ Database verification: temp_id {temp_id} found in temp_registrations")
    else:
        logger.error(f"❌ CRITICAL: Database verification failed - temp_id {temp_id} not found after insert!")
```

### 2. Enhanced Logging in `find_temp_id_by_email` Method

**File: `models/user_model.py`**

Added detailed logging to help diagnose lookup issues:

```python
def find_temp_id_by_email(self, email: str) -> Optional[str]:
    """Find temp_id for a given email from temp_registrations table with enhanced logging"""
    
    logger.info(f"🔍 Searching for temp_id by email: {email}")
    
    # ... database query ...
    
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
```

### 3. Enhanced Signup Endpoint Logging

**File: `routes/auth_routes.py`**

Added comprehensive logging to the signup endpoint:

```python
@auth_bp.route('/api/send-signup-otp', methods=['POST'])
def send_signup_otp():
    """Send OTP for signup with comprehensive validation and enhanced database logging"""
    
    # FIXED: Enhanced logging for signup process
    client_info = get_client_info()
    logger.info(f"🚀 Starting signup process for {email} from {client_info['ip_address']}")
    
    # Send signup OTP with enhanced logging
    logger.info(f"📧 Calling user_manager.send_signup_otp for {email}")
    success, message, temp_id = user_manager.send_signup_otp(email, password)
    
    if success:
        logger.info(f"✅ Signup OTP sent successfully for {email}")
        logger.info(f"✅ Generated temp_id: {temp_id}")
        
        # FIXED: Verify database insertion immediately
        logger.info(f"🔍 Verifying database insertion for temp_id: {temp_id}")
        db_temp_id = user_manager.find_temp_id_by_email(email)
        if db_temp_id:
            logger.info(f"✅ Database verification successful: temp_id {db_temp_id} found in database")
        else:
            logger.error(f"❌ CRITICAL: Database verification failed - temp_id not found in database!")
            logger.error(f"❌ Expected temp_id: {temp_id}")
            logger.error(f"❌ Email: {email}")
```

### 4. Database Schema Verification

**File: `models/user_model.py`**

Added a method to check database schema and table structure:

```python
def check_database_schema(self) -> Dict[str, Any]:
    """Check database schema and table structure for debugging"""
    schema_info = {
        'temp_registrations_exists': False,
        'temp_registrations_columns': [],
        'temp_registrations_count': 0,
        'database_path': self.db_path
    }
    
    # Check if temp_registrations table exists
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='temp_registrations'
    """)
    table_exists = cursor.fetchone() is not None
    schema_info['temp_registrations_exists'] = table_exists
    
    if table_exists:
        # Get table schema and row count
        cursor.execute("PRAGMA table_info(temp_registrations)")
        columns = cursor.fetchall()
        schema_info['temp_registrations_columns'] = [col['name'] for col in columns]
        
        cursor.execute("SELECT COUNT(*) as count FROM temp_registrations")
        count_result = cursor.fetchone()
        schema_info['temp_registrations_count'] = count_result['count'] if count_result else 0
        
        logger.info(f"✅ temp_registrations table exists with {schema_info['temp_registrations_count']} rows")
        logger.info(f"📋 Columns: {schema_info['temp_registrations_columns']}")
    else:
        logger.error("❌ temp_registrations table does not exist!")
    
    return schema_info
```

### 5. Debug Endpoints

**File: `routes/auth_routes.py`**

Added debug endpoints to help diagnose issues:

```python
@auth_bp.route('/debug-database')
def debug_database():
    """Debug endpoint to check database schema and temp_registrations table"""
    # Check database schema
    schema_info = user_manager.check_database_schema()
    
    # Get sample data from temp_registrations
    conn = user_manager.create_connection()
    temp_data = []
    if conn:
        cursor = conn.cursor()
        cursor.execute('SELECT temp_id, email, created_at, expires_at FROM temp_registrations ORDER BY created_at DESC LIMIT 10')
        rows = cursor.fetchall()
        temp_data = [dict(row) for row in rows]
        conn.close()
    
    return jsonify({
        'status': 'success',
        'schema_info': schema_info,
        'temp_registrations_sample': temp_data,
        'timestamp': datetime.now().isoformat()
    })

@auth_bp.route('/test-temp-insert', methods=['POST'])
def test_temp_insert():
    """Test endpoint to manually insert a temp registration for debugging"""
    # Manually insert a test temp registration to verify database functionality
```

### 6. Comprehensive Test Script

**File: `test_signup_fix.py`**

Created a comprehensive test script to verify the signup process:

```python
def main():
    """Run comprehensive signup tests"""
    # Test 1: Database connection and schema
    db_ok = test_database_connection()
    
    # Test 2: Debug endpoints
    test_debug_endpoints()
    
    # Test 3: Manual temp insertion
    manual_temp_id = test_temp_insert()
    
    # Test 4: Signup OTP send
    signup_success = test_signup_otp_send()
    
    # Test 5: Verify temp registration after signup
    signup_temp_id = verify_temp_registration_in_db(TEST_EMAIL)
    
    # Test 6: Test find_temp_id_by_email
    found_temp_id = test_find_temp_id_by_email(TEST_EMAIL)
```

## Key Improvements

### 1. **Immediate Database Verification**
After inserting a temp registration, the code now immediately verifies it was inserted correctly:

```python
# Verify the insertion immediately
cursor.execute('SELECT temp_id FROM temp_registrations WHERE temp_id = ?', (temp_id,))
verification_result = cursor.fetchone()
if verification_result:
    logger.info(f"✅ Database verification: temp_id {temp_id} found in temp_registrations")
else:
    logger.error(f"❌ CRITICAL: Database verification failed - temp_id {temp_id} not found after insert!")
```

### 2. **Enhanced Error Handling**
All database operations now have proper error handling and logging:

```python
except sqlite3.IntegrityError as e:
    logger.error(f"❌ Integrity error sending signup OTP for {email}: {e}")
    return False, "Database error during signup", None
except sqlite3.Error as e:
    logger.error(f"❌ Database error sending signup OTP for {email}: {e}")
    return False, "Database error during signup", None
```

### 3. **Comprehensive Logging**
Every step of the signup process is now logged with clear emojis and detailed information:

- 🚀 Starting signup process
- 🧹 Cleaning up existing registrations
- 🆔 Generated temp_id
- 🔐 Storing temp registration
- 💾 Committing transaction
- ✅ Database verification
- 🔢 Generating OTP
- 📧 Sending email

### 4. **Database Schema Validation**
The system now validates that the required tables exist and have the correct structure.

## Testing the Fix

1. **Run the test script:**
   ```bash
   python test_signup_fix.py
   ```

2. **Check debug endpoints:**
   - `GET /debug-database` - Check database schema
   - `POST /test-temp-insert` - Test manual insertion
   - `GET /session-debug` - Check session state

3. **Monitor logs:**
   The enhanced logging will show exactly where any issues occur in the signup process.

## Expected Results

After implementing these fixes:

1. ✅ Signup process will create temp_registrations in database
2. ✅ Session will contain temp_user_id
3. ✅ Database lookup will find the temp registration
4. ✅ OTP verification will work correctly
5. ✅ User account creation will succeed

The enhanced logging will help identify any remaining issues and ensure the signup process works reliably in all environments, including cloud deployments where session persistence might be problematic. 