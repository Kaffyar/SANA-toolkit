# SANA Flask App - Render Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the SANA Flask app to Render with proper session handling and OTP verification.

## Prerequisites

1. Your code is pushed to a Git repository (GitHub, GitLab, etc.)
2. You have a Render account
3. Your Flask app is working locally

## Step 1: Environment Variables for Render

In your Render dashboard, add these **Environment Variables**:

### Required Variables:
```
FLASK_ENV=production
RENDER=true
FLASK_SECRET_KEY=your-secure-32-character-secret-key-here
```

### Optional Variables:
```
PORT=10000
```

### How to Generate a Secure Secret Key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Step 2: Render Service Configuration

### Web Service Settings:
- **Name**: `sana-toolkit` (or your preferred name)
- **Environment**: `Python 3`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`

### Advanced Settings:
- **Auto-Deploy**: `Yes` (recommended)
- **Branch**: `main` (or your default branch)

## Step 3: Verify Your Files

Make sure these files are in your repository:

### Required Files:
- ✅ `app.py` (with session fixes)
- ✅ `requirements.txt` (without Flask-Session)
- ✅ `Procfile` (for gunicorn)
- ✅ `.gitignore` (excludes secret_key.txt)

### Key Changes Made:
- ✅ Enhanced session configuration for Render
- ✅ Database fallback for OTP verification
- ✅ CORS headers for cloud deployment
- ✅ Render-specific environment detection

## Step 4: Deploy and Test

1. **Deploy**: Render will automatically deploy when you push to your repository
2. **Check Logs**: Monitor the deployment logs for any errors
3. **Test OTP Flow**: Try the registration/login process

## Step 5: Troubleshooting

### If Sessions Still Don't Work:

1. **Check Environment Variables**:
   ```bash
   # In Render logs, look for:
   FLASK_ENV=production
   RENDER=true
   FLASK_SECRET_KEY=set
   ```

2. **Test Database Fallback**:
   - The app has a database fallback for OTP verification
   - This works even if sessions fail
   - Check logs for "Database fallback" messages

3. **Check Cookie Settings**:
   - Ensure HTTPS is working (Render provides this)
   - Check browser console for cookie errors
   - Verify domain settings

### Common Issues:

#### Issue: "Email is required for verification"
**Solution**: The database fallback should handle this. Check if OTP codes are being sent and stored.

#### Issue: Sessions are empty
**Solution**: This is expected on Render. The database fallback will handle OTP verification.

#### Issue: App won't start
**Solution**: Check the build logs for missing dependencies or import errors.

## Step 6: Monitoring

### Check These Logs:
```
✅ Generated secure secret key for Render deployment
✅ Database initialized successfully on startup
🔐 Session data set successfully:
🔄 Attempting database fallback verification...
✅ Database fallback login successful
```

### Debug Endpoints:
- `/auth/session-debug` - Check session state
- `/auth/test-session` - Test session functionality
- `/auth/api/verify-otp-db` - Direct database OTP verification

## Step 7: Testing the Deployment

### Test OTP Flow:
1. Go to your Render app URL
2. Try to register/login with your email
3. Check if OTP is sent
4. Enter the OTP code
5. Should work even if sessions fail (database fallback)

### Test Session Debug:
```bash
curl https://your-app.onrender.com/auth/session-debug
```

## Environment Variables Summary

| Variable | Value | Purpose |
|----------|-------|---------|
| `FLASK_ENV` | `production` | Enable production mode |
| `RENDER` | `true` | Enable Render-specific config |
| `FLASK_SECRET_KEY` | `your-secret-key` | Secure session encryption |
| `PORT` | `10000` | Port for the app (optional) |

## Benefits of This Configuration

✅ **Works on Render**: No filesystem dependencies  
✅ **Session Fallback**: Database-backed OTP verification  
✅ **Secure**: HTTPS cookies and signed sessions  
✅ **Scalable**: Works with multiple instances  
✅ **Debugging**: Comprehensive logging and test endpoints  

## Support

If you encounter issues:

1. Check the Render deployment logs
2. Test the database fallback endpoint
3. Verify environment variables are set correctly
4. Check browser console for cookie errors

The database fallback ensures OTP verification works even when sessions fail, making the app robust for cloud deployment. 