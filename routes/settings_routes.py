"""
SANA Toolkit - Settings Routes
Handles all settings-related endpoints for user preferences and account management
"""

from flask import Blueprint, request, jsonify, render_template, session
from models.settings_model import settings_manager
from routes.auth_routes import login_required
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create settings blueprint
settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
@login_required
def settings_page():
    """Render the settings page with user data"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        # Get user settings
        settings = settings_manager.get_user_settings(user_id)
        
        # Get user stats
        user_stats = settings_manager.get_user_stats(user_id)
        
        # Get user info for display
        from models.user_model import UserManager
        user_mgr = UserManager()
        user_info = user_mgr.get_user_by_id(user_id)
        
        if not user_info:
            return jsonify({'error': 'User not found'}), 404
        
        # Convert string dates to datetime objects for template formatting
        created_at = None
        last_login = None
        
        if user_info['created_at']:
            try:
                created_at = datetime.fromisoformat(user_info['created_at'])
            except (ValueError, TypeError):
                created_at = None
        
        if user_info['last_login']:
            try:
                last_login = datetime.fromisoformat(user_info['last_login'])
            except (ValueError, TypeError):
                last_login = None
        
        # Prepare data for template
        template_data = {
            'settings': settings,
            'user_info': {
                'user_id': user_info['user_id'],
                'email': user_info['email'],
                'is_verified': user_info['is_verified'],
                'created_at': created_at,
                'last_login': last_login
            },
            'user_stats': user_stats
        }
        
        return render_template('settings.html', **template_data)
        
    except Exception as e:
        logger.error(f"Error rendering settings page: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    """Get user settings via API"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        settings = settings_manager.get_user_settings(user_id)
        return jsonify({
            'success': True,
            'settings': settings
        })
        
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings', methods=['POST'])
@login_required
def update_settings():
    """Update user settings"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract settings from request
        settings_to_update = {}
        
        if 'theme' in data:
            settings_to_update['theme'] = data['theme']
        
        if 'scan_timeout' in data:
            settings_to_update['scan_timeout'] = int(data['scan_timeout'])
        
        if 'virustotal_api_key' in data:
            settings_to_update['virustotal_api_key'] = data['virustotal_api_key']
        
        if 'history_cleanup_days' in data:
            settings_to_update['history_cleanup_days'] = int(data['history_cleanup_days'])
        
        if 'notifications_enabled' in data:
            settings_to_update['notifications_enabled'] = bool(data['notifications_enabled'])
        
        if 'auto_save_results' in data:
            settings_to_update['auto_save_results'] = bool(data['auto_save_results'])
        
        if 'scan_verbosity' in data:
            settings_to_update['scan_verbosity'] = data['scan_verbosity']
        
        # Update settings
        success, message = settings_manager.update_user_settings(user_id, settings_to_update)
        
        if success:
            # Get updated settings
            updated_settings = settings_manager.get_user_settings(user_id)
            return jsonify({
                'success': True,
                'message': message,
                'settings': updated_settings
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"Error updating settings: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/reset', methods=['POST'])
@login_required
def reset_settings():
    """Reset user settings to defaults"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        success, message = settings_manager.reset_user_settings(user_id)
        
        if success:
            # Get reset settings
            reset_settings = settings_manager.get_user_settings(user_id)
            return jsonify({
                'success': True,
                'message': message,
                'settings': reset_settings
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"Error resetting settings: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/change-email', methods=['POST'])
@login_required
def change_email():
    """Change user email address"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        data = request.get_json()
        if not data or 'new_email' not in data:
            return jsonify({'error': 'New email is required'}), 400
        
        new_email = data['new_email'].strip()
        if not new_email:
            return jsonify({'error': 'New email cannot be empty'}), 400
        
        success, message = settings_manager.change_user_email(user_id, new_email)
        
        if success:
            return jsonify({
                'success': True,
                'message': message,
                'new_email': new_email
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"Error changing email: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        current_password = data.get('current_password', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        # Validation
        if not current_password:
            return jsonify({'error': 'Current password is required'}), 400
        
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
        
        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match'}), 400
        
        success, message = settings_manager.change_user_password(user_id, current_password, new_password)
        
        if success:
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/user-stats', methods=['GET'])
@login_required
def get_user_stats():
    """Get user statistics"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        stats = settings_manager.get_user_stats(user_id)
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/cleanup-history', methods=['POST'])
@login_required
def cleanup_history():
    """Clean up old scan history based on user settings"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        # Get request data for optional force cleanup
        data = request.get_json() or {}
        force_days = data.get('force_days')  # Optional: force cleanup for specific days
        
        success, message, deleted_count = settings_manager.cleanup_old_scan_history(user_id, force_days)
        
        if success:
            return jsonify({
                'success': True,
                'message': message,
                'deleted_count': deleted_count
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
    except Exception as e:
        logger.error(f"Error cleaning up history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/validate-virustotal-key', methods=['POST'])
@login_required
def validate_virustotal_key():
    """Validate VirusTotal API key"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        data = request.get_json()
        if not data or 'api_key' not in data:
            return jsonify({'error': 'API key is required'}), 400
        
        api_key = data['api_key'].strip()
        if not api_key:
            return jsonify({'error': 'API key cannot be empty'}), 400
        
        # Basic validation - check if it looks like a valid VT API key
        if len(api_key) < 20 or len(api_key) > 100:
            return jsonify({
                'success': False,
                'error': 'Invalid API key format'
            }), 400
        
        # TODO: Add actual VirusTotal API validation here
        # For now, just return success
        return jsonify({
            'success': True,
            'message': 'API key format is valid'
        })
        
    except Exception as e:
        logger.error(f"Error validating VirusTotal key: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@settings_bp.route('/api/settings/export', methods=['GET'])
@login_required
def export_settings():
    """Export user settings as JSON"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        settings = settings_manager.get_user_settings(user_id)
        user_stats = settings_manager.get_user_stats(user_id)
        
        # Get user info
        from models.user_model import UserManager
        user_mgr = UserManager()
        user_info = user_mgr.get_user_by_id(user_id)
        
        export_data = {
            'export_date': datetime.now().isoformat(),
            'user_info': {
                'user_id': user_info['user_id'] if user_info else None,
                'email': user_info['email'] if user_info else None,
                'created_at': user_info['created_at'] if user_info else None
            },
            'settings': settings,
            'statistics': user_stats
        }
        
        return jsonify({
            'success': True,
            'data': export_data
        })
        
    except Exception as e:
        logger.error(f"Error exporting settings: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers for settings blueprint
@settings_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Settings endpoint not found'}), 404

@settings_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Settings blueprint error: {error}")
    return jsonify({'error': 'Internal server error'}), 500 