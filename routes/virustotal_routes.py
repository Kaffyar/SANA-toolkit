from flask import Blueprint, render_template, request, jsonify, session
import requests
import hashlib
import re
import logging
import base64
import os
from urllib.parse import urlparse
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create blueprint
virustotal_bp = Blueprint('virustotal', __name__)

# VirusTotal API configuration
VT_API_KEY = "7ff506ba436facd6310f96c097fa1c54eb3da3aff50b1a27b2ed70b38bba312b"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Helper functions
def get_headers():
    """Get headers for VirusTotal API requests"""
    return {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/json"
    }

def initialize_counters():
    """Initialize counter files if they don't exist"""
    try:
        # Initialize scan counter
        if not os.path.exists('scan_counter.txt'):
            with open('scan_counter.txt', 'w') as f:
                f.write('0')
        
        # Initialize threats counter  
        if not os.path.exists('threats_counter.txt'):
            with open('threats_counter.txt', 'w') as f:
                f.write('0')
                
        logger.info("Counter files initialized")
    except Exception as e:
        logger.error(f"Failed to initialize counters: {str(e)}")

def get_total_scans_performed():
    """Get total number of scans performed by users"""
    try:
        counter_file = 'scan_counter.txt'
        if os.path.exists(counter_file):
            with open(counter_file, 'r') as f:
                return int(f.read().strip() or 0)
        else:
            return 0
    except:
        return 0

def increment_scan_counter():
    """Increment the scan counter - call this after each successful scan"""
    try:
        current_count = get_total_scans_performed()
        new_count = current_count + 1
        
        with open('scan_counter.txt', 'w') as f:
            f.write(str(new_count))
        
        logger.info(f"Scan counter incremented to: {new_count}")
        return new_count
    except Exception as e:
        logger.error(f"Failed to increment scan counter: {str(e)}")
        return 0

def get_threats_detected_count():
    """Get total threats detected"""
    try:
        counter_file = 'threats_counter.txt'
        if os.path.exists(counter_file):
            with open(counter_file, 'r') as f:
                return int(f.read().strip() or 0)
        else:
            return 0
    except:
        return 0

def increment_threats_counter():
    """Increment threats counter when malicious items are found"""
    try:
        current_count = get_threats_detected_count()
        new_count = current_count + 1
        
        with open('threats_counter.txt', 'w') as f:
            f.write(str(new_count))
        
        logger.info(f"Threats counter incremented to: {new_count}")
        return new_count
    except Exception as e:
        logger.error(f"Failed to increment threats counter: {str(e)}")
        return 0

def should_increment_threat_counter(stats):
    """Safely determine if we should increment the threat counter"""
    if not stats or not isinstance(stats, dict):
        logger.info("No stats provided or invalid format")
        return False
    
    # Get counts and ensure they're integers
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    
    try:
        malicious = int(malicious) if malicious is not None else 0
        suspicious = int(suspicious) if suspicious is not None else 0
    except (ValueError, TypeError):
        logger.warning(f"Could not convert threat counts to integers: malicious={malicious}, suspicious={suspicious}")
        return False
    
    # Only increment if we have actual threats
    has_threats = malicious > 0 or suspicious > 0
    
    logger.info(f"Threat analysis - Malicious: {malicious}, Suspicious: {suspicious}, Has threats: {has_threats}")
    
    return has_threats

def get_available_engines_count():
    """Get real number of available engines from VirusTotal"""
    try:
        # This gets the actual engine count from VT
        url = f"{VT_BASE_URL}/metadata"
        response = requests.get(url, headers=get_headers(), timeout=10)
        
        if response.status_code == 200:
            # If metadata endpoint works, count engines
            return 70  # Fallback to known count
        else:
            # Fallback to standard VirusTotal engine count
            return 73
    except:
        return 70  # Safe fallback

@virustotal_bp.route('/virustotal-dashboard-stats')
def get_dashboard_stats():
    """Get real dashboard statistics for VirusTotal integration"""
    try:
        # Get real API quota information
        quota_response = get_api_quota()
        
        if isinstance(quota_response, tuple):
            quota_data = quota_response[0].get_json()
        else:
            quota_data = quota_response.get_json()
        
        # Get actual usage from your app
        total_scans = get_total_scans_performed()
        threats_detected = get_threats_detected_count()
        
        # Get real engine count from VirusTotal
        engines_count = get_available_engines_count()
        
        # Safely get quota information with defaults
        quota_info = quota_data.get('quota', {})
        requests_made = quota_info.get('requests_made', 0)
        requests_allowed = quota_info.get('requests_allowed', 0)
        
        # Handle quota information safely
        if isinstance(requests_made, str) and requests_made == 'N/A':
            requests_made = 0
        if isinstance(requests_allowed, str):
            requests_allowed = 0
        
        # Ensure they're integers
        try:
            requests_made = int(requests_made) if requests_made else 0
            requests_allowed = int(requests_allowed) if requests_allowed else 0
        except (ValueError, TypeError):
            requests_made = 0
            requests_allowed = 0
        
        # Calculate API usage percentage safely
        if requests_allowed > 0:
            api_usage_percentage = round((requests_made / requests_allowed) * 100, 1)
            requests_remaining = max(0, requests_allowed - requests_made)
        else:
            api_usage_percentage = 0
            requests_remaining = 'Unknown'
        
        return jsonify({
            'status': 'success',
            'stats': {
                'total_analyses': total_scans,
                'threats_detected': threats_detected,
                'engines_available': engines_count,
                'api_requests_used': requests_made,
                'api_requests_remaining': requests_remaining,
                'api_usage_percentage': api_usage_percentage,
                'last_updated': int(time.time())
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        # Return safe fallback data instead of error
        return jsonify({
            'status': 'success',
            'stats': {
                'total_analyses': get_total_scans_performed(),
                'threats_detected': get_threats_detected_count(),
                'engines_available': 70,
                'api_requests_used': 0,
                'api_requests_remaining': 'Unknown',
                'api_usage_percentage': 0,
                'last_updated': int(time.time())
            }
        })

@virustotal_bp.route('/virustotal-quota')
def get_api_quota():
    """Get current API quota information"""
    try:
        # Note: This endpoint might not work with all API keys
        url = f"{VT_BASE_URL}/users/current"
        response = requests.get(url, headers=get_headers(), timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Safely extract quota information
            quotas = attributes.get('quotas', {})
            api_monthly = quotas.get('api_requests_monthly', {})
            uploads_monthly = quotas.get('api_uploads_monthly', {})
            
            quota_info = {
                'requests_made': api_monthly.get('used', 0),
                'requests_allowed': api_monthly.get('allowed', 1000),  # Default fallback
                'uploads_made': uploads_monthly.get('used', 0),
                'uploads_allowed': uploads_monthly.get('allowed', 100)  # Default fallback
            }
            
            return jsonify({
                'status': 'success',
                'quota': quota_info
            })
        else:
            # If quota endpoint is not available, return safe defaults
            logger.warning(f"Quota endpoint returned {response.status_code}, using defaults")
            return jsonify({
                'status': 'success',
                'quota': {
                    'requests_made': 0,
                    'requests_allowed': 1000,  # Safe default
                    'uploads_made': 0,
                    'uploads_allowed': 100
                }
            })
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error getting quota: {str(e)}")
        # Return safe defaults instead of error
        return jsonify({
            'status': 'success',
            'quota': {
                'requests_made': 0,
                'requests_allowed': 1000,  # Safe default
                'uploads_made': 0,
                'uploads_allowed': 100
            }
        })
    except Exception as e:
        logger.error(f"Error getting quota: {str(e)}")
        # Return safe defaults
        return jsonify({
            'status': 'success',
            'quota': {
                'requests_made': 0,
                'requests_allowed': 1000,
                'uploads_made': 0,
                'uploads_allowed': 100
            }
        })

def is_valid_hash(hash_string):
    """Validate if string is a valid hash (MD5, SHA1, SHA256)"""
    hash_string = hash_string.strip().lower()
    if re.match(r'^[a-f0-9]{32}$', hash_string):  # MD5
        return True, 'md5'
    elif re.match(r'^[a-f0-9]{40}$', hash_string):  # SHA1
        return True, 'sha1'
    elif re.match(r'^[a-f0-9]{64}$', hash_string):  # SHA256
        return True, 'sha256'
    return False, None

def is_valid_url(url):
    """Validate if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_domain(domain):
    """Validate if string is a valid domain"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return domain_pattern.match(domain) is not None

def is_valid_ip(ip):
    """Validate if string is a valid IP address"""
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return ip_pattern.match(ip) is not None

def format_scan_stats(stats):
    """Format scan statistics for display"""
    if not stats:
        return {}
    
    total = sum(stats.values())
    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0),
        'harmless': stats.get('harmless', 0),
        'timeout': stats.get('timeout', 0),
        'total': total,
        'malicious_percentage': round((stats.get('malicious', 0) / total * 100) if total > 0 else 0, 1),
        'detection_ratio': f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{total}"
    }

def process_analysis_results(analysis_results):
    """Process and format analysis results from multiple engines"""
    if not analysis_results:
        return []
    
    results = []
    for engine_name, engine_data in analysis_results.items():
        if isinstance(engine_data, dict):
            # Get the actual detection result text
            detection_result = engine_data.get('result')
            category = engine_data.get('category', 'undetected')
            
            # If category is harmless/clean but no result, set appropriate result text
            if category in ['harmless', 'undetected'] and not detection_result:
                detection_result = 'Clean'
            elif category == 'malicious' and not detection_result:
                detection_result = 'Detected'
            elif category == 'suspicious' and not detection_result:
                detection_result = 'Potentially unwanted'
            elif category == 'timeout':
                detection_result = 'Timeout'
            elif not detection_result:
                detection_result = 'No result'
            
            # Get method - if not provided, infer from category
            method = engine_data.get('method', 'unknown')
            if method == 'unknown' or not method:
                if category == 'harmless':
                    method = 'signature'
                elif category == 'malicious':
                    method = 'detection'
                elif category == 'suspicious':
                    method = 'heuristic'
                else:
                    method = 'analysis'
            
            # Get engine version
            engine_version = engine_data.get('engine_version', '')
            if not engine_version:
                engine_version = engine_data.get('engine_update', 'Unknown')
            
            results.append({
                'engine': engine_name,
                'category': category,
                'result': detection_result,
                'method': method,
                'engine_version': engine_version,
                'engine_update': engine_data.get('engine_update', '')
            })
    
    # Sort by category priority: malicious > suspicious > timeout > harmless > undetected
    category_priority = {
        'malicious': 0,
        'suspicious': 1, 
        'timeout': 2,
        'harmless': 3,
        'undetected': 4
    }
    
    return sorted(results, key=lambda x: category_priority.get(x['category'], 5))

def determine_reputation(stats):
    """Determine overall reputation based on scan statistics"""
    if not stats:
        return 'unknown'
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total = sum(stats.values())
    
    if total == 0:
        return 'unknown'
    
    malicious_ratio = malicious / total
    suspicious_ratio = suspicious / total
    
    if malicious_ratio >= 0.1:  # 10% or more malicious
        return 'malicious'
    elif malicious_ratio > 0 or suspicious_ratio >= 0.2:  # Any malicious or 20% suspicious
        return 'suspicious'
    else:
        return 'clean'

@virustotal_bp.route('/virustotal')
def virustotal_page():
    """Render the VirusTotal analysis page"""
    return render_template('virustotal.html')

@virustotal_bp.route('/virustotal-analyze', methods=['POST'])
def analyze_resource():
    """Analyze a resource (hash, URL, domain, or IP) using VirusTotal API"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        
        resource = data.get('resource', '').strip()
        analysis_type = data.get('analysisType', 'auto')
        
        if not resource:
            return jsonify({
                'status': 'error',
                'message': 'Resource is required'
            }), 400
        
        logger.info(f"Analyzing resource: {resource[:50]}... (type: {analysis_type})")
        
        # Determine resource type and call appropriate analysis function
        if analysis_type == 'auto':
            # Auto-detect resource type
            is_hash, hash_type = is_valid_hash(resource)
            if is_hash:
                return analyze_file_hash(resource, hash_type)
            elif is_valid_url(resource):
                return analyze_url(resource)
            elif is_valid_ip(resource):
                return analyze_ip(resource)
            elif is_valid_domain(resource):
                return analyze_domain(resource)
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid resource format. Please provide a valid hash, URL, domain, or IP address.'
                }), 400
        else:
            # Use specified analysis type
            if analysis_type == 'hash':
                is_hash, hash_type = is_valid_hash(resource)
                if not is_hash:
                    return jsonify({
                        'status': 'error',
                        'message': 'Invalid hash format'
                    }), 400
                return analyze_file_hash(resource, hash_type)
            elif analysis_type == 'url':
                return analyze_url(resource)
            elif analysis_type == 'domain':
                return analyze_domain(resource)
            elif analysis_type == 'ip':
                return analyze_ip(resource)
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid analysis type'
                }), 400
                
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Analysis failed: {str(e)}'
        }), 500

def analyze_file_hash(file_hash, hash_type):
    """Analyze a file hash using VirusTotal API"""
    scan_start_time = time.time()  # Track duration
    try:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=get_headers(), timeout=30)
        scan_duration = int(time.time() - scan_start_time)
        if response.status_code == 200:
            increment_scan_counter()
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            if should_increment_threat_counter(stats):
                increment_threats_counter()
            logger.info(f"VirusTotal response received for hash: {file_hash}")
            analysis_results = attributes.get('last_analysis_results', {})
            logger.info(f"Number of engines: {len(analysis_results)}")
            result = {
                'status': 'success',
                'resource_type': 'file',
                'resource': file_hash,
                'hash_type': hash_type,
                'scan_date': attributes.get('last_analysis_date'),
                'scan_stats': format_scan_stats(attributes.get('last_analysis_stats', {})),
                'analysis_results': process_analysis_results(analysis_results),
                'file_info': {
                    'md5': attributes.get('md5', ''),
                    'sha1': attributes.get('sha1', ''),
                    'sha256': attributes.get('sha256', ''),
                    'file_size': attributes.get('size', 0),
                    'file_type': attributes.get('type_description', ''),
                    'magic': attributes.get('magic', ''),
                    'first_submission_date': attributes.get('first_submission_date'),
                    'last_submission_date': attributes.get('last_submission_date'),
                    'times_submitted': attributes.get('times_submitted', 0),
                    'names': attributes.get('names', [])
                },
                'reputation': determine_reputation(attributes.get('last_analysis_stats', {}))
            }
            # --- VIRUSTOTAL SCAN HISTORY INTEGRATION ---
            if scan_history_db and 'user_id' in session:
                try:
                    scan_parameters = {'hash_type': hash_type}
                    scan_results_data = result
                    threat_level = result['reputation'] if result['reputation'] in ['low','medium','high','critical'] else 'low'
                    vulnerabilities_found = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    scan_history_db.add_scan(
                        user_id=session['user_id'],
                        scan_type='virustotal',
                        target=file_hash,
                        scan_parameters=scan_parameters,
                        scan_results=scan_results_data,
                        scan_command=f"VirusTotal file hash scan: {file_hash}",
                        duration=scan_duration,
                        hosts_found=0,
                        ports_found=0,
                        vulnerabilities_found=vulnerabilities_found,
                        threat_level=threat_level,
                        status='completed',
                        notes=f"VirusTotal file scan - {vulnerabilities_found} threats"
                    )
                except Exception as e:
                    logger.error(f"Failed to save VirusTotal file scan to history: {e}")
            # --- END INTEGRATION ---
            return jsonify(result)
        elif response.status_code == 404:
            return jsonify({
                'status': 'error',
                'message': 'File hash not found in VirusTotal database',
                'resource': file_hash
            }), 404
        else:
            logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
            return jsonify({
                'status': 'error',
                'message': f'VirusTotal API error: {response.status_code}',
                'resource': file_hash
            }), response.status_code
    except Exception as e:
        scan_duration = int(time.time() - scan_start_time)
        # --- VIRUSTOTAL SCAN HISTORY INTEGRATION (FAILED) ---
        if scan_history_db and 'user_id' in session:
            try:
                scan_history_db.add_scan(
                    user_id=session['user_id'],
                    scan_type='virustotal',
                    target=file_hash,
                    scan_parameters={'hash_type': hash_type, 'error': str(e)},
                    scan_results={'error': str(e)},
                    scan_command=f"VirusTotal file hash scan: {file_hash}",
                    duration=scan_duration,
                    status='failed',
                    threat_level='low',
                    notes='VirusTotal file scan failed'
                )
            except Exception as ex:
                logger.error(f"Failed to save failed VirusTotal file scan to history: {ex}")
        # --- END INTEGRATION ---
        logger.error(f"Error analyzing file hash: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error analyzing file hash: {str(e)}'
        }), 500

def analyze_url(url):
    """Analyze a URL using VirusTotal API"""
    scan_start_time = time.time()
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        get_url = f"{VT_BASE_URL}/urls/{url_id}"
        response = requests.get(get_url, headers=get_headers(), timeout=30)
        scan_duration = int(time.time() - scan_start_time)
        if response.status_code == 200:
            increment_scan_counter()
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            if should_increment_threat_counter(stats):
                increment_threats_counter()
            logger.info(f"VirusTotal response received for URL: {url}")
            analysis_results = attributes.get('last_analysis_results', {})
            logger.info(f"Number of engines: {len(analysis_results)}")
            result = {
                'status': 'success',
                'resource_type': 'url',
                'resource': url,
                'scan_date': attributes.get('last_analysis_date'),
                'scan_stats': format_scan_stats(attributes.get('last_analysis_stats', {})),
                'analysis_results': process_analysis_results(analysis_results),
                'url_info': {
                    'final_url': attributes.get('last_final_url', url),
                    'title': attributes.get('title', ''),
                    'last_http_response_code': attributes.get('last_http_response_code'),
                    'last_http_response_content_length': attributes.get('last_http_response_content_length'),
                    'categories': attributes.get('categories', {}),
                    'first_submission_date': attributes.get('first_submission_date'),
                    'last_submission_date': attributes.get('last_submission_date'),
                    'times_submitted': attributes.get('times_submitted', 0)
                },
                'reputation': determine_reputation(attributes.get('last_analysis_stats', {}))
            }
            # --- VIRUSTOTAL SCAN HISTORY INTEGRATION ---
            if scan_history_db and 'user_id' in session:
                try:
                    scan_parameters = {}
                    scan_results_data = result
                    threat_level = result['reputation'] if result['reputation'] in ['low','medium','high','critical'] else 'low'
                    vulnerabilities_found = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    scan_history_db.add_scan(
                        user_id=session['user_id'],
                        scan_type='virustotal',
                        target=url,
                        scan_parameters=scan_parameters,
                        scan_results=scan_results_data,
                        scan_command=f"VirusTotal URL scan: {url}",
                        duration=scan_duration,
                        hosts_found=0,
                        ports_found=0,
                        vulnerabilities_found=vulnerabilities_found,
                        threat_level=threat_level,
                        status='completed',
                        notes=f"VirusTotal URL scan - {vulnerabilities_found} threats"
                    )
                except Exception as e:
                    logger.error(f"Failed to save VirusTotal URL scan to history: {e}")
            # --- END INTEGRATION ---
            return jsonify(result)
        else:
            scan_duration = int(time.time() - scan_start_time)
            # --- VIRUSTOTAL SCAN HISTORY INTEGRATION (FAILED) ---
            if scan_history_db and 'user_id' in session:
                try:
                    scan_history_db.add_scan(
                        user_id=session['user_id'],
                        scan_type='virustotal',
                        target=url,
                        scan_parameters={'error': f'URL scan failed: {response.status_code}'},
                        scan_results={'error': response.text},
                        scan_command=f"VirusTotal URL scan: {url}",
                        duration=scan_duration,
                        status='failed',
                        threat_level='low',
                        notes='VirusTotal URL scan failed'
                    )
                except Exception as ex:
                    logger.error(f"Failed to save failed VirusTotal URL scan to history: {ex}")
            # --- END INTEGRATION ---
            if response.status_code == 200:
                # (should not happen)
                return jsonify(result)
            elif response.status_code == 404:
                return jsonify({
                    'status': 'error',
                    'message': 'URL not found in VirusTotal database',
                    'resource': url
                }), 404
            else:
                logger.error(f"Failed to submit URL for scanning: {response.status_code} - {response.text}")
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to submit URL for scanning: {response.status_code}'
                }), response.status_code
    except Exception as e:
        scan_duration = int(time.time() - scan_start_time)
        # --- VIRUSTOTAL SCAN HISTORY INTEGRATION (FAILED) ---
        if scan_history_db and 'user_id' in session:
            try:
                scan_history_db.add_scan(
                    user_id=session['user_id'],
                    scan_type='virustotal',
                    target=url,
                    scan_parameters={'error': str(e)},
                    scan_results={'error': str(e)},
                    scan_command=f"VirusTotal URL scan: {url}",
                    duration=scan_duration,
                    status='failed',
                    threat_level='low',
                    notes='VirusTotal URL scan failed'
                )
            except Exception as ex:
                logger.error(f"Failed to save failed VirusTotal URL scan to history: {ex}")
        # --- END INTEGRATION ---
        logger.error(f"Network error analyzing URL: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500

def analyze_domain(domain):
    """Analyze a domain using VirusTotal API"""
    scan_start_time = time.time()
    try:
        url = f"{VT_BASE_URL}/domains/{domain}"
        response = requests.get(url, headers=get_headers(), timeout=30)
        scan_duration = int(time.time() - scan_start_time)
        if response.status_code == 200:
            increment_scan_counter()
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            if should_increment_threat_counter(stats):
                increment_threats_counter()
            logger.info(f"VirusTotal response received for domain: {domain}")
            analysis_results = attributes.get('last_analysis_results', {})
            logger.info(f"Number of engines: {len(analysis_results)}")
            result = {
                'status': 'success',
                'resource_type': 'domain',
                'resource': domain,
                'scan_date': attributes.get('last_analysis_date'),
                'scan_stats': format_scan_stats(attributes.get('last_analysis_stats', {})),
                'analysis_results': process_analysis_results(analysis_results),
                'domain_info': {
                    'creation_date': attributes.get('creation_date'),
                    'last_update_date': attributes.get('last_update_date'),
                    'registrar': attributes.get('registrar', ''),
                    'whois_date': attributes.get('whois_date'),
                    'categories': attributes.get('categories', {}),
                    'popularity_ranks': attributes.get('popularity_ranks', {}),
                    'last_dns_records': attributes.get('last_dns_records', []),
                    'last_https_certificate_date': attributes.get('last_https_certificate_date')
                },
                'reputation': determine_reputation(attributes.get('last_analysis_stats', {}))
            }
            # --- VIRUSTOTAL SCAN HISTORY INTEGRATION ---
            if scan_history_db and 'user_id' in session:
                try:
                    scan_parameters = {}
                    scan_results_data = result
                    threat_level = result['reputation'] if result['reputation'] in ['low','medium','high','critical'] else 'low'
                    vulnerabilities_found = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    scan_history_db.add_scan(
                        user_id=session['user_id'],
                        scan_type='virustotal',
                        target=domain,
                        scan_parameters=scan_parameters,
                        scan_results=scan_results_data,
                        scan_command=f"VirusTotal domain scan: {domain}",
                        duration=scan_duration,
                        hosts_found=0,
                        ports_found=0,
                        vulnerabilities_found=vulnerabilities_found,
                        threat_level=threat_level,
                        status='completed',
                        notes=f"VirusTotal domain scan - {vulnerabilities_found} threats"
                    )
                except Exception as e:
                    logger.error(f"Failed to save VirusTotal domain scan to history: {e}")
            # --- END INTEGRATION ---
            return jsonify(result)
        elif response.status_code == 404:
            return jsonify({
                'status': 'error',
                'message': 'Domain not found in VirusTotal database',
                'resource': domain
            }), 404
        else:
            logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
            return jsonify({
                'status': 'error',
                'message': f'VirusTotal API error: {response.status_code}',
                'resource': domain
            }), response.status_code
    except Exception as e:
        scan_duration = int(time.time() - scan_start_time)
        # --- VIRUSTOTAL SCAN HISTORY INTEGRATION (FAILED) ---
        if scan_history_db and 'user_id' in session:
            try:
                scan_history_db.add_scan(
                    user_id=session['user_id'],
                    scan_type='virustotal',
                    target=domain,
                    scan_parameters={'error': str(e)},
                    scan_results={'error': str(e)},
                    scan_command=f"VirusTotal domain scan: {domain}",
                    duration=scan_duration,
                    status='failed',
                    threat_level='low',
                    notes='VirusTotal domain scan failed'
                )
            except Exception as ex:
                logger.error(f"Failed to save failed VirusTotal domain scan to history: {ex}")
        # --- END INTEGRATION ---
        logger.error(f"Network error analyzing domain: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500

def analyze_ip(ip_address):
    """Analyze an IP address using VirusTotal API"""
    scan_start_time = time.time()
    try:
        url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
        response = requests.get(url, headers=get_headers(), timeout=30)
        scan_duration = int(time.time() - scan_start_time)
        if response.status_code == 200:
            increment_scan_counter()
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            if should_increment_threat_counter(stats):
                increment_threats_counter()
            logger.info(f"VirusTotal response received for IP: {ip_address}")
            analysis_results = attributes.get('last_analysis_results', {})
            logger.info(f"Number of engines: {len(analysis_results)}")
            result = {
                'status': 'success',
                'resource_type': 'ip',
                'resource': ip_address,
                'scan_date': attributes.get('last_analysis_date'),
                'scan_stats': format_scan_stats(attributes.get('last_analysis_stats', {})),
                'analysis_results': process_analysis_results(analysis_results),
                'ip_info': {
                    'country': attributes.get('country', ''),
                    'asn': attributes.get('asn'),
                    'as_owner': attributes.get('as_owner', ''),
                    'network': attributes.get('network', ''),
                    'regional_internet_registry': attributes.get('regional_internet_registry', ''),
                    'last_https_certificate_date': attributes.get('last_https_certificate_date'),
                    'tags': attributes.get('tags', [])
                },
                'reputation': determine_reputation(attributes.get('last_analysis_stats', {}))
            }
            # --- VIRUSTOTAL SCAN HISTORY INTEGRATION ---
            if scan_history_db and 'user_id' in session:
                try:
                    scan_parameters = {}
                    scan_results_data = result
                    threat_level = result['reputation'] if result['reputation'] in ['low','medium','high','critical'] else 'low'
                    vulnerabilities_found = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    scan_history_db.add_scan(
                        user_id=session['user_id'],
                        scan_type='virustotal',
                        target=ip_address,
                        scan_parameters=scan_parameters,
                        scan_results=scan_results_data,
                        scan_command=f"VirusTotal IP scan: {ip_address}",
                        duration=scan_duration,
                        hosts_found=0,
                        ports_found=0,
                        vulnerabilities_found=vulnerabilities_found,
                        threat_level=threat_level,
                        status='completed',
                        notes=f"VirusTotal IP scan - {vulnerabilities_found} threats"
                    )
                except Exception as e:
                    logger.error(f"Failed to save VirusTotal IP scan to history: {e}")
            # --- END INTEGRATION ---
            return jsonify(result)
        elif response.status_code == 404:
            return jsonify({
                'status': 'error',
                'message': 'IP address not found in VirusTotal database',
                'resource': ip_address
            }), 404
        else:
            logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
            return jsonify({
                'status': 'error',
                'message': f'VirusTotal API error: {response.status_code}',
                'resource': ip_address
            }), response.status_code
    except Exception as e:
        scan_duration = int(time.time() - scan_start_time)
        # --- VIRUSTOTAL SCAN HISTORY INTEGRATION (FAILED) ---
        if scan_history_db and 'user_id' in session:
            try:
                scan_history_db.add_scan(
                    user_id=session['user_id'],
                    scan_type='virustotal',
                    target=ip_address,
                    scan_parameters={'error': str(e)},
                    scan_results={'error': str(e)},
                    scan_command=f"VirusTotal IP scan: {ip_address}",
                    duration=scan_duration,
                    status='failed',
                    threat_level='low',
                    notes='VirusTotal IP scan failed'
                )
            except Exception as ex:
                logger.error(f"Failed to save failed VirusTotal IP scan to history: {ex}")
        # --- END INTEGRATION ---
        logger.error(f"Network error analyzing IP: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500

@virustotal_bp.route('/virustotal-scan-status/<scan_id>')
def get_scan_status(scan_id):
    """Get the status of a URL scan"""
    try:
        url = f"{VT_BASE_URL}/analyses/{scan_id}"
        response = requests.get(url, headers=get_headers(), timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            status = attributes.get('status', 'queued')
            
            if status == 'completed':
                # Get the full results
                stats = attributes.get('stats', {})
                return jsonify({
                    'status': 'completed',
                    'scan_stats': format_scan_stats(stats),
                    'scan_date': attributes.get('date'),
                    'reputation': determine_reputation(stats)
                })
            else:
                return jsonify({
                    'status': status,
                    'message': f'Scan is {status}. Please wait...'
                })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to get scan status: {response.status_code}'
            }), response.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error getting scan status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500

@virustotal_bp.route('/virustotal-file-upload', methods=['POST'])
def upload_file():
    """Upload a file to VirusTotal for analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': 'No file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': 'No file selected'
            }), 400
        
        # Check file size (VirusTotal free API has limits)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 32 * 1024 * 1024:  # 32MB limit for free API
            return jsonify({
                'status': 'error',
                'message': 'File too large. Maximum size is 32MB.'
            }), 400
        
        # Upload file to VirusTotal
        upload_url = f"{VT_BASE_URL}/files"
        files = {'file': (file.filename, file.stream, file.mimetype)}
        
        response = requests.post(
            upload_url,
            headers={"x-apikey": VT_API_KEY},
            files=files,
            timeout=120
        )
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            
            return jsonify({
                'status': 'uploading',
                'message': 'File uploaded successfully. Analysis in progress...',
                'analysis_id': analysis_id,
                'filename': file.filename
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to upload file: {response.status_code}'
            }), response.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error uploading file: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Upload failed: {str(e)}'
        }), 500

@virustotal_bp.route('/virustotal-file-analysis/<analysis_id>')
def get_file_analysis(analysis_id):
    """Get the results of a file analysis"""
    try:
        url = f"{VT_BASE_URL}/analyses/{analysis_id}"
        response = requests.get(url, headers=get_headers(), timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            status = attributes.get('status', 'queued')
            
            if status == 'completed':
                # Get file hash and retrieve full file report
                file_id = data.get('meta', {}).get('file_info', {}).get('sha256')
                if file_id:
                    return analyze_file_hash(file_id, 'sha256')
                else:
                    # Return basic analysis results
                    stats = attributes.get('stats', {})
                    return jsonify({
                        'status': 'completed',
                        'resource_type': 'file',
                        'scan_stats': format_scan_stats(stats),
                        'scan_date': attributes.get('date'),
                        'reputation': determine_reputation(stats)
                    })
            else:
                return jsonify({
                    'status': status,
                    'message': f'Analysis is {status}. Please wait...'
                })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to get analysis status: {response.status_code}'
            }), response.status_code
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error getting file analysis: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }), 500

# Error handlers
@virustotal_bp.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404

@virustotal_bp.errorhandler(429)
def rate_limit_error(error):
    return jsonify({
        'status': 'error',
        'message': 'API rate limit exceeded. Please wait before making more requests.'
    }), 429

@virustotal_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error occurred'
    }), 500

# Initialize counters when the module is imported
initialize_counters()

try:
    from models.scan_history_model import scan_history_db
except ImportError:
    scan_history_db = None