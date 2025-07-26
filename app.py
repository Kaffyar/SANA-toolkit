"""
SANA Toolkit - Enhanced Main Application
Now with comprehensive scan history tracking for all scan types
"""

# Import necessary libraries
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import os    # For operating system related functionality
import datetime
import json
import re
import logging
import ipaddress
import subprocess
import time
from typing import Dict, List

# Import nmap utilities
try:
    from utils.nmap_utils import get_nmap_scanner, is_nmap_available, get_nmap_unavailable_message
except ImportError:
    # Fallback if utils module doesn't exist
    def get_nmap_scanner():
        return None
    def is_nmap_available():
        return False
    def get_nmap_unavailable_message():
        return {
            "available": False,
            "message": "Nmap is not available",
            "details": "Network scanning features require nmap to be installed locally."
        }

# Import all route blueprints
from routes.dns_recon_route import dns_recon_bp
from routes.scan_history_routes import scan_history_bp
from routes.virustotal_routes import virustotal_bp
from routes.host_discovery_routes import host_discovery_bp
from routes.auth_routes import auth_bp, login_required
from routes.settings_routes import settings_bp

# ===== FIXED: Import scan history from correct location =====
from models.scan_history_model import scan_history_db
from models.database_init import DatabaseInitializer

import secrets
from datetime import timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    # ===== Session Configuration =====
    # Use a persistent secret key to prevent session invalidation on app restart
    secret_key_file = 'secret_key.txt'
    try:
        with open(secret_key_file, 'r') as f:
            app.secret_key = f.read().strip()
    except FileNotFoundError:
        # Generate a new secret key if file doesn't exist
        app.secret_key = secrets.token_hex(32)
        with open(secret_key_file, 'w') as f:
            f.write(app.secret_key)
        logger.info("Generated new persistent secret key")
    
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'sana:'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

    # Session security settings
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(virustotal_bp)
    app.register_blueprint(dns_recon_bp)
    app.register_blueprint(scan_history_bp)
    app.register_blueprint(host_discovery_bp)
    app.register_blueprint(settings_bp)
    
    # Add context processors for templates
    @app.context_processor
    def inject_current_year():
        return {'current_year': datetime.datetime.now().year}
    
    @app.context_processor
    def inject_user_info():
        """Add user information to all templates"""
        user_info = {}
        if 'user_id' in session and session.get('authenticated'):
            try:
                from routes.auth_routes import user_manager
                user = user_manager.get_user_by_id(session['user_id'])
                if user:
                    user_info = {
                        'id': user['user_id'],
                        'email': user['email'],
                        'verified': user['is_verified'],
                        'authenticated': True
                    }
                    # Add scan history availability
                    user_info['scan_history_available'] = scan_history_db is not None
            except Exception as e:
                logger.error(f"Error getting user info for template: {e}")
        return {'user_info': user_info}
    
    return app

# Create the Flask app
app = create_app()

# Initialize nmap scanner (will be None if nmap is not available)
nm = get_nmap_scanner()

# ===== MAIN ROUTES ===== #

@app.route('/')
@login_required
def index():
    # Return the main dashboard page
    return render_template('index.html')

@app.route('/nmap')
@login_required
def nmap_scanner():
    # Return the network scanning interface page
    nmap_available = is_nmap_available()
    return render_template('nmap_scanner.html', nmap_available=nmap_available)



@app.route('/vulnerability-scanner')
@login_required
def vulnerability_scanner():
    # Return the vulnerability scanner interface page
    return render_template('vulnerability_scanner.html')

# ===== ENHANCED NETWORK SCANNING WITH HISTORY ===== #

@app.route('/nmap-scan', methods=['POST'])
@login_required
def nmap_scan():
    """Enhanced network scanning with comprehensive history tracking"""
    scan_start_time = time.time()  # Track scan duration
    
    # Check if nmap is available
    if not is_nmap_available():
        return jsonify({
            'status': 'error',
            'message': 'Nmap is not available on this system',
            'details': get_nmap_unavailable_message()
        }), 503
    
    try:
        # Get the JSON data from the request
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        
        # Extract scan parameters from the request data
        target = data.get('target', '').strip()
        scan_type = data.get('scanType', 'basic')
        timing_template = data.get('timingTemplate', 'T3')
        port_range = data.get('portRange', '')
        custom_args = data.get('customArgs', '') if scan_type == 'custom' else ''
        
        # Validate target
        if not target:
            return jsonify({
                'status': 'error',
                'message': 'Target is required'
            }), 400
        
        if not is_valid_target(target):
            return jsonify({
                'status': 'error',
                'message': 'Invalid target format'
            }), 400
        
        # Check for malicious input
        if contains_malicious_input(target):
            logger.warning(f"Malicious input detected: {target}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid characters in target'
            }), 400
        
        # ===== BUILD NMAP COMMAND ===== #
        
        # Build Nmap arguments based on user selection
        args = f'-{timing_template} '  # Add timing template to control scan speed
        
        # Add specific scan arguments based on the selected scan type
        if scan_type == 'basic':
            args += '-sV'  # Service/version detection only
        elif scan_type == 'comprehensive':
            args += '-sS -sV -sC -O'  # SYN scan + service detection + default scripts + OS detection
        elif scan_type == 'udp':
            args += '-sU -sV'  # UDP scan for detecting UDP services
        elif scan_type == 'stealth':
            args += '-sS -T2'  # SYN scan with slower timing for stealth
        elif scan_type == 'aggressive':
            args += '-sS -sV -sC -O -A'  # Aggressive scan
        elif scan_type == 'balanced':
            args += '-sV'  # Balanced scan
        elif scan_type == 'custom':
            # Sanitize custom arguments
            safe_args = sanitize_nmap_args(custom_args)
            if safe_args:
                args += safe_args
            else:
                args += '-sV'  # Default to basic if custom args are unsafe
        else:
            args += '-sV'  # Default to basic scan
        
        # Add port range if specified and valid
        if port_range and is_valid_port_range(port_range):
            args += f' -p {port_range}'
        
        # Store the command for display to the user
        nmap_command = f"nmap {args} {target}"
        
        logger.info(f"🔍 User {session['user_id']} running nmap scan: {nmap_command}")
        
        # ===== EXECUTE SCAN ===== #
        
        # Run the scan with the constructed arguments
        nm.scan(hosts=target, arguments=args)
        
        # Process results into an organized data structure
        scan_results = process_scan_results(nm)
        
        # Analyze for security issues
        security_analysis = analyze_security_issues(scan_results['hosts'])
        
        # Calculate scan metrics
        scan_end_time = time.time()
        scan_duration = int(scan_end_time - scan_start_time)
        hosts_found = scan_results['host_count']
        ports_found = scan_results['port_count']
        vulnerabilities_found = len([issue for issue in security_analysis if issue.get('severity') in ['high', 'critical']])
        
        # Determine threat level based on findings
        threat_level = determine_threat_level(security_analysis, vulnerabilities_found)
        
        # ===== SAVE TO SCAN HISTORY ===== #
        
        try:
            scan_parameters = {
                'scan_type': scan_type,
                'timing_template': timing_template,
                'port_range': port_range,
                'custom_args': custom_args
            }
            
            scan_results_data = {
                'hosts': scan_results['hosts'],
                'host_count': hosts_found,
                'port_count': ports_found,
                'security_analysis': security_analysis,
                'raw_output': str(nm.csv()) if hasattr(nm, 'csv') else ''
            }
            
            scan_id = scan_history_db.add_scan(
                user_id=session['user_id'],
                scan_type='network',
                target=target,
                scan_parameters=scan_parameters,
                scan_results=scan_results_data,
                scan_command=nmap_command,
                duration=scan_duration,
                hosts_found=hosts_found,
                ports_found=ports_found,
                vulnerabilities_found=vulnerabilities_found,
                threat_level=threat_level,
                status='completed'
            )
            
            logger.info(f"✅ Network scan saved to history: ID={scan_id}, User={session['user_id']}, Target={target}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save network scan to history: {e}")
            # Continue without failing the entire scan
        
        # ===== RETURN RESULTS ===== #
        
        # Return the scan results as JSON
        return jsonify({
            'status': 'success',
            'command': nmap_command,
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'results': scan_results['hosts'],
            'hostCount': scan_results['host_count'],
            'portCount': scan_results['port_count'],
            'security_analysis': security_analysis,
            'scan_duration': scan_duration,
            'threat_level': threat_level,
            'summary': {
                'total_hosts': scan_results['host_count'],
                'open_ports': scan_results['port_count'],
                'vulnerabilities': vulnerabilities_found,
                'scan_type': scan_type,
                'timing': timing_template,
                'duration': f"{scan_duration}s"
            }
        })
        
    except Exception as e:
        # Calculate duration even for failed scans
        scan_duration = int(time.time() - scan_start_time)
        
        # Save failed scan to history
        try:
            scan_history_db.add_scan(
                user_id=session['user_id'],
                scan_type='network',
                target=target,
                scan_parameters={'scan_type': scan_type, 'error': str(e)},
                scan_results={'error': str(e)},
                scan_command=nmap_command if 'nmap_command' in locals() else 'N/A',
                duration=scan_duration,
                status='failed',
                threat_level='low'
            )
        except:
            pass  # Don't fail on history save error
        
        # Handle any errors during the scan
        logger.error(f"❌ Nmap scan failed for user {session['user_id']}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }), 500

# ===== ENHANCED VULNERABILITY SCANNING WITH HISTORY ===== #

@app.route('/vulnerability-scan', methods=['POST'])
@login_required
def vulnerability_scan():
    """Enhanced vulnerability scanning with comprehensive history tracking"""
    import requests
    scan_start_time = time.time()
    
    # Check if nmap is available
    if not is_nmap_available():
        return jsonify({
            'status': 'error',
            'message': 'Nmap is not available on this system',
            'details': get_nmap_unavailable_message()
        }), 503
    
    try:
        # Get the JSON data from the request
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        
        # Extract scan parameters from the request data
        target = data.get('target', '').strip()
        scan_type = data.get('scanType', 'comprehensive')
        timing_template = data.get('timingTemplate', 'T3')
        port_range = data.get('portRange', '')
        
        # Validate target
        if not target:
            return jsonify({
                'status': 'error',
                'message': 'Target is required'
            }), 400
        
        if not is_valid_target(target):
            return jsonify({
                'status': 'error',
                'message': 'Invalid target format'
            }), 400
        
        # Check for malicious input
        if contains_malicious_input(target):
            logger.warning(f"Malicious input detected: {target}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid characters in target'
            }), 400
        
        # Vulners API key
        vulners_api_key = "HBFQYNTC80EGFXVUSIKNP411NCUDZ0ZGLR8CVQX7KYO8U9FM7Y3Q5E1QF2IDNA39"
        
        # Build Nmap arguments with vulnerability scripts
        args = f'-{timing_template} -sV'
        
        # Add port range if specified and valid
        if port_range and is_valid_port_range(port_range):
            args += f' -p {port_range}'
        
        # Add scan type specific arguments
        if scan_type == 'comprehensive':
            args += ' -A --script=vuln,auth,default'
        elif scan_type == 'web':
            args += ' -p 80,443,8080,8443 --script=http-vuln-*,http-enum'
        elif scan_type == 'basic':
            args += ' --script=vuln --script-args=vulns.showall=on'
        
        # Add the vulners script
        args += ' --script=vulners'
        
        # Store the command for display
        nmap_command = f"nmap {args} {target}"
        logger.info(f"🔍 User {session['user_id']} running vulnerability scan: {nmap_command}")
        
        # Initialize results structure
        results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'scan_type': scan_type,
            'services_scanned': 0,
            'vulnerabilities': []
        }
        
        # Run the scan with the constructed arguments
        nm.scan(hosts=target, arguments=args)
        
        # Process results to find services and vulnerabilities
        services_found = []
        vulnerabilities_count = 0
        
        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                for port in ports:
                    port_info = nm[host][protocol][port]
                    
                    if port_info['state'] == 'open':
                        service = {
                            'host': host,
                            'port': port,
                            'protocol': protocol,
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        services_found.append(service)
                        
                        # Check for script results (vulnerabilities)
                        if 'script' in port_info:
                            for script_name, script_output in port_info['script'].items():
                                if 'vuln' in script_name.lower() or 'cve' in script_output.lower():
                                    vulnerability = {
                                        'host': host,
                                        'port': port,
                                        'service': port_info.get('name', 'unknown'),
                                        'script': script_name,
                                        'description': script_output,
                                        'severity': determine_vuln_severity(script_output),
                                        'cve_ids': extract_cve_ids(script_output)
                                    }
                                    results['vulnerabilities'].append(vulnerability)
                                    vulnerabilities_count += 1
        
        results['services_scanned'] = len(services_found)
        
        # Calculate scan metrics
        scan_end_time = time.time()
        scan_duration = int(scan_end_time - scan_start_time)
        threat_level = determine_threat_level_vuln(results['vulnerabilities'])
        
        # ===== SAVE TO SCAN HISTORY ===== #
        
        try:
            scan_parameters = {
                'scan_type': scan_type,
                'timing_template': timing_template,
                'port_range': port_range,
                'vulners_api_used': True
            }
            
            scan_results_data = {
                'services_found': services_found,
                'vulnerabilities': results['vulnerabilities'],
                'services_scanned': results['services_scanned'],
                'raw_output': str(nm.csv()) if hasattr(nm, 'csv') else ''
            }
            
            scan_id = scan_history_db.add_scan(
                user_id=session['user_id'],
                scan_type='network',  # Vulnerability scan is a type of network scan
                target=target,
                scan_parameters=scan_parameters,
                scan_results=scan_results_data,
                scan_command=nmap_command,
                duration=scan_duration,
                hosts_found=len(set([vuln['host'] for vuln in results['vulnerabilities']])),
                ports_found=len(services_found),
                vulnerabilities_found=vulnerabilities_count,
                threat_level=threat_level,
                status='completed',
                notes=f"Vulnerability scan - {vulnerabilities_count} vulnerabilities found"
            )
            
            logger.info(f"✅ Vulnerability scan saved to history: ID={scan_id}, User={session['user_id']}, Vulns={vulnerabilities_count}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save vulnerability scan to history: {e}")
        
        # Log final count
        logger.info(f"Total vulnerabilities found: {len(results['vulnerabilities'])}")
        
        # Return results
        return jsonify({
            'status': 'success',
            'nmap_command': nmap_command,
            'results': results,
            'scan_duration': scan_duration,
            'threat_level': threat_level,
            'summary': {
                'services_scanned': results['services_scanned'],
                'vulnerabilities_found': vulnerabilities_count,
                'threat_level': threat_level,
                'duration': f"{scan_duration}s"
            }
        })
        
    except Exception as e:
        # Calculate duration for failed scans
        scan_duration = int(time.time() - scan_start_time)
        
        # Save failed scan to history
        try:
            scan_history_db.add_scan(
                user_id=session['user_id'],
                scan_type='network',
                target=target if 'target' in locals() else 'unknown',
                scan_parameters={'scan_type': 'vulnerability', 'error': str(e)},
                scan_results={'error': str(e)},
                scan_command=nmap_command if 'nmap_command' in locals() else 'N/A',
                duration=scan_duration,
                status='failed',
                threat_level='low'
            )
        except:
            pass
        
        # Handle any errors
        logger.error(f"❌ Vulnerability scan failed for user {session['user_id']}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Vulnerability scan failed: {str(e)}'
        }), 500

# ===== HELPER FUNCTIONS ===== #

def determine_threat_level(security_analysis, vulnerabilities_found):
    """Determine threat level based on scan results"""
    if vulnerabilities_found >= 5:
        return 'critical'
    elif vulnerabilities_found >= 3:
        return 'high' 
    elif vulnerabilities_found >= 1:
        return 'medium'
    else:
        return 'low'

def determine_threat_level_vuln(vulnerabilities):
    """Determine threat level based on vulnerability severity"""
    critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
    high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
    
    if critical_count > 0:
        return 'critical'
    elif high_count >= 3:
        return 'high'
    elif high_count >= 1 or len(vulnerabilities) >= 3:
        return 'medium'
    else:
        return 'low'

def determine_vuln_severity(script_output):
    """Determine vulnerability severity from script output"""
    if any(keyword in script_output.lower() for keyword in ['critical', 'rce', 'remote code execution']):
        return 'critical'
    elif any(keyword in script_output.lower() for keyword in ['high', 'dangerous', 'exploit']):
        return 'high'
    elif any(keyword in script_output.lower() for keyword in ['medium', 'moderate']):
        return 'medium'
    else:
        return 'low'

def extract_cve_ids(text):
    """Extract CVE IDs from text"""
    import re
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, text.upper())

# ===== EXISTING HELPER FUNCTIONS ===== #

def is_valid_target(target):
    """Validate if the target is a valid IP address, hostname, or network range"""
    try:
        # Check if it's a valid IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    try:
        # Check if it's a valid network (CIDR notation)
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid hostname/domain name
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(hostname_pattern.match(target))

def contains_malicious_input(input_string):
    """Check for potentially malicious input that could be used for command injection"""
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '>', '<', '*', '?']
    dangerous_keywords = ['rm ', 'del ', 'format', 'shutdown', 'reboot', 'kill', 'python', 'bash', 'sh ', 'cmd', 'powershell']
    
    # Check for dangerous characters
    for char in dangerous_chars:
        if char in input_string:
            return True
    
    # Check for dangerous keywords
    for keyword in dangerous_keywords:
        if keyword.lower() in input_string.lower():
            return True
    
    return False

def is_valid_port_range(port_range):
    """Validate port range format"""
    if not port_range:
        return True
    
    # Allow individual ports (80), ranges (80-443), and lists (80,443,8080)
    port_pattern = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$')
    return bool(port_pattern.match(port_range))

def sanitize_nmap_args(args):
    """Sanitize custom nmap arguments"""
    if not args:
        return ''
    
    # Remove potentially dangerous arguments
    dangerous_args = ['-oN', '-oX', '-oG', '--script=', '--script-args=', '-iL']
    sanitized = args
    
    for dangerous in dangerous_args:
        if dangerous in sanitized:
            return ''  # Return empty if dangerous args found
    
    return sanitized

def process_scan_results(nm):
    """Process nmap scan results into organized structure"""
    results = {
        'hosts': [],
        'host_count': 0,
        'port_count': 0
    }
    
    total_ports = 0
    
    for host in nm.all_hosts():
        host_info = {
            'ip': host,
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': {},
            'os': []  # Add OS field to store OS detection results
        }
        
        # Extract OS information if available
        if 'osmatch' in nm[host]:
            for os_match in nm[host]['osmatch']:
                host_info['os'].append({
                    'name': os_match.get('name', 'Unknown'),
                    'accuracy': os_match.get('accuracy', '0')
                })
        
        for protocol in nm[host].all_protocols():
            ports = nm[host][protocol].keys()
            host_info['protocols'][protocol] = []
            
            for port in ports:
                port_info = nm[host][protocol][port]
                if port_info['state'] == 'open':
                    host_info['protocols'][protocol].append({
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    })
                    total_ports += 1
        
        results['hosts'].append(host_info)
    
    results['host_count'] = len(results['hosts'])
    results['port_count'] = total_ports
    
    return results

def analyze_security_issues(hosts):
    """Analyze hosts for potential security issues"""
    security_issues = []
    
    for host in hosts:
        for protocol, ports in host['protocols'].items():
            for port_info in ports:
                # Check for common vulnerable services
                service = port_info['service'].lower()
                port = port_info['port']
                
                if service in ['telnet', 'ftp', 'rsh', 'rlogin']:
                    security_issues.append({
                        'host': host['ip'],
                        'port': port,
                        'service': service,
                        'issue': 'Insecure protocol detected',
                        'severity': 'high',
                        'description': f'{service.upper()} transmits data in plaintext'
                    })
                
                elif service == 'ssh' and port != 22:
                    security_issues.append({
                        'host': host['ip'],
                        'port': port,
                        'service': service,
                        'issue': 'SSH on non-standard port',
                        'severity': 'medium',
                        'description': 'SSH running on non-standard port may indicate security through obscurity'
                    })
    
    return security_issues

# ===== DASHBOARD ROUTES ===== #

@app.route('/scan-count')
@login_required
def get_scan_count():
    """Get total scan count for current user"""
    try:
        if scan_history_db:
            count = scan_history_db.get_scan_count(session['user_id'])
            return jsonify({'count': count})
        else:
            return jsonify({'count': 0, 'error': 'Scan history not available'})
    except Exception as e:
        logger.error(f"Failed to get scan count: {e}")
        return jsonify({'count': 0, 'error': str(e)})

@app.route('/dashboard-stats')
@login_required 
def get_dashboard_stats():
    """Get dashboard statistics for the main page"""
    try:
        if not scan_history_db:
            return jsonify({
                'total_scans': 0,
                'recent_scans': 0,
                'threats_found': 0,
                'hosts_discovered': 0
            })
        
        user_id = session['user_id']
        
        # Get overall stats
        total_scans = scan_history_db.get_scan_count(user_id)
        
        # Get recent scans (last 7 days)
        recent_scans = scan_history_db.get_user_scans(
            user_id, 
            filters={'date_from': (datetime.datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')},
            limit=100
        )
        
        # Calculate stats
        threats_found = sum(scan.get('vulnerabilities_found', 0) for scan in recent_scans)
        hosts_discovered = sum(scan.get('hosts_found', 0) for scan in recent_scans)
        ports_found = sum(scan.get('ports_found', 0) for scan in recent_scans)
        
        return jsonify({
            'total_scans': total_scans,
            'recent_scans': len(recent_scans),
            'threats_found': threats_found,
            'hosts_discovered': hosts_discovered,
            'ports_found': ports_found
        })
        
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {e}")
        return jsonify({
            'total_scans': 0,
            'recent_scans': 0, 
            'threats_found': 0,
            'hosts_discovered': 0,
            'ports_found': 0,
            'error': str(e)
        })

@app.route('/check_privileges')
@login_required
def check_privileges():
    """Check if the application has sufficient privileges to run nmap"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return jsonify({
                'elevated': ctypes.windll.shell32.IsUserAnAdmin() != 0,
                'platform': 'windows'
            })
        else:  # Unix-like operating systems
            uid = os.getuid() if hasattr(os, 'getuid') else 1000
            return jsonify({
                'elevated': uid == 0,
                'platform': 'unix',
                'uid': uid
            })
    except Exception as e:
        return jsonify({
            'elevated': False,
            'error': str(e)
        })

# ===== AUTHENTICATION ROUTES ===== #

@app.route('/welcome')
def welcome():
    """Landing page that redirects to login or dashboard"""
    if 'user_id' in session and session.get('authenticated'):
        return redirect(url_for('index'))
    else:
        return redirect(url_for('auth.login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with security features"""
    return render_template('dashboard.html')

@app.route('/check-auth')
def check_auth_status():
    """Check if user is authenticated"""
    if 'user_id' in session and session.get('authenticated'):
        return jsonify({'authenticated': True})
    return jsonify({'authenticated': False}), 401

@app.before_request
def require_login():
    """Redirect unauthenticated users to login page"""
    # Allow access to auth routes and static files
    allowed_paths = ['/auth/', '/static/', '/check-auth']
    if any(request.path.startswith(path) for path in allowed_paths):
        return
    # Check if user is authenticated for protected routes
    if 'user_id' not in session or not session.get('authenticated'):
        if request.is_json:
            return jsonify({'error': 'Authentication required', 'redirect': '/auth/login'}), 401
        return redirect(url_for('auth.login'))

# ===== STARTUP INITIALIZATION ===== #

if __name__ == '__main__':
    try:
        db_init = DatabaseInitializer()
        if db_init.initialize_database():
            logger.info("✅ Database initialized successfully")
        else:
            logger.warning("⚠️  Database initialization failed")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}")
    
    # Railway deployment configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Start the web server
    app.run(host='0.0.0.0', port=port, debug=debug)