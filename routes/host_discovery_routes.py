"""
SANA Toolkit - Enhanced Host Discovery Routes
Advanced host discovery functionality with comprehensive network scanning + Scan History Integration
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect
import nmap
import ipaddress
import re
import logging
import json
import time
import threading
import subprocess
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import os

# ===== NEW: Import authentication and scan history =====
try:
    from routes.auth_routes import login_required
    from models.scan_history_model import scan_history_db
except ImportError:
    # Fallback for testing
    def login_required(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/auth/login')
            return f(*args, **kwargs)
        return decorated_function

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create blueprint
host_discovery_bp = Blueprint('host_discovery', __name__)

# Global nmap scanner instance
nm = nmap.PortScanner()

# Active discovery sessions
active_discoveries = {}

# Discovery statistics
discovery_stats = {
    'total_discoveries': 0,
    'total_hosts_found': 0,
    'total_networks_scanned': 0
}

# ===== HELPER FUNCTIONS ===== #

def initialize_discovery_counters():
    """Initialize discovery counter files if they don't exist"""
    try:
        counter_files = [
            'discovery_counter.txt',
            'hosts_found_counter.txt', 
            'networks_scanned_counter.txt'
        ]
        
        for counter_file in counter_files:
            if not os.path.exists(counter_file):
                with open(counter_file, 'w') as f:
                    f.write('0')
        
        logger.info("Discovery counter files initialized")
    except Exception as e:
        logger.error(f"Failed to initialize discovery counters: {str(e)}")

def increment_discovery_counter():
    """Increment the discovery counter"""
    try:
        current_count = get_total_discoveries_performed()
        new_count = current_count + 1
        
        with open('discovery_counter.txt', 'w') as f:
            f.write(str(new_count))
        
        discovery_stats['total_discoveries'] = new_count
        logger.info(f"Discovery counter incremented to: {new_count}")
        return new_count
    except Exception as e:
        logger.error(f"Failed to increment discovery counter: {str(e)}")
        return 0

def get_total_discoveries_performed():
    """Get total number of discoveries performed"""
    try:
        if os.path.exists('discovery_counter.txt'):
            with open('discovery_counter.txt', 'r') as f:
                return int(f.read().strip() or 0)
        return 0
    except:
        return 0

def increment_hosts_found_counter(count):
    """Increment the hosts found counter"""
    try:
        current_count = get_total_hosts_found()
        new_count = current_count + count
        
        with open('hosts_found_counter.txt', 'w') as f:
            f.write(str(new_count))
        
        discovery_stats['total_hosts_found'] = new_count
        logger.info(f"Hosts found counter incremented by {count} to: {new_count}")
        return new_count
    except Exception as e:
        logger.error(f"Failed to increment hosts found counter: {str(e)}")
        return 0

def get_total_hosts_found():
    """Get total number of hosts found"""
    try:
        if os.path.exists('hosts_found_counter.txt'):
            with open('hosts_found_counter.txt', 'r') as f:
                return int(f.read().strip() or 0)
        return 0
    except:
        return 0

def is_valid_network_range(target: str) -> bool:
    """Validate network range input"""
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    
    try:
        # Single IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    try:
        # CIDR notation (e.g., 192.168.1.0/24)
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # IP range (e.g., 192.168.1.1-254)
    if '-' in target:
        parts = target.split('-')
        if len(parts) == 2:
            try:
                base_ip = parts[0].strip()
                end_octet = parts[1].strip()
                
                # Validate base IP
                ipaddress.ip_address(base_ip)
                
                # Validate end octet (must be 0-255)
                if end_octet.isdigit() and 0 <= int(end_octet) <= 255:
                    return True
            except ValueError:
                pass
    
    # Hostname validation
    hostname_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return hostname_pattern.match(target) is not None

def is_valid_port_range(port_range: str) -> bool:
    """Validate port range format"""
    if not port_range:
        return True  # Empty is valid (optional)
    
    port_range = port_range.strip()
    
    # Common keywords
    if port_range.lower() in ['top-ports', 'common', 'default']:
        return True
    
    # Single port or comma-separated ports
    if re.match(r'^\d{1,5}(?:,\d{1,5})*$', port_range):
        ports = [int(p.strip()) for p in port_range.split(',')]
        return all(1 <= port <= 65535 for port in ports)
    
    # Port range (e.g., 1-1000)
    range_match = re.match(r'^(\d{1,5})-(\d{1,5})$', port_range)
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        return 1 <= start <= end <= 65535
    
    return False

def contains_malicious_input(target: str) -> bool:
    """Check for command injection attempts in network target"""
    if not target:
        return False
    
    malicious_patterns = [
        r'[;&|`$()]',     # Command injection characters
        r'\.\./',         # Directory traversal
        r'<script',       # XSS attempts
        r'exec\(',        # Code execution
        r'eval\(',        # Code evaluation
        r'system\(',      # System calls
        r'rm\s+',         # Delete commands
        r'cat\s+',        # File reading
        r'wget\s+',       # Download commands
        r'curl\s+',       # HTTP requests
        r'nc\s+',         # Netcat
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, target, re.IGNORECASE):
            return True
    return False

def is_private_network(target: str) -> bool:
    """Check if target is in private network range"""
    try:
        # Extract base IP from target
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return network.is_private
        elif '-' in target:
            base_ip = target.split('-')[0].strip()
            return ipaddress.ip_address(base_ip).is_private
        else:
            return ipaddress.ip_address(target).is_private
    except:
        return False

def estimate_total_hosts(target: str) -> int:
    """Estimate total number of hosts in target range"""
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return network.num_addresses - 2  # Subtract network and broadcast
        elif '-' in target:
            parts = target.split('-')
            if len(parts) == 2:
                start_octet = int(parts[0].split('.')[-1])
                end_octet = int(parts[1])
                return max(0, end_octet - start_octet + 1)
        return 1  # Single host
    except:
        return 1

def sanitize_nmap_args(args: str) -> str:
    """Sanitize nmap arguments to prevent command injection"""
    if not args:
        return ""
    
    # Remove dangerous arguments
    dangerous_args = [
        '--script=.*exec.*',
        '--script=.*file.*',
        '--script=.*backdoor.*',
        '--script=.*vuln.*',
        '--privileged',
        '--reason',
        '--packet-trace',
        '--debug',
        '--data-string',
        '--data-length'
    ]
    
    sanitized = args
    for dangerous in dangerous_args:
        sanitized = re.sub(dangerous, '', sanitized, flags=re.IGNORECASE)
    
    # Only allow safe characters and arguments
    allowed_pattern = r'^[-a-zA-Z0-9\s._/,:]+$'
    if not re.match(allowed_pattern, sanitized):
        return ""
    
    return sanitized.strip()

def expand_network_range(target: str) -> List[str]:
    """Expand network range to individual IPs for estimation"""
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in list(network.hosts())[:1000]]  # Limit for performance
        elif '-' in target:
            parts = target.split('-')
            base_ip = parts[0].strip()
            end_octet = int(parts[1].strip())
            
            base_parts = base_ip.split('.')
            start_octet = int(base_parts[3])
            
            ips = []
            for i in range(start_octet, min(end_octet + 1, 256)):
                ip = '.'.join(base_parts[:3] + [str(i)])
                ips.append(ip)
            return ips
        else:
            return [target]
    except:
        return [target]

def build_nmap_command(data: Dict) -> str:
    """Build nmap command based on discovery configuration"""
    target = data['targetNetwork']
    discovery_method = data['discoveryMethod']
    timing_template = data['timingTemplate']
    port_range = data.get('portRange', '')
    resolve_hostnames = data.get('resolveHostnames', False)
    detect_os = data.get('detectOS', False)
    vendor_detection = data.get('vendorDetection', False)
    
    # Start with timing template
    args = f'-{timing_template} '
    
    # Add discovery method specific arguments
    if discovery_method == 'ping-sweep':
        args += '-sn '  # Ping sweep only
    elif discovery_method == 'arp-scan':
        args += '-sn --send-ip '  # ARP scan
    elif discovery_method == 'tcp-connect':
        args += '-sT '  # TCP connect scan
        if port_range and is_valid_port_range(port_range):
            args += f'-p {port_range} '
    elif discovery_method == 'udp-discovery':
        args += '-sU --top-ports 100 '  # UDP discovery
    elif discovery_method == 'comprehensive':
        args += '-sn -PS -PA -PU '  # Multiple discovery techniques
    else:
        args += '-sn '  # Default to ping sweep
    
    # Additional options
    if not resolve_hostnames:
        args += '-n '  # No DNS resolution
    
    if detect_os:
        args += '-O '  # OS detection
    
    if vendor_detection:
        args += '--script=mac-lookup '  # MAC vendor lookup
    
    # Always include these for better results
    args += '--max-retries 1 --host-timeout 30s '
    
    return f"nmap {args.strip()} {target}"

def execute_host_discovery(data: Dict, discovery_id: str) -> Dict:
    """Execute host discovery scan using nmap"""
    try:
        logger.info(f"Starting host discovery {discovery_id} with target: {data['targetNetwork']}")
        
        # Build nmap command
        nmap_command = build_nmap_command(data)
        logger.info(f"Executing command: {nmap_command}")
        
        # Update discovery session
        if discovery_id in active_discoveries:
            active_discoveries[discovery_id]['status'] = 'scanning'
            active_discoveries[discovery_id]['command'] = nmap_command
        
        # Extract nmap arguments (remove 'nmap' and target)
        command_parts = nmap_command.split()
        args = ' '.join(command_parts[1:-1])  # Everything except 'nmap' and target
        target = command_parts[-1]
        
        # Execute nmap scan
        start_time = time.time()
        
        # Update progress to scanning
        if discovery_id in active_discoveries:
            active_discoveries[discovery_id]['progress'] = 25
            active_discoveries[discovery_id]['status'] = 'scanning'
        
        nm.scan(hosts=target, arguments=args)
        
        # Update progress to processing
        if discovery_id in active_discoveries:
            active_discoveries[discovery_id]['progress'] = 75
        
        end_time = time.time()
        
        # Process results
        results = process_discovery_results(nm, data, start_time, end_time)
        results['command'] = nmap_command
        results['discovery_id'] = discovery_id
        
        # Update progress to complete
        if discovery_id in active_discoveries:
            active_discoveries[discovery_id]['progress'] = 100
            active_discoveries[discovery_id]['status'] = 'completed'
            active_discoveries[discovery_id]['results'] = results
        
        # Update counters
        increment_discovery_counter()
        increment_hosts_found_counter(results['hostCount'])
        
        logger.info(f"Host discovery {discovery_id} completed. Found {results['hostCount']} hosts.")
        
        return results
        
    except Exception as e:
        logger.error(f"Error during host discovery {discovery_id}: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'hostCount': 0,
            'hosts': [],
            'discovery_id': discovery_id
        }

def process_discovery_results(nm_result, data: Dict, start_time: float, end_time: float) -> Dict:
    """Process nmap discovery results into structured data"""
    hosts = []
    host_count = 0
    
    for host in nm_result.all_hosts():
        try:
            host_info = {
                'ip': host,
                'hostname': '',
                'status': nm_result[host].state(),
                'mac_address': '',
                'vendor': '',
                'os_info': {},
                'open_ports': [],
                'services': []
            }
            
            # Get hostname if available
            if nm_result[host].hostname():
                host_info['hostname'] = nm_result[host].hostname()
            
            # Get MAC address and vendor info
            if 'mac' in nm_result[host]['addresses']:
                host_info['mac_address'] = nm_result[host]['addresses']['mac']
                if 'vendor' in nm_result[host] and nm_result[host]['vendor']:
                    host_info['vendor'] = list(nm_result[host]['vendor'].values())[0]
            
            # Get OS information if available
            if 'osmatch' in nm_result[host]:
                os_matches = nm_result[host]['osmatch']
                if os_matches:
                    best_match = os_matches[0]
                    host_info['os_info'] = {
                        'name': best_match.get('name', ''),
                        'accuracy': best_match.get('accuracy', 0),
                        'line': best_match.get('line', 0)
                    }
            
            # Get open ports and services
            for protocol in nm_result[host].all_protocols():
                ports = nm_result[host][protocol].keys()
                for port in ports:
                    port_info = nm_result[host][protocol][port]
                    if port_info['state'] == 'open':
                        host_info['open_ports'].append(port)
                        host_info['services'].append({
                            'port': port,
                            'protocol': protocol,
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
            
            hosts.append(host_info)
            if host_info['status'] == 'up':
                host_count += 1
                
        except Exception as e:
            logger.warning(f"Error processing host {host}: {str(e)}")
            continue
    
    # Calculate total ports scanned (estimate based on common port ranges)
    total_ports_scanned = 0
    if data.get('discoveryMethod') == 'comprehensive':
        total_ports_scanned = 1000  # Common ports
    elif data.get('discoveryMethod') == 'quick':
        total_ports_scanned = 100   # Top ports
    else:
        total_ports_scanned = 500   # Default
    
    return {
        'status': 'completed',
        'targetNetwork': data['targetNetwork'],
        'discoveryMethod': data['discoveryMethod'],
        'timingTemplate': data['timingTemplate'],
        'startTime': start_time,
        'endTime': end_time,
        'duration': round(end_time - start_time, 2),
        'hostCount': host_count,
        'totalHosts': len(hosts),
        'totalPortsScanned': total_ports_scanned * len(hosts),  # Ports per host
        'openPortsCount': sum(len(h['open_ports']) for h in hosts),
        'hosts': hosts,
        'statistics': {
            'alive_hosts': host_count,
            'total_scanned': len(hosts),
            'response_rate': round((host_count / len(hosts) * 100) if hosts else 0, 1),
            'ports_found': sum(len(h['open_ports']) for h in hosts),
            'services_identified': sum(len(h['services']) for h in hosts),
            'total_ports_scanned': total_ports_scanned * len(hosts)
        }
    }

def get_discovery_recommendations(target: str) -> Dict:
    """Get discovery recommendations based on target"""
    recommendations = {
        'recommended_method': 'comprehensive',
        'recommended_timing': 'T3',
        'estimated_duration': '1-5 minutes',
        'notes': []
    }
    
    try:
        # Check if it's a private network
        if is_private_network(target):
            recommendations['recommended_method'] = 'arp-scan'
            recommendations['recommended_timing'] = 'T4'
            recommendations['estimated_duration'] = '30 seconds - 2 minutes'
            recommendations['notes'].append('Private network detected - ARP scan recommended for fast discovery')
        else:
            recommendations['recommended_method'] = 'ping-sweep'
            recommendations['recommended_timing'] = 'T2'
            recommendations['estimated_duration'] = '2-10 minutes'
            recommendations['notes'].append('External network detected - slower timing recommended')
        
        # Estimate host count
        estimated_hosts = estimate_total_hosts(target)
        if estimated_hosts > 100:
            recommendations['notes'].append(f'Large network detected (~{estimated_hosts} hosts) - scan may take longer')
        
    except Exception as e:
        logger.warning(f"Failed to generate recommendations: {str(e)}")
    
    return recommendations

def cleanup_old_discoveries():
    """Clean up old discovery sessions"""
    current_time = time.time()
    expired_sessions = []
    
    for discovery_id, session in active_discoveries.items():
        if current_time - session['start_time'] > 3600:  # 1 hour timeout
            expired_sessions.append(discovery_id)
    
    for discovery_id in expired_sessions:
        del active_discoveries[discovery_id]
        logger.info(f"Cleaned up expired discovery session: {discovery_id}")

# ===== NEW: Determine threat level for host discovery ===== #

def determine_discovery_threat_level(results: Dict) -> str:
    """Determine threat level based on host discovery results"""
    if not results or results.get('status') != 'completed':
        return 'low'
    
    hosts = results.get('hosts', [])
    if not hosts:
        return 'low'
    
    # Calculate risk factors
    total_open_ports = sum(len(host.get('open_ports', [])) for host in hosts)
    hosts_with_services = sum(1 for host in hosts if host.get('services'))
    alive_hosts = results.get('hostCount', 0)
    
    # Risk assessment
    if total_open_ports > 50 or hosts_with_services > 10:
        return 'high'
    elif total_open_ports > 20 or hosts_with_services > 5:
        return 'medium'
    elif alive_hosts > 0:
        return 'low'
    else:
        return 'low'

# ===== ROUTES ===== #

@host_discovery_bp.route('/host-discovery')
@login_required  # ✅ NEW: Added authentication
def host_discovery_page():
    """Render the host discovery page"""
    try:
        # Initialize counters if needed
        initialize_discovery_counters()
        
        # Clean up old sessions
        cleanup_old_discoveries()
        
        # Get current statistics
        context = {
            'total_discoveries': get_total_discoveries_performed(),
            'total_hosts_found': get_total_hosts_found(),
            'active_sessions': len(active_discoveries),
            'page_title': 'Host Discovery',
            'current_year': datetime.now().year
        }
        
        return render_template('host_discovery.html', **context)
        
    except Exception as e:
        logger.error(f"Error rendering host discovery page: {str(e)}")
        return render_template('host_discovery.html', error="Failed to load page")

@host_discovery_bp.route('/host-discovery', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def start_host_discovery():
    scan_start_time = time.time()  # ✅ NEW: Track scan duration
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400
        # Extract and validate parameters
        target_network = data.get('targetNetwork', '').strip()
        discovery_method = data.get('discoveryMethod', 'comprehensive')
        timing_template = data.get('timingTemplate', 'T3')
        port_range = data.get('portRange', '')
        resolve_hostnames = data.get('resolveHostnames', True)
        detect_os = data.get('detectOS', False)
        vendor_detection = data.get('vendorDetection', False)
        # Validate required fields
        if not target_network:
            return jsonify({
                'status': 'error',
                'message': 'Target network is required'
            }), 400
        if not is_valid_network_range(target_network):
            return jsonify({
                'status': 'error',
                'message': 'Invalid network range format'
            }), 400
        # Check for malicious input
        if contains_malicious_input(target_network):
            logger.warning(f"Malicious input detected from user {session['user_id']}: {target_network}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid characters in target network'
            }), 400
        # ✅ NEW: Log user activity
        user_id = session['user_id']  # Capture user_id here
        logger.info(f"🔍 User {user_id} starting host discovery: {target_network}")
        # Create discovery session
        discovery_id = f"discovery_{int(time.time())}_{hash(target_network) % 10000}"
        active_discoveries[discovery_id] = {
            'user_id': user_id,  # ✅ NEW: Track user
            'target': target_network,
            'method': discovery_method,
            'start_time': time.time(),
            'status': 'initializing',
            'progress': 0
        }
        # Start discovery in background thread
        def run_discovery(user_id):
            try:
                # Execute the discovery
                results = execute_host_discovery(data, discovery_id)
                # Update session with results
                if discovery_id in active_discoveries:
                    active_discoveries[discovery_id]['status'] = 'completed'
                    active_discoveries[discovery_id]['results'] = results
                    active_discoveries[discovery_id]['progress'] = 100
                    logger.info(f"✅ Discovery {discovery_id} completed and stored with {len(results.get('hosts', []))} hosts")
                else:
                    logger.error(f"❌ Discovery {discovery_id} not found in active_discoveries when trying to store results")
                # ===== NEW: SAVE TO SCAN HISTORY ===== #
                try:
                    scan_end_time = time.time()
                    scan_duration = int(scan_end_time - scan_start_time)
                    # Extract metrics from results
                    hosts_found = results.get('hostCount', 0)
                    total_ports = results.get('statistics', {}).get('ports_found', 0)
                    services_found = results.get('statistics', {}).get('services_identified', 0)
                    # Determine threat level
                    threat_level = determine_discovery_threat_level(results)
                    # Prepare scan parameters
                    scan_parameters = {
                        'discovery_method': discovery_method,
                        'timing_template': timing_template,
                        'port_range': port_range,
                        'resolve_hostnames': resolve_hostnames,
                        'detect_os': detect_os,
                        'vendor_detection': vendor_detection,
                        'target_network': target_network
                    }
                    # Prepare scan results
                    scan_results_data = {
                        'discovery_results': results,
                        'hosts_found': hosts_found,
                        'total_ports': total_ports,
                        'services_found': services_found,
                        'statistics': results.get('statistics', {}),
                        'nmap_command': results.get('command', '')
                    }
                    # Save to scan history
                    scan_id = scan_history_db.add_scan(
                        user_id=user_id,
                        scan_type='host_discovery',
                        target=target_network,
                        scan_parameters=scan_parameters,
                        scan_results=scan_results_data,
                        scan_command=results.get('command', f"Host discovery ({discovery_method})"),
                        duration=scan_duration,
                        hosts_found=hosts_found,
                        ports_found=total_ports,
                        vulnerabilities_found=0,  # Host discovery doesn't check vulnerabilities
                        threat_level=threat_level,
                        status='completed' if results.get('status') == 'completed' else 'failed',
                        notes=f"Host discovery - {hosts_found} hosts found using {discovery_method}"
                    )
                    logger.info(f"✅ Host discovery saved to history: ID={scan_id}, User={user_id}, Target={target_network}")
                except Exception as e:
                    logger.error(f"❌ Failed to save host discovery to history: {e}")
            except Exception as e:
                logger.error(f"Discovery thread error: {str(e)}")
                if discovery_id in active_discoveries:
                    active_discoveries[discovery_id]['status'] = 'error'
                    active_discoveries[discovery_id]['error'] = str(e)
                # ✅ NEW: Save failed scan to history
                try:
                    scan_duration = int(time.time() - scan_start_time)
                    scan_history_db.add_scan(
                        user_id=user_id,
                        scan_type='host_discovery',
                        target=target_network,
                        scan_parameters={'error': str(e)},
                        scan_results={'error': str(e)},
                        scan_command='Host discovery (failed)',
                        duration=scan_duration,
                        status='failed',
                        threat_level='low'
                    )
                except:
                    pass
        discovery_thread = threading.Thread(target=run_discovery, args=(user_id,))
        discovery_thread.daemon = True
        discovery_thread.start()
        return jsonify({
            'status': 'success',
            'message': 'Host discovery started',
            'discovery_id': discovery_id,
            'estimated_duration': get_discovery_recommendations(target_network)['estimated_duration']
        })
    except Exception as e:
        logger.error(f"❌ Host discovery failed for user {session['user_id']}: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to start discovery: {str(e)}'
        }), 500

@host_discovery_bp.route('/host-discovery/status/<discovery_id>')
@login_required  # ✅ NEW: Added authentication
def get_discovery_status(discovery_id):
    """Get the status of a host discovery scan"""
    try:
        if discovery_id not in active_discoveries:
            return jsonify({
                'status': 'error',
                'message': 'Discovery session not found'
            }), 404
        
        session_data = active_discoveries[discovery_id]
        
        # ✅ NEW: Check user ownership of discovery session
        if session_data.get('user_id') != session['user_id']:
            return jsonify({
                'status': 'error',
                'message': 'Access denied'
            }), 403
        
        # ADD DEBUGGING
        logger.info(f"🔍 Discovery status for {discovery_id}: {session_data['status']}")
        if 'results' in session_data:
            logger.info(f"🔍 Results available: {len(session_data['results'].get('hosts', []))} hosts")
        
        response_data = {
            'status': session_data['status'],
            'progress': session_data['progress'],
            'target': session_data['target'],
            'method': session_data['method'],
            'start_time': session_data['start_time'],
            'elapsed_time': round(time.time() - session_data['start_time'], 1)
        }
        
        if session_data['status'] == 'completed' and 'results' in session_data:
            response_data['results'] = session_data['results']
            logger.info(f"✅ Returning completed results for {discovery_id}")
        elif session_data['status'] == 'error' and 'error' in session_data:
            response_data['error'] = session_data['error']
            logger.info(f"❌ Returning error for {discovery_id}: {session_data['error']}")
        
        return jsonify({
            'status': 'success',
            'discovery': response_data
        })
        
    except Exception as e:
        logger.error(f"Error getting discovery status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get discovery status: {str(e)}'
        }), 500

@host_discovery_bp.route('/host-discovery/cancel/<discovery_id>', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def cancel_discovery(discovery_id):
    """Cancel a running discovery scan"""
    try:
        if discovery_id not in active_discoveries:
            return jsonify({
                'status': 'error',
                'message': 'Discovery session not found'
            }), 404
        
        session_data = active_discoveries[discovery_id]
        
        # ✅ NEW: Check user ownership
        if session_data.get('user_id') != session['user_id']:
            return jsonify({
                'status': 'error',
                'message': 'Access denied'
            }), 403
        
        # Mark as cancelled
        active_discoveries[discovery_id]['status'] = 'cancelled'
        active_discoveries[discovery_id]['progress'] = 0
        
        logger.info(f"🛑 User {session['user_id']} cancelled discovery: {discovery_id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Discovery cancelled',
            'discovery_id': discovery_id
        })
        
    except Exception as e:
        logger.error(f"Error cancelling discovery: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to cancel discovery: {str(e)}'
        }), 500

@host_discovery_bp.route('/host-discovery/recommendations', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def get_target_recommendations():
    """Get discovery recommendations for a target"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Target network required'
            }), 400
        
        target = data['target'].strip()
        
        if not is_valid_network_range(target):
            return jsonify({
                'status': 'error',
                'message': 'Invalid network range format'
            }), 400
        
        recommendations = get_discovery_recommendations(target)
        
        return jsonify({
            'status': 'success',
            'target': target,
            'recommendations': recommendations
        })
        
    except Exception as e:
        logger.error(f"Error getting recommendations: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get recommendations: {str(e)}'
        }), 500

@host_discovery_bp.route('/host-discovery/validate', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def validate_network_target():
    """Validate a network target"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Target network required'
            }), 400
        
        target = data['target'].strip()
        
        # Validate format
        is_valid = is_valid_network_range(target)
        if not is_valid:
            return jsonify({
                'status': 'invalid',
                'message': 'Invalid network range format',
                'suggestions': [
                    'Use CIDR notation: 192.168.1.0/24',
                    'Use IP range: 192.168.1.1-254',
                    'Use single IP: 192.168.1.1'
                ]
            })
        
        # Check for malicious input
        if contains_malicious_input(target):
            return jsonify({
                'status': 'invalid',
                'message': 'Invalid characters detected',
                'suggestions': ['Only use IP addresses, CIDR notation, or hostname formats']
            })
        
        # Get additional info
        is_private = is_private_network(target)
        estimated_hosts = estimate_total_hosts(target)
        
        return jsonify({
            'status': 'valid',
            'target': target,
            'is_private_network': is_private,
            'estimated_host_count': estimated_hosts,
            'network_type': 'Private' if is_private else 'Public',
            'recommendations': get_discovery_recommendations(target)
        })
        
    except Exception as e:
        logger.error(f"Error validating network target: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Validation failed: {str(e)}'
        }), 500

@host_discovery_bp.route('/host-discovery/statistics')
@login_required  # ✅ NEW: Added authentication
def get_discovery_statistics():
    """Get discovery statistics for current user"""
    try:
        # Get global statistics
        stats = {
            'total_discoveries': get_total_discoveries_performed(),
            'total_hosts_found': get_total_hosts_found(),
            'active_sessions': len([s for s in active_discoveries.values() if s.get('user_id') == session['user_id']]),
            'user_discoveries': 0,
            'user_hosts_found': 0,
            'average_hosts_per_discovery': 0
        }
        
        # ✅ NEW: Get user-specific statistics from scan history
        try:
            user_stats = scan_history_db.get_user_scan_stats(session['user_id'])
            host_discovery_scans = [scan for scan in user_stats.get('scan_type_breakdown', []) if scan['scan_type'] == 'host_discovery']
            
            if host_discovery_scans:
                user_discovery_data = host_discovery_scans[0]
                stats['user_discoveries'] = user_discovery_data['count']
                # Calculate user-specific hosts found from scan history
                user_scans = scan_history_db.get_user_scans(session['user_id'], filters={'scan_type': 'host_discovery'}, limit=1000)
                stats['user_hosts_found'] = sum(scan.get('hosts_found', 0) for scan in user_scans)
                
                if stats['user_discoveries'] > 0:
                    stats['average_hosts_per_discovery'] = round(stats['user_hosts_found'] / stats['user_discoveries'], 1)
                    
        except Exception as e:
            logger.warning(f"Could not get user-specific stats: {e}")
        
        # Mock some additional stats
        stats.update({
            'most_common_network_types': {
                'private': 85,
                'public': 15
            },
            'discovery_methods_usage': {
                'comprehensive': 40,
                'ping-sweep': 30,
                'arp-scan': 20,
                'tcp-connect': 8,
                'udp-discovery': 2
            }
        })
        
        return jsonify({
            'status': 'success',
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to get statistics: {str(e)}'
        }), 500

# Error handlers
@host_discovery_bp.errorhandler(404)
def not_found_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Resource not found'
    }), 404

@host_discovery_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error occurred'
    }), 500

# Initialize counters when the module is imported
initialize_discovery_counters()