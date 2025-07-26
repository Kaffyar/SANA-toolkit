"""
SANA Toolkit - Enhanced DNS Reconnaissance Routes
Advanced DNS reconnaissance functionality with Sublist3r subdomain enumeration + Scan History Integration
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect 
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import socket
import re
import logging
import json
import time
import threading
import subprocess
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
import os
import concurrent.futures
import whois
import concurrent.futures

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
dns_recon_bp = Blueprint('dns_recon', __name__)

# Active DNS sessions
active_dns_sessions = {}

# DNS statistics
dns_stats = {
   'total_lookups': 0,
   'total_domains_analyzed': 0,
   'total_subdomains_found': 0
}

# Common DNS record types
DNS_RECORD_TYPES = [
   'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR', 'SRV', 'CAA'
]

# Check if Sublist3r is available
SUBLIST3R_AVAILABLE = False

def check_sublist3r_availability():
   """Check if Sublist3r is installed and available"""
   global SUBLIST3R_AVAILABLE
   try:
       import sublist3r
       SUBLIST3R_AVAILABLE = True
       logger.info("✅ Sublist3r is available - will use for powerful subdomain discovery")
   except ImportError:
       logger.warning("❌ Sublist3r not available - install with: pip install sublist3r")
       SUBLIST3R_AVAILABLE = False

# Fallback wordlist if Sublist3r is not available
FALLBACK_SUBDOMAINS = [
   'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
   'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
   'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news',
   'vpn', 'ns4', 'mail2', 'new', 'mysql', 'old', 'www1', 'beta', 'exchange',
   'api', 'wap', 'www3', 'mail3', 'directoryadmin', 'www4', 'secure', 'shop',
   'stage', 'staging', 'app', 'git', 'svn', 'demo', 'mobile', 'cdn', 'assets',
   'store', 'support', 'help', 'docs', 'login', 'signin', 'signup', 'register',
   'user', 'account', 'profile', 'dashboard', 'panel', 'control', 'manage',
   'video', 'stream', 'chat', 'forum', 'community', 'service', 'download',
   'file', 'upload', 'media', 'image', 'photo', 'gallery', 'career', 'job',
   'contact', 'about', 'info', 'search', 'archive', 'backup', 'internal'
]

# ===== HELPER FUNCTIONS ===== #

def initialize_dns_counters():
   """Initialize DNS counter files if they don't exist"""
   try:
       counter_files = [
           'dns_lookups_counter.txt',
           'domains_analyzed_counter.txt',
           'subdomains_found_counter.txt'
       ]
       
       for counter_file in counter_files:
           if not os.path.exists(counter_file):
               with open(counter_file, 'w') as f:
                   f.write('0')
       
       logger.info("DNS counter files initialized")
   except Exception as e:
       logger.error(f"Failed to initialize DNS counters: {str(e)}")

def increment_dns_lookup_counter():
   """Increment the DNS lookup counter"""
   try:
       current_count = get_total_dns_lookups()
       new_count = current_count + 1
       
       with open('dns_lookups_counter.txt', 'w') as f:
           f.write(str(new_count))
       
       dns_stats['total_lookups'] = new_count
       logger.info(f"DNS lookup counter incremented to: {new_count}")
       return new_count
   except Exception as e:
       logger.error(f"Failed to increment DNS lookup counter: {str(e)}")
       return 0

def get_total_dns_lookups():
   """Get total number of DNS lookups performed"""
   try:
       if os.path.exists('dns_lookups_counter.txt'):
           with open('dns_lookups_counter.txt', 'r') as f:
               return int(f.read().strip() or 0)
       return 0
   except:
       return 0

def increment_domains_analyzed_counter():
   """Increment the domains analyzed counter"""
   try:
       current_count = get_total_domains_analyzed()
       new_count = current_count + 1
       
       with open('domains_analyzed_counter.txt', 'w') as f:
           f.write(str(new_count))
       
       dns_stats['total_domains_analyzed'] = new_count
       logger.info(f"Domains analyzed counter incremented to: {new_count}")
       return new_count
   except Exception as e:
       logger.error(f"Failed to increment domains analyzed counter: {str(e)}")
       return 0

def get_total_domains_analyzed():
   """Get total number of domains analyzed"""
   try:
       if os.path.exists('domains_analyzed_counter.txt'):
           with open('domains_analyzed_counter.txt', 'r') as f:
               return int(f.read().strip() or 0)
       return 0
   except:
       return 0

def increment_subdomains_found_counter(count):
   """Increment the subdomains found counter"""
   try:
       current_count = get_total_subdomains_found()
       new_count = current_count + count
       
       with open('subdomains_found_counter.txt', 'w') as f:
           f.write(str(new_count))
       
       dns_stats['total_subdomains_found'] = new_count
       logger.info(f"Subdomains found counter incremented by {count} to: {new_count}")
       return new_count
   except Exception as e:
       logger.error(f"Failed to increment subdomains found counter: {str(e)}")
       return 0

def get_total_subdomains_found():
   """Get total number of subdomains found"""
   try:
       if os.path.exists('subdomains_found_counter.txt'):
           with open('subdomains_found_counter.txt', 'r') as f:
               return int(f.read().strip() or 0)
       return 0
   except:
       return 0

def is_valid_domain(domain: str) -> bool:
   """Validate domain name format"""
   if not domain or not isinstance(domain, str):
       return False
   
   domain = domain.strip().lower()
   
   # Remove protocol if present
   if domain.startswith(('http://', 'https://')):
       domain = domain.split('://', 1)[1]
   
   # Remove path if present
   domain = domain.split('/')[0]
   
   # Domain regex pattern
   domain_pattern = re.compile(
       r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
   )
   
   return bool(domain_pattern.match(domain)) and len(domain) <= 253

def sanitize_domain(domain: str) -> str:
   """Sanitize and normalize domain name"""
   if not domain:
       return ""
   
   domain = domain.strip().lower()
   
   # Remove protocol
   if domain.startswith(('http://', 'https://')):
       domain = domain.split('://', 1)[1]
   
   # Remove path
   domain = domain.split('/')[0]
   
   # Remove port
   domain = domain.split(':')[0]
   
   return domain

def perform_dns_lookup(domain: str, record_type: str) -> Dict:
   """Perform DNS lookup for specific record type"""
   try:
       resolver = dns.resolver.Resolver()
       resolver.timeout = 5.0
       resolver.lifetime = 10.0
       
       answers = resolver.resolve(domain, record_type)
       records = []
       
       for rdata in answers:
           record_data = {
               'value': str(rdata),
               'ttl': answers.ttl,
               'type': record_type
           }
           
           # Add additional info for specific record types
           if record_type == 'MX':
               record_data['priority'] = rdata.preference
               record_data['exchange'] = str(rdata.exchange)
           elif record_type == 'SOA':
               record_data['mname'] = str(rdata.mname)
               record_data['rname'] = str(rdata.rname)
               record_data['serial'] = rdata.serial
               record_data['refresh'] = rdata.refresh
               record_data['retry'] = rdata.retry
               record_data['expire'] = rdata.expire
               record_data['minimum'] = rdata.minimum
           elif record_type == 'SRV':
               record_data['priority'] = rdata.priority
               record_data['weight'] = rdata.weight
               record_data['port'] = rdata.port
               record_data['target'] = str(rdata.target)
           
           records.append(record_data)
       
       return {
           'success': True,
           'records': records,
           'count': len(records)
       }
       
   except dns.resolver.NXDOMAIN:
       return {'success': False, 'error': 'Domain not found', 'records': [], 'count': 0}
   except dns.resolver.NoAnswer:
       return {'success': False, 'error': f'No {record_type} records found', 'records': [], 'count': 0}
   except dns.resolver.Timeout:
       return {'success': False, 'error': 'DNS query timeout', 'records': [], 'count': 0}
   except Exception as e:
       return {'success': False, 'error': str(e), 'records': [], 'count': 0}

def perform_reverse_dns_lookup(ip: str) -> Dict:
   """Perform reverse DNS lookup for IP address"""
   try:
       hostname = socket.gethostbyaddr(ip)[0]
       return {
           'success': True,
           'hostname': hostname,
           'ip': ip
       }
   except socket.herror:
       return {
           'success': False,
           'error': 'No PTR record found',
           'ip': ip
       }
   except Exception as e:
       return {
           'success': False,
           'error': str(e),
           'ip': ip
       }

# ===== ENHANCED SUBDOMAIN ENUMERATION WITH SUBLIST3R ===== #

def enumerate_subdomains_sublist3r(domain: str) -> List[Dict]:
    """Simplified Sublist3r with better error handling"""
    try:
        logger.info(f"🚀 Running Sublist3r for domain: {domain}")
        
        # Try subprocess approach first
        import subprocess
        import os
        import tempfile
        
        # Create temp file for results
        temp_file = tempfile.mktemp(suffix='.txt')
        
        # Try different Sublist3r command variations
        commands = [
            ['sublist3r', '-d', domain, '-o', temp_file],
            ['python', '-m', 'sublist3r', '-d', domain, '-o', temp_file], 
            ['python3', '-m', 'sublist3r', '-d', domain, '-o', temp_file]
        ]
        
        success = False
        for cmd in commands:
            try:
                logger.info(f"Trying command: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    success = True
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.warning(f"Command failed: {cmd[0]} - {e}")
                continue
        
        if not success:
            raise Exception("All Sublist3r commands failed")
        
        # Read results
        found_subdomains = []
        if os.path.exists(temp_file):
            with open(temp_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            # Verify each subdomain
            for subdomain in subdomains[:20]:  # Limit to 20 for speed
                if subdomain != domain:
                    result = perform_dns_lookup(subdomain, 'A')
                    if result['success']:
                        found_subdomains.append({
                            'subdomain': subdomain,
                            'ip_addresses': [r['value'] for r in result['records']],
                            'source': 'sublist3r',
                            'found': True
                        })
            
            os.unlink(temp_file)  # Clean up
        
        logger.info(f"✅ Sublist3r found {len(found_subdomains)} subdomains")
        return found_subdomains
        
    except Exception as e:
        logger.error(f"❌ Sublist3r failed: {e}")
        logger.info("🔄 Falling back to wordlist")
        return enumerate_subdomains_fallback(domain)

def enumerate_subdomains_fallback(domain: str) -> List[Dict]:
   """Fallback wordlist-based subdomain enumeration if Sublist3r fails"""
   logger.info(f"📋 Running fallback wordlist enumeration for domain: {domain}")
   
   found_subdomains = []
   
   def check_subdomain(subdomain):
       full_domain = f"{subdomain}.{domain}"
       try:
           result = perform_dns_lookup(full_domain, 'A')
           if result['success'] and result['records']:
               return {
                   'subdomain': full_domain,
                   'ip_addresses': [record['value'] for record in result['records']],
                   'source': 'wordlist_fallback',
                   'found': True
               }
       except:
           pass
       return None
   
   # Use ThreadPoolExecutor for concurrent subdomain checking
   with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
       future_to_subdomain = {
           executor.submit(check_subdomain, sub): sub for sub in FALLBACK_SUBDOMAINS
       }
       
       for future in concurrent.futures.as_completed(future_to_subdomain):
           result = future.result()
           if result:
               found_subdomains.append(result)
   
   logger.info(f"✅ Fallback wordlist found {len(found_subdomains)} active subdomains")
   return found_subdomains

def enumerate_subdomains(domain: str, wordlist: List[str] = None) -> List[Dict]:
   """Main subdomain enumeration function - uses Sublist3r automatically"""
   logger.info(f"🎯 Starting subdomain enumeration for: {domain}")
   
   # Always try Sublist3r first (it will handle fallback internally)
   subdomains = enumerate_subdomains_sublist3r(domain)
   
   logger.info(f"🎉 Subdomain enumeration completed. Total subdomains: {len(subdomains)}")
   return subdomains

# ===== CONTINUE WITH ORIGINAL FUNCTIONS ===== #

def attempt_zone_transfer(domain: str) -> Dict:
   """Attempt DNS zone transfer"""
   try:
       # Get nameservers for the domain
       ns_result = perform_dns_lookup(domain, 'NS')
       if not ns_result['success']:
           return {
               'success': False,
               'error': 'Could not retrieve nameservers',
               'zone_data': []
           }
       
       nameservers = [record['value'].rstrip('.') for record in ns_result['records']]
       zone_data = []
       
       for ns in nameservers:
           try:
               zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
               records = []
               for name, node in zone.nodes.items():
                   for rdataset in node.rdatasets:
                       for rdata in rdataset:
                           records.append({
                               'name': str(name),
                               'type': dns.rdatatype.to_text(rdataset.rdtype),
                               'value': str(rdata),
                               'ttl': rdataset.ttl
                           })
               
               zone_data.append({
                   'nameserver': ns,
                   'success': True,
                   'records': records
               })
               
           except Exception as e:
               zone_data.append({
                   'nameserver': ns,
                   'success': False,
                   'error': str(e)
               })
       
       return {
           'success': any(zd['success'] for zd in zone_data),
           'zone_data': zone_data
       }
       
   except Exception as e:
       return {
           'success': False,
           'error': str(e),
           'zone_data': []
       }

def get_whois_info(domain: str) -> Dict:
   """Get WHOIS information for domain"""
   try:
       w = whois.whois(domain)
       
       # Convert to serializable format
       whois_data = {}
       for key, value in w.items():
           if value is not None:
               if isinstance(value, (list, tuple)):
                   whois_data[key] = [str(v) for v in value]
               elif hasattr(value, 'isoformat'):  # datetime object
                   whois_data[key] = value.isoformat()
               else:
                   whois_data[key] = str(value)
       
       return {
           'success': True,
           'whois_data': whois_data
       }
       
   except Exception as e:
       return {
           'success': False,
           'error': str(e),
           'whois_data': {}
       }

def analyze_dns_security(domain: str) -> Dict:
   """Analyze DNS security features"""
   security_features = {
       'dnssec': False,
       'spf': False,
       'dmarc': False,
       'dkim': False,
       'caa': False
   }
   
   try:
       # Check DNSSEC
       try:
           resolver = dns.resolver.Resolver()
           resolver.set_flags(dns.flags.AD)
           answer = resolver.resolve(domain, 'A')
           security_features['dnssec'] = answer.response.flags & dns.flags.AD != 0
       except:
           pass
       
       # Check SPF record
       try:
           txt_result = perform_dns_lookup(domain, 'TXT')
           if txt_result['success']:
               for record in txt_result['records']:
                   if 'v=spf1' in record['value'].lower():
                       security_features['spf'] = True
                       break
       except:
           pass
       
       # Check DMARC record
       try:
           dmarc_domain = f"_dmarc.{domain}"
           dmarc_result = perform_dns_lookup(dmarc_domain, 'TXT')
           if dmarc_result['success']:
               for record in dmarc_result['records']:
                   if 'v=dmarc1' in record['value'].lower():
                       security_features['dmarc'] = True
                       break
       except:
           pass
       
       # Check CAA record
       try:
           caa_result = perform_dns_lookup(domain, 'CAA')
           security_features['caa'] = caa_result['success'] and caa_result['count'] > 0
       except:
           pass
       
   except Exception as e:
       logger.warning(f"Error analyzing DNS security for {domain}: {str(e)}")
   
   return security_features

def cleanup_old_dns_sessions():
   """Clean up old DNS sessions"""
   current_time = time.time()
   expired_sessions = []
   
   for session_id, session in active_dns_sessions.items():
       if current_time - session['start_time'] > 3600:  # 1 hour timeout
           expired_sessions.append(session_id)
   
   for session_id in expired_sessions:
       del active_dns_sessions[session_id]
       logger.info(f"Cleaned up expired DNS session: {session_id}")

# ===== NEW: Determine threat level based on DNS findings ===== #

def determine_dns_threat_level(results: Dict) -> str:
   """Determine threat level based on DNS scan results"""
   threat_score = 0
   
   # Check for zone transfer vulnerability
   if results.get('zone_transfer', {}).get('success'):
       threat_score += 3  # High risk
   
   # Check for missing security records
   security = results.get('security_analysis', {})
   if not security.get('spf'):
       threat_score += 1
   if not security.get('dmarc'):
       threat_score += 1
   if not security.get('dnssec'):
       threat_score += 1
   
   # Check for excessive subdomains (attack surface)
   subdomains_count = len(results.get('subdomains', []))
   if subdomains_count > 50:
       threat_score += 2
   elif subdomains_count > 20:
       threat_score += 1
   
   # Determine threat level
   if threat_score >= 4:
       return 'critical'
   elif threat_score >= 3:
       return 'high'
   elif threat_score >= 1:
       return 'medium'
   else:
       return 'low'

# ===== ROUTES ===== #

@dns_recon_bp.route('/dns-recon')
@login_required  # ✅ NEW: Added authentication
def dns_recon_page():
   """Render the DNS reconnaissance page"""
   try:
       # Initialize counters if needed
       initialize_dns_counters()
       
       # Clean up old sessions
       cleanup_old_dns_sessions()
       
       # Get current statistics
       context = {
           'total_lookups': get_total_dns_lookups(),
           'total_domains': get_total_domains_analyzed(),
           'total_subdomains': get_total_subdomains_found(),
           'active_sessions': len(active_dns_sessions),
           'sublist3r_available': SUBLIST3R_AVAILABLE,
           'page_title': 'DNS Reconnaissance',
           'current_year': datetime.now().year
       }
       
       return render_template('dns_recon.html', **context)
       
   except Exception as e:
       logger.error(f"Error rendering DNS reconnaissance page: {str(e)}")
       return render_template('dns_recon.html', error="Failed to load page")

@dns_recon_bp.route('/dns-lookup', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def dns_lookup():
   """Perform comprehensive DNS lookup with Sublist3r subdomain enumeration + Scan History"""
   scan_start_time = time.time()  # ✅ NEW: Track scan duration
   
   try:
       data = request.get_json()
       if not data:
           return jsonify({
               'status': 'error',
               'message': 'No JSON data provided'
           }), 400
       
       domain = data.get('domain', '').strip()
       record_types = data.get('recordTypes', ['A', 'AAAA', 'MX', 'NS', 'TXT'])
       include_subdomains = data.get('includeSubdomains', False)
       include_zone_transfer = data.get('includeZoneTransfer', False)
       include_whois = data.get('includeWhois', False)
       include_security = data.get('includeSecurity', False)
       
       # Validate domain
       if not domain:
           return jsonify({
               'status': 'error',
               'message': 'Domain is required'
           }), 400
       
       domain = sanitize_domain(domain)
       
       if not is_valid_domain(domain):
           return jsonify({
               'status': 'error',
               'message': 'Invalid domain format'
           }), 400
       
       # ✅ NEW: Log user activity
       logger.info(f"🔍 User {session['user_id']} starting DNS recon: {domain}")
       
       # Create session ID
       session_id = f"dns_{int(time.time())}_{hash(domain) % 10000}"
       
       # Initialize session
       active_dns_sessions[session_id] = {
           'domain': domain,
           'start_time': time.time(),
           'status': 'running',
           'progress': 0
       }
       
       results = {
           'domain': domain,
           'session_id': session_id,
           'timestamp': datetime.now().isoformat(),
           'dns_records': {},
           'subdomains': [],
           'zone_transfer': {},
           'whois_info': {},
           'security_analysis': {},
           'statistics': {
               'total_records': 0,
               'subdomains_found': 0,
               'record_types_found': [],
               'enumeration_method': 'sublist3r' if SUBLIST3R_AVAILABLE else 'fallback_wordlist'
           }
       }
       
       # Perform DNS lookups for requested record types
       total_steps = len(record_types)
       if include_subdomains:
           total_steps += 1
       if include_zone_transfer:
           total_steps += 1
       if include_whois:
           total_steps += 1
       if include_security:
           total_steps += 1
       
       current_step = 0
       
       for record_type in record_types:
           current_step += 1
           progress = int((current_step / total_steps) * 100)
           active_dns_sessions[session_id]['progress'] = progress
           
           lookup_result = perform_dns_lookup(domain, record_type)
           results['dns_records'][record_type] = lookup_result
           
           if lookup_result['success']:
               results['statistics']['total_records'] += lookup_result['count']
               results['statistics']['record_types_found'].append(record_type)
       
       # Enhanced subdomain enumeration with Sublist3r
       if include_subdomains:
           current_step += 1
           progress = int((current_step / total_steps) * 100)
           active_dns_sessions[session_id]['progress'] = progress
           
           subdomains = enumerate_subdomains(domain)
           results['subdomains'] = subdomains
           results['statistics']['subdomains_found'] = len(subdomains)
           
           # Update subdomain counter
           if subdomains:
               increment_subdomains_found_counter(len(subdomains))
       
       # Zone transfer attempt
       if include_zone_transfer:
           current_step += 1
           progress = int((current_step / total_steps) * 100)
           active_dns_sessions[session_id]['progress'] = progress
           
           zone_result = attempt_zone_transfer(domain)
           results['zone_transfer'] = zone_result
       
       # WHOIS lookup
       if include_whois:
           current_step += 1
           progress = int((current_step / total_steps) * 100)
           active_dns_sessions[session_id]['progress'] = progress
           
           whois_result = get_whois_info(domain)
           results['whois_info'] = whois_result
       
       # Security analysis
       if include_security:
           current_step += 1
           progress = int((current_step / total_steps) * 100)
           active_dns_sessions[session_id]['progress'] = progress
           
           security_result = analyze_dns_security(domain)
           results['security_analysis'] = security_result
       
       # Update counters
       increment_dns_lookup_counter()
       increment_domains_analyzed_counter()
       
       # Complete session
       active_dns_sessions[session_id]['status'] = 'completed'
       active_dns_sessions[session_id]['progress'] = 100
       active_dns_sessions[session_id]['results'] = results
       
       # ===== NEW: SAVE TO SCAN HISTORY ===== #
       
       try:
           # Calculate metrics
           scan_end_time = time.time()
           scan_duration = int(scan_end_time - scan_start_time)
           threat_level = determine_dns_threat_level(results)
           
           # Count vulnerabilities
           vulnerabilities_found = 0
           if results.get('zone_transfer', {}).get('success'):
               vulnerabilities_found += 1
           if not results.get('security_analysis', {}).get('spf'):
               vulnerabilities_found += 1
           if not results.get('security_analysis', {}).get('dmarc'):
               vulnerabilities_found += 1
           
           # Prepare scan parameters
           scan_parameters = {
               'record_types': record_types,
               'include_subdomains': include_subdomains,
               'include_zone_transfer': include_zone_transfer,
               'include_whois': include_whois,
               'include_security': include_security,
               'enumeration_method': results['statistics']['enumeration_method']
           }
           
           # Save to scan history
           scan_id = scan_history_db.add_scan(
               user_id=session['user_id'],
               scan_type='dns',
               target=domain,
               scan_parameters=scan_parameters,
               scan_results=results,
               scan_command=f"DNS recon: {', '.join(record_types)}" + (" + subdomains" if include_subdomains else ""),
               duration=scan_duration,
               hosts_found=results['statistics']['subdomains_found'],
               ports_found=results['statistics']['total_records'],
               vulnerabilities_found=vulnerabilities_found,
               threat_level=threat_level,
               status='completed',
               notes=f"DNS recon - {results['statistics']['total_records']} records, {results['statistics']['subdomains_found']} subdomains"
           )
           
           logger.info(f"✅ DNS recon saved to history: ID={scan_id}, User={session['user_id']}, Domain={domain}")
           
       except Exception as e:
           logger.error(f"❌ Failed to save DNS recon to history: {e}")
           # Continue without failing the entire scan
       
       return jsonify({
           'status': 'success',
           'results': results
       })
       
   except Exception as e:
       # ✅ NEW: Save failed scans to history
       try:
           scan_duration = int(time.time() - scan_start_time)
           scan_history_db.add_scan(
               user_id=session['user_id'],
               scan_type='dns',
               target=domain if 'domain' in locals() else 'unknown',
               scan_parameters={'error': str(e)},
               scan_results={'error': str(e)},
               scan_command='DNS recon (failed)',
               duration=scan_duration,
               status='failed',
               threat_level='low'
           )
       except:
           pass
       
       logger.error(f"❌ DNS lookup failed for user {session['user_id']}: {str(e)}")
       return jsonify({
           'status': 'error',
           'message': f'DNS lookup failed: {str(e)}'
       }), 500

@dns_recon_bp.route('/reverse-dns', methods=['POST'])
@login_required  # ✅ NEW: Added authentication
def reverse_dns():
   """Perform reverse DNS lookup with scan history tracking"""
   scan_start_time = time.time()  # ✅ NEW: Track scan duration
   
   try:
       data = request.get_json()
       if not data:
           return jsonify({
               'status': 'error',
               'message': 'No JSON data provided'
           }), 400
       
       ip_address = data.get('ip', '').strip()
       
       if not ip_address:
           return jsonify({
               'status': 'error',
               'message': 'IP address is required'
           }), 400
       
       # Validate IP address
       try:
           ipaddress.ip_address(ip_address)
       except ValueError:
           return jsonify({
               'status': 'error',
               'message': 'Invalid IP address format'
           }), 400
       
       # ✅ NEW: Log user activity
       logger.info(f"🔍 User {session['user_id']} reverse DNS lookup: {ip_address}")
       
       # Perform reverse DNS lookup
       result = perform_reverse_dns_lookup(ip_address)
       
       # Increment counter
       increment_dns_lookup_counter()
       
       # ✅ NEW: Save to scan history
       try:
           scan_duration = int(time.time() - scan_start_time)
           
           scan_id = scan_history_db.add_scan(
               user_id=session['user_id'],
               scan_type='dns',
               target=ip_address,
               scan_parameters={'lookup_type': 'reverse_dns'},
               scan_results=result,
               scan_command=f"Reverse DNS lookup",
               duration=scan_duration,
               hosts_found=1 if result['success'] else 0,
               ports_found=0,
               vulnerabilities_found=0,
               threat_level='low',
               status='completed' if result['success'] else 'failed',
               notes=f"Reverse DNS - {'Found: ' + result.get('hostname', 'N/A') if result['success'] else 'Not found'}"
           )
           
           logger.info(f"✅ Reverse DNS saved to history: ID={scan_id}, IP={ip_address}")
           
       except Exception as e:
           logger.error(f"❌ Failed to save reverse DNS to history: {e}")
       
       return jsonify({
           'status': 'success',
           'result': result
       })
       
   except Exception as e:
       logger.error(f"❌ Reverse DNS lookup failed for user {session['user_id']}: {str(e)}")
       return jsonify({
           'status': 'error',
           'message': f'Reverse DNS lookup failed: {str(e)}'
       }), 500

@dns_recon_bp.route('/dns-session/<session_id>')
@login_required  # ✅ NEW: Added authentication
def get_dns_session(session_id):
   """Get DNS session status and results"""
   try:
       if session_id not in active_dns_sessions:
           return jsonify({
               'status': 'error',
               'message': 'Session not found'
           }), 404
       
       session = active_dns_sessions[session_id]
       
       return jsonify({
           'status': 'success',
           'session': {
               'id': session_id,
               'domain': session['domain'],
               'status': session['status'],
               'progress': session['progress'],
               'start_time': session['start_time'],
               'results': session.get('results', {})
           }
       })
       
   except Exception as e:
       logger.error(f"Error getting DNS session: {str(e)}")
       return jsonify({
           'status': 'error',
           'message': f'Failed to get session: {str(e)}'
       }), 500

@dns_recon_bp.route('/dns-stats')
@login_required  # ✅ NEW: Added authentication
def get_dns_stats():
   """Get DNS reconnaissance statistics"""
   try:
       stats = {
           'total_lookups': get_total_dns_lookups(),
           'total_domains': get_total_domains_analyzed(),
           'total_subdomains': get_total_subdomains_found(),
           'active_sessions': len(active_dns_sessions),
           'supported_record_types': DNS_RECORD_TYPES,
           'sublist3r_available': SUBLIST3R_AVAILABLE
       }
       
       return jsonify({
           'status': 'success',
           'stats': stats
       })
       
   except Exception as e:
       logger.error(f"Error getting DNS stats: {str(e)}")
       return jsonify({
           'status': 'error',
           'message': f'Failed to get stats: {str(e)}'
       }), 500

# Error handlers
@dns_recon_bp.errorhandler(404)
def not_found_error(error):
   return jsonify({
       'status': 'error',
       'message': 'Resource not found'
   }), 404

@dns_recon_bp.errorhandler(500)
def internal_error(error):
   return jsonify({
       'status': 'error',
       'message': 'Internal server error occurred'
   }), 500

# Initialize everything when the module is imported
initialize_dns_counters()
check_sublist3r_availability()