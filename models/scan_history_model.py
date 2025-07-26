"""
SANA Toolkit - Comprehensive Scan History Model
Handles all database operations for user scan history across all scan types
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanHistoryDB:
    def __init__(self, db_path='data/sana_toolkit.db'):
        self.db_path = db_path
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        # Initialize the search index
        self._setup_search_index()
        
    def create_connection(self):
        """Create a database connection with proper error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            return None
    
    def add_scan(self, user_id: int, scan_type: str, target: str, 
                 scan_parameters: Dict = None, scan_results: Dict = None, 
                 scan_command: str = None, duration: int = 0, 
                 hosts_found: int = 0, ports_found: int = 0, 
                 vulnerabilities_found: int = 0, threat_level: str = 'low',
                 status: str = 'completed', notes: str = None) -> Optional[int]:
        """
        Add a scan entry to user's history
        
        Args:
            user_id: The user's ID
            scan_type: Type of scan ('network', 'dns', 'virustotal', 'host_discovery')
            target: Target IP/domain/URL
            scan_parameters: Dictionary of scan parameters (will be JSON encoded)
            scan_results: Dictionary of scan results (will be JSON encoded)
            scan_command: Command executed (for nmap scans)
            duration: Scan duration in seconds
            hosts_found: Number of hosts discovered
            ports_found: Number of ports found
            vulnerabilities_found: Number of vulnerabilities detected
            threat_level: Threat level ('low', 'medium', 'high', 'critical')
            status: Scan status ('completed', 'failed', 'in_progress')
            notes: User notes about the scan
            
        Returns:
            scan_id if successful, None if failed
        """
        conn = self.create_connection()
        if not conn:
            return None
            
        try:
            with conn:
                cursor = conn.cursor()
                
                # Convert dictionaries to JSON strings
                parameters_json = json.dumps(scan_parameters) if scan_parameters else None
                results_json = json.dumps(scan_results) if scan_results else None
                
                # Calculate threat level if not provided explicitly or if it's the default 'low'
                logger.info(f"🔍 add_scan: threat_level='{threat_level}', scan_type='{scan_type}', has_scan_results={scan_results is not None}")
                
                if (not threat_level or threat_level == 'low' or threat_level == 'Low') and scan_results:
                    logger.info(f"🔄 Calculating threat level for new scan: type={scan_type}, target={target}")
                    threat_level = self.calculate_threat_level(scan_type, scan_results, vulnerabilities_found, ports_found)
                    logger.info(f"✅ Calculated threat level: {threat_level}")
                else:
                    logger.info(f"📝 Using provided threat level: {threat_level}")
                
                # Insert scan record
                cursor.execute("""
                    INSERT INTO scan_history (
                        user_id, scan_type, target, scan_parameters, scan_results,
                        scan_command, status, duration, hosts_found, ports_found,
                        vulnerabilities_found, threat_level, notes, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id, scan_type, target, parameters_json, results_json,
                    scan_command, status, duration, hosts_found, ports_found,
                    vulnerabilities_found, threat_level, notes, datetime.now()
                ))
                
                scan_id = cursor.lastrowid
                logger.info(f"✅ Scan added to history: ID={scan_id}, User={user_id}, Type={scan_type}, Target={target}")
                return scan_id
                
        except sqlite3.Error as e:
            logger.error(f"❌ Error adding scan to history: {e}")
            return None
        finally:
            conn.close()

    def calculate_threat_level(self, scan_type: str, scan_results: Dict, 
                              vulnerabilities_found: int = 0, ports_found: int = 0) -> str:
        """
        Calculate threat level based on scan type and results
        
        Args:
            scan_type: Type of scan
            scan_results: Dictionary of scan results
            vulnerabilities_found: Number of vulnerabilities detected
            ports_found: Number of open ports found
            
        Returns:
            Threat level string ('low', 'medium', 'high', 'critical')
        """
        # Default threat level
        threat_level = 'low'
        
        try:
            if scan_type == 'virustotal':
                # Calculate VirusTotal threat level based on detection ratio and total threats
                logger.info(f"🔍 Processing VirusTotal scan results: {type(scan_results)}")
                
                # Handle case where scan_results might be a JSON string
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                        logger.info(f"✅ Parsed JSON scan_results")
                    except json.JSONDecodeError as e:
                        logger.error(f"❌ Failed to parse scan_results JSON: {e}")
                        return 'low'
                
                if scan_results and 'scan_stats' in scan_results:
                    stats = scan_results['scan_stats']
                    logger.info(f"📊 Found scan_stats: {stats}")
                    
                    # Handle case where stats might be a JSON string
                    if isinstance(stats, str):
                        try:
                            stats = json.loads(stats)
                            logger.info(f"✅ Parsed JSON stats")
                        except json.JSONDecodeError as e:
                            logger.error(f"❌ Failed to parse stats JSON: {e}")
                            return 'low'
                    
                    malicious = int(stats.get('malicious', 0))
                    suspicious = int(stats.get('suspicious', 0))
                    total = int(stats.get('total', 0))
                    
                    if total > 0:
                        ratio = (malicious / total) * 100
                        
                        # Log for debugging
                        logger.info(f"VirusTotal threat calculation: malicious={malicious} (type: {type(malicious)}), suspicious={suspicious}, total={total} (type: {type(total)}), ratio={ratio:.2f}%")
                        
                        # Updated logic: Consider both ratio and total threat count
                        logger.info(f"🔍 Checking conditions: ratio >= 50 ({ratio:.2f} >= 50) = {ratio >= 50}, malicious >= 30 ({malicious} >= 30) = {malicious >= 30}, total >= 50 ({total} >= 50) = {total >= 50}")
                        
                        if ratio >= 50 or malicious >= 30 or total >= 50:
                            threat_level = 'critical'
                            logger.info(f"✅ VirusTotal scan marked as CRITICAL: {ratio:.2f}% detection rate, {malicious} malicious, {total} total")
                        elif ratio >= 25 or malicious >= 15:
                            threat_level = 'high'
                            logger.info(f"⚠️ VirusTotal scan marked as HIGH: {ratio:.2f}% detection rate, {malicious} malicious, {total} total")
                        elif ratio >= 10 or malicious >= 5:
                            threat_level = 'medium'
                            logger.info(f"⚠️ VirusTotal scan marked as MEDIUM: {ratio:.2f}% detection rate, {malicious} malicious, {total} total")
                        else:
                            threat_level = 'low'
                            logger.info(f"ℹ️ VirusTotal scan marked as LOW: {ratio:.2f}% detection rate, {malicious} malicious, {total} total")
                    else:
                        threat_level = 'low'
                        logger.info(f"ℹ️ VirusTotal scan marked as LOW: no total threats found")
                else:
                    threat_level = 'low'
                            
            elif scan_type == 'network':
                # Calculate network scan threat level based on vulnerabilities and sensitive ports
                if vulnerabilities_found > 10:
                    threat_level = 'critical'
                elif vulnerabilities_found > 5:
                    threat_level = 'high'
                elif vulnerabilities_found > 0:
                    threat_level = 'medium'
                
                # Check for sensitive ports (if scan_results has hosts data)
                sensitive_ports = {21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080}
                if scan_results and 'hosts' in scan_results:
                    for host in scan_results['hosts']:
                        if 'protocols' in host and 'tcp' in host['protocols']:
                            # Check for sensitive open ports
                            open_sensitive = [int(port['port']) for port in host['protocols']['tcp'] 
                                           if port['state'] == 'open' and int(port['port']) in sensitive_ports]
                            
                            # Increase threat level based on number of sensitive open ports
                            if len(open_sensitive) >= 5 and threat_level != 'critical':
                                threat_level = 'high'
                            elif len(open_sensitive) >= 3 and threat_level not in ['critical', 'high']:
                                threat_level = 'medium'
                                
            elif scan_type == 'host_discovery':
                # For host discovery, base threat on number of hosts found
                # This is mostly informational, so threat level is generally lower
                if hosts_found > 100:
                    threat_level = 'medium'
                elif hosts_found > 50:
                    threat_level = 'low'
                    
            elif scan_type == 'dns':
                # For DNS reconnaissance
                # Higher threat if many subdomains are found
                if scan_results:
                    subdomains_count = len(scan_results.get('subdomains', []))
                    if subdomains_count > 100:
                        threat_level = 'medium'
                    elif subdomains_count > 50:
                        threat_level = 'low'
                        
                    # Check for sensitive DNS records (like SPF failures or DMARC issues)
                    dns_records = scan_results.get('dns_records', {})
                    
                    # Check for missing SPF, DMARC, or DNSSEC
                    security_issues = 0
                    if 'TXT' in dns_records:
                        has_spf = False
                        has_dmarc = False
                        
                        for record in dns_records['TXT'].get('records', []):
                            if 'v=spf1' in record.get('value', ''):
                                has_spf = True
                            if 'v=DMARC1' in record.get('value', ''):
                                has_dmarc = True
                        
                        if not has_spf:
                            security_issues += 1
                        if not has_dmarc:
                            security_issues += 1
                    
                    if security_issues >= 2:
                        threat_level = 'medium'
                    elif security_issues >= 1 and threat_level == 'low':
                        threat_level = 'low'
            
            # Adjust final threat level based on total vulnerabilities found across scan types
            if vulnerabilities_found > 20:
                threat_level = 'critical'
            elif vulnerabilities_found > 10 and threat_level != 'critical':
                threat_level = 'high'
            elif vulnerabilities_found > 5 and threat_level not in ['critical', 'high']:
                threat_level = 'medium'
                
        except Exception as e:
            logger.error(f"Error calculating threat level: {e}")
            # Fallback to provided threat level or 'low' if calculation fails
        
        return threat_level
    
    def get_user_scans(self, user_id: int, filters: Dict = None, 
                       limit: int = 50, offset: int = 0) -> List[Dict]:
        """
        Get user's scan history with optional filtering
        
        Args:
            user_id: The user's ID
            filters: Dictionary of filters {
                'scan_type': str,
                'target': str (partial match),
                'status': str,
                'threat_level': str,
                'date_from': str (YYYY-MM-DD),
                'date_to': str (YYYY-MM-DD),
                'search': str (searches target and notes)
            }
            limit: Maximum number of records to return
            offset: Number of records to skip (for pagination)
            
        Returns:
            List of scan dictionaries
        """
        conn = self.create_connection()
        if not conn:
            return []
            
        try:
            cursor = conn.cursor()
            
            # Build query with filters
            query = """
                SELECT 
                    scan_id, scan_type, target, scan_parameters, scan_results,
                    scan_command, status, duration, hosts_found, ports_found,
                    vulnerabilities_found, threat_level, notes, timestamp
                FROM scan_history 
                WHERE user_id = ?
            """
            params = [user_id]
            
            # Apply filters
            if filters:
                if filters.get('scan_type'):
                    query += " AND scan_type = ?"
                    params.append(filters['scan_type'])
                
                if filters.get('target'):
                    query += " AND target LIKE ?"
                    params.append(f"%{filters['target']}%")
                
                if filters.get('status'):
                    query += " AND status = ?"
                    params.append(filters['status'])
                
                if filters.get('threat_level'):
                    query += " AND threat_level = ?"
                    params.append(filters['threat_level'])
                
                if filters.get('date_from'):
                    query += " AND date(timestamp) >= ?"
                    params.append(filters['date_from'])
                
                if filters.get('date_to'):
                    query += " AND date(timestamp) <= ?"
                    params.append(filters['date_to'])
                
                if filters.get('search'):
                    query += " AND (target LIKE ? OR notes LIKE ?)"
                    search_term = f"%{filters['search']}%"
                    params.extend([search_term, search_term])
            
            # Order by timestamp (newest first) and apply pagination
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries and parse JSON fields
            scans = []
            for row in rows:
                scan = dict(row)
                
                # Parse JSON fields
                if scan['scan_parameters']:
                    try:
                        scan['scan_parameters'] = json.loads(scan['scan_parameters'])
                    except json.JSONDecodeError:
                        scan['scan_parameters'] = {}
                
                if scan['scan_results']:
                    try:
                        scan['scan_results'] = json.loads(scan['scan_results'])
                    except json.JSONDecodeError:
                        scan['scan_results'] = {}
                
                # Format timestamp for display
                scan['formatted_timestamp'] = self._format_timestamp(scan['timestamp'])
                scan['time_ago'] = self._time_ago(scan['timestamp'])
                
                scans.append(scan)
            
            logger.info(f" {len(scans)} scans for user {user_id}")
            return scans
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error retrieving user scans: {e}")
            return []
        finally:
            conn.close()
    
    def get_scan_by_id(self, user_id: int, scan_id: int) -> Optional[Dict]:
        """
        Get a specific scan by ID (user must own the scan)
        
        Args:
            user_id: The user's ID
            scan_id: The scan ID
            
        Returns:
            Scan dictionary or None if not found
        """
        conn = self.create_connection()
        if not conn:
            return None
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    scan_id, scan_type, target, scan_parameters, scan_results,
                    scan_command, status, duration, hosts_found, ports_found,
                    vulnerabilities_found, threat_level, notes, timestamp
                FROM scan_history 
                WHERE user_id = ? AND scan_id = ?
            """, (user_id, scan_id))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            scan = dict(row)
            
            # Parse JSON fields
            if scan['scan_parameters']:
                try:
                    scan['scan_parameters'] = json.loads(scan['scan_parameters'])
                except json.JSONDecodeError:
                    scan['scan_parameters'] = {}
            
            if scan['scan_results']:
                try:
                    scan['scan_results'] = json.loads(scan['scan_results'])
                except json.JSONDecodeError:
                    scan['scan_results'] = {}
            
            # Format timestamp
            scan['formatted_timestamp'] = self._format_timestamp(scan['timestamp'])
            scan['time_ago'] = self._time_ago(scan['timestamp'])
            
            return scan
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error retrieving scan {scan_id}: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_scan_stats(self, user_id: int) -> Dict[str, Any]:
        """
        Get comprehensive scanning statistics for a user
        
        Args:
            user_id: The user's ID
            
        Returns:
            Dictionary with user's scan statistics
        """
        conn = self.create_connection()
        if not conn:
            return {}
            
        try:
            cursor = conn.cursor()
            
            # Overall statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(duration) as total_duration,
                    SUM(hosts_found) as total_hosts_found,
                    SUM(ports_found) as total_ports_found,
                    SUM(vulnerabilities_found) as total_vulnerabilities,
                    AVG(duration) as avg_duration,
                    MAX(timestamp) as last_scan_date,
                    MIN(timestamp) as first_scan_date
                FROM scan_history 
                WHERE user_id = ?
            """, (user_id,))
            
            overall_stats = dict(cursor.fetchone())
            
            # Scan type breakdown
            cursor.execute("""
                SELECT 
                    scan_type,
                    COUNT(*) as count,
                    SUM(duration) as total_duration,
                    AVG(duration) as avg_duration,
                    MAX(timestamp) as last_scan
                FROM scan_history 
                WHERE user_id = ?
                GROUP BY scan_type
                ORDER BY count DESC
            """, (user_id,))
            
            scan_type_stats = [dict(row) for row in cursor.fetchall()]
            
            # Status breakdown
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM scan_history 
                WHERE user_id = ?
                GROUP BY status
            """, (user_id,))
            
            status_stats = {row['status']: row['count'] for row in cursor.fetchall()}
            
            # Threat level breakdown - normalize case to handle inconsistent storage
            cursor.execute("""
                SELECT LOWER(threat_level) as threat_level, COUNT(*) as count
                FROM scan_history 
                WHERE user_id = ?
                GROUP BY LOWER(threat_level)
            """, (user_id,))
            
            threat_stats = {row['threat_level']: row['count'] for row in cursor.fetchall()}
            
            # Debug logging for threat levels
            logger.info(f"🔍 Raw threat levels from database for user {user_id}: {threat_stats}")
            
            # Also log individual threat level entries for debugging
            cursor.execute("""
                SELECT threat_level, scan_id, scan_type, target
                FROM scan_history 
                WHERE user_id = ?
                ORDER BY threat_level
            """, (user_id,))
            
            all_threats = cursor.fetchall()
            logger.info(f"🔍 All threat level entries for user {user_id}:")
            for row in all_threats:
                logger.info(f"  - Scan {row['scan_id']}: {row['threat_level']} ({row['scan_type']}) - {row['target'][:50]}...")
            
            # Debug VirusTotal scans specifically
            cursor.execute("""
                SELECT scan_id, threat_level, scan_results
                FROM scan_history 
                WHERE user_id = ? AND scan_type = 'virustotal'
                ORDER BY scan_id DESC
                LIMIT 5
            """, (user_id,))
            
            vt_scans = cursor.fetchall()
            logger.info(f"🔍 VirusTotal scans for user {user_id}:")
            for row in vt_scans:
                logger.info(f"  - VT Scan {row['scan_id']}: threat_level = {row['threat_level']}")
                # Try to parse scan_results to see detection stats
                try:
                    if row['scan_results']:
                        results = json.loads(row['scan_results'])
                        if 'scan_stats' in results:
                            stats = results['scan_stats']
                            malicious = stats.get('malicious', 0)
                            total = stats.get('total', 0)
                            ratio = (malicious / total * 100) if total > 0 else 0
                            logger.info(f"    Detection stats: {malicious}/{total} = {ratio:.1f}%")
                except:
                    pass
            
            # Recent activity (last 7 days)
            cursor.execute("""
                SELECT COUNT(*) as recent_scans
                FROM scan_history 
                WHERE user_id = ? AND timestamp >= datetime('now', '-7 days')
            """, (user_id,))
            
            recent_scans = cursor.fetchone()['recent_scans']
            
            # Success rate
            success_rate = 0
            if overall_stats['total_scans'] > 0:
                success_rate = (status_stats.get('completed', 0) / overall_stats['total_scans']) * 100
            
            stats = {
                'total_scans': overall_stats['total_scans'] or 0,
                'total_duration': overall_stats['total_duration'] or 0,
                'total_hosts_found': overall_stats['total_hosts_found'] or 0,
                'total_ports_found': overall_stats['total_ports_found'] or 0,
                'total_vulnerabilities': overall_stats['total_vulnerabilities'] or 0,
                'avg_duration': round(overall_stats['avg_duration'] or 0, 2),
                'last_scan_date': overall_stats['last_scan_date'],
                'first_scan_date': overall_stats['first_scan_date'],
                'recent_scans': recent_scans,
                'success_rate': round(success_rate, 1),
                'scan_type_breakdown': scan_type_stats,
                'status_breakdown': status_stats,
                'threat_breakdown': threat_stats
            }
            
            logger.info(f"📈 Generated stats for user {user_id}: {stats['total_scans']} total scans")
            return stats
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error retrieving user stats: {e}")
            return {}
        finally:
            conn.close()
    
    def delete_scan(self, user_id: int, scan_id: int) -> bool:
        """
        Delete a specific scan from user's history
        
        Args:
            user_id: The user's ID
            scan_id: The scan ID to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM scan_history 
                    WHERE user_id = ? AND scan_id = ?
                """, (user_id, scan_id))
                
                if cursor.rowcount > 0:
                    logger.info(f"🗑️ Deleted scan {scan_id} for user {user_id}")
                    return True
                else:
                    logger.warning(f"⚠️ Scan {scan_id} not found for user {user_id}")
                    return False
                    
        except sqlite3.Error as e:
            logger.error(f"❌ Error deleting scan {scan_id}: {e}")
            return False
        finally:
            conn.close()
    
    def delete_user_scans(self, user_id: int, older_than_days: int = None) -> int:
        """
        Delete user's scan history (optionally only old scans)
        
        Args:
            user_id: The user's ID
            older_than_days: Only delete scans older than this many days (None = delete all)
            
        Returns:
            Number of scans deleted
        """
        conn = self.create_connection()
        if not conn:
            return 0
            
        try:
            with conn:
                cursor = conn.cursor()
                
                if older_than_days:
                    cursor.execute("""
                        DELETE FROM scan_history 
                        WHERE user_id = ? AND timestamp < datetime('now', '-{} days')
                    """.format(older_than_days), (user_id,))
                else:
                    cursor.execute("""
                        DELETE FROM scan_history 
                        WHERE user_id = ?
                    """, (user_id,))
                
                deleted_count = cursor.rowcount
                logger.info(f"🗑️ Deleted {deleted_count} scans for user {user_id}")
                return deleted_count
                
        except sqlite3.Error as e:
            logger.error(f"❌ Error deleting user scans: {e}")
            return 0
        finally:
            conn.close()
    
    def update_scan_notes(self, user_id: int, scan_id: int, notes: str) -> bool:
        """
        Update notes for a specific scan
        
        Args:
            user_id: The user's ID
            scan_id: The scan ID
            notes: New notes content
            
        Returns:
            True if updated successfully, False otherwise
        """
        conn = self.create_connection()
        if not conn:
            return False
            
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_history 
                    SET notes = ? 
                    WHERE user_id = ? AND scan_id = ?
                """, (notes, user_id, scan_id))
                
                if cursor.rowcount > 0:
                    logger.info(f"📝 Updated notes for scan {scan_id}")
                    return True
                else:
                    return False
                    
        except sqlite3.Error as e:
            logger.error(f"❌ Error updating scan notes: {e}")
            return False
        finally:
            conn.close()
    
    def get_scan_count(self, user_id: int = None) -> int:
        """
        Get total scan count (for a specific user or all users)
        
        Args:
            user_id: Specific user ID (None for all users)
            
        Returns:
            Total number of scans
        """
        conn = self.create_connection()
        if not conn:
            return 0
            
        try:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute("SELECT COUNT(*) as count FROM scan_history WHERE user_id = ?", (user_id,))
            else:
                cursor.execute("SELECT COUNT(*) as count FROM scan_history")
            
            return cursor.fetchone()['count']
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error getting scan count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_recent_scans(self, user_id: int, limit: int = 10) -> List[Dict]:
        """
        Get user's most recent scans
        
        Args:
            user_id: The user's ID
            limit: Maximum number of scans to return
            
        Returns:
            List of recent scan dictionaries
        """
        return self.get_user_scans(user_id, limit=limit, offset=0)
    
    def search_scans(self, user_id: int, search_term: str, limit: int = 50) -> List[Dict]:
        """
        Search user's scans by target or notes using FTS for better performance
        
        Args:
            user_id: The user's ID
            search_term: Term to search for
            limit: Maximum number of results
            
        Returns:
            List of matching scan dictionaries
        """
        if not search_term:
            return []
            
        conn = self.create_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor()
            
            # Check if FTS table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history_fts'")
            if cursor.fetchone():
                # Use FTS for more efficient searching
                query = """
                    SELECT 
                        s.scan_id, s.scan_type, s.target, s.scan_parameters, s.scan_results,
                        s.scan_command, s.status, s.duration, s.hosts_found, s.ports_found,
                        s.vulnerabilities_found, s.threat_level, s.notes, s.timestamp
                    FROM 
                        scan_history s
                    JOIN 
                        scan_history_fts f ON s.scan_id = f.rowid
                    WHERE 
                        s.user_id = ? AND scan_history_fts MATCH ?
                    ORDER BY 
                        s.timestamp DESC
                    LIMIT ?
                """
                
                # Format the search term for FTS
                fts_term = f"{search_term}*"
                cursor.execute(query, (user_id, fts_term, limit))
            else:
                # Fallback to LIKE if FTS not available
                query = """
                    SELECT 
                        scan_id, scan_type, target, scan_parameters, scan_results,
                        scan_command, status, duration, hosts_found, ports_found,
                        vulnerabilities_found, threat_level, notes, timestamp
                    FROM 
                        scan_history
                    WHERE 
                        user_id = ? AND (
                            target LIKE ? OR 
                            notes LIKE ? OR
                            scan_command LIKE ? OR
                            scan_parameters LIKE ? OR
                            scan_results LIKE ?
                        )
                    ORDER BY 
                        timestamp DESC
                    LIMIT ?
                """
                
                search_pattern = f"%{search_term}%"
                cursor.execute(query, (
                    user_id, 
                    search_pattern, 
                    search_pattern, 
                    search_pattern, 
                    search_pattern, 
                    search_pattern, 
                    limit
                ))
            
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries and parse JSON fields
            scans = []
            for row in rows:
                scan = dict(row)
                
                # Parse JSON fields
                if scan['scan_parameters']:
                    try:
                        scan['scan_parameters'] = json.loads(scan['scan_parameters'])
                    except json.JSONDecodeError:
                        scan['scan_parameters'] = {}
                
                if scan['scan_results']:
                    try:
                        scan['scan_results'] = json.loads(scan['scan_results'])
                    except json.JSONDecodeError:
                        scan['scan_results'] = {}
                
                # Format timestamp for display
                scan['formatted_timestamp'] = self._format_timestamp(scan['timestamp'])
                scan['time_ago'] = self._time_ago(scan['timestamp'])
                
                scans.append(scan)
            
            logger.info(f"🔍 Search for '{search_term}' found {len(scans)} matches for user {user_id}")
            return scans
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error searching scans: {e}")
            return []
        finally:
            conn.close()
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return timestamp_str
    
    def _time_ago(self, timestamp_str: str) -> str:
        """Convert timestamp to 'time ago' format"""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            now = datetime.now()
            diff = now - dt
            
            if diff.days > 0:
                return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                return "Just now"
        except:
            return "Unknown"

    def _setup_search_index(self):
        """Setup SQLite FTS (Full-Text Search) virtual table for faster searching"""
        conn = self.create_connection()
        if not conn:
            logger.error("Failed to setup search index - cannot connect to database")
            return
            
        try:
            cursor = conn.cursor()
            
            # Check if FTS5 is available
            cursor.execute("SELECT sqlite_source_id()")
            sqlite_version = cursor.fetchone()[0]
            
            # First, check if our virtual table already exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history_fts'")
            if cursor.fetchone() is None:
                logger.info("Creating full-text search index for scan history")
                
                # Create FTS virtual table (use FTS5 if available, otherwise FTS4)
                if "FTS5" in sqlite_version:
                    cursor.execute("""
                        CREATE VIRTUAL TABLE IF NOT EXISTS scan_history_fts USING FTS5(
                            target, notes, scan_command, scan_parameters, scan_results,
                            content=scan_history, content_rowid=scan_id
                        )
                    """)
                else:
                    cursor.execute("""
                        CREATE VIRTUAL TABLE IF NOT EXISTS scan_history_fts USING FTS4(
                            target, notes, scan_command, scan_parameters, scan_results,
                            content=scan_history, notindexed=scan_parameters, notindexed=scan_results
                        )
                    """)
                    
                # Create triggers to keep the FTS index updated
                cursor.execute("""
                    CREATE TRIGGER IF NOT EXISTS scan_history_ai AFTER INSERT ON scan_history BEGIN
                        INSERT INTO scan_history_fts(rowid, target, notes, scan_command, scan_parameters, scan_results)
                        VALUES (new.scan_id, new.target, new.notes, new.scan_command, new.scan_parameters, new.scan_results);
                    END
                """)
                
                cursor.execute("""
                    CREATE TRIGGER IF NOT EXISTS scan_history_ad AFTER DELETE ON scan_history BEGIN
                        DELETE FROM scan_history_fts WHERE rowid = old.scan_id;
                    END
                """)
                
                cursor.execute("""
                    CREATE TRIGGER IF NOT EXISTS scan_history_au AFTER UPDATE ON scan_history BEGIN
                        DELETE FROM scan_history_fts WHERE rowid = old.scan_id;
                        INSERT INTO scan_history_fts(rowid, target, notes, scan_command, scan_parameters, scan_results)
                        VALUES (new.scan_id, new.target, new.notes, new.scan_command, new.scan_parameters, new.scan_results);
                    END
                """)
                
                # Populate the FTS table with existing data
                cursor.execute("""
                    INSERT INTO scan_history_fts(rowid, target, notes, scan_command, scan_parameters, scan_results)
                    SELECT scan_id, target, notes, scan_command, scan_parameters, scan_results FROM scan_history
                """)
                
                conn.commit()
                logger.info("✅ Full-text search index created and populated")
            
        except sqlite3.Error as e:
            logger.error(f"❌ Error setting up search index: {e}")
            # Continue without search index
        finally:
            conn.close()

# Create global instance
scan_history_db = ScanHistoryDB()

def test_scan_history():
    """Test function for the ScanHistoryDB class"""
    print("🧪 Testing SANA Scan History Database")
    print("=" * 50)
    
    # Test user ID
    test_user_id = 1
    
    # Test adding a scan
    print("\n1. Testing add_scan...")
    scan_id = scan_history_db.add_scan(
        user_id=test_user_id,
        scan_type='network',
        target='192.168.1.1',
        scan_parameters={'scan_type': 'comprehensive', 'timing': 'T3'},
        scan_results={'hosts_found': 5, 'open_ports': 15},
        scan_command='nmap -sS -sV -T3 192.168.1.1',
        duration=120,
        hosts_found=5,
        ports_found=15,
        vulnerabilities_found=2,
        threat_level='medium'
    )
    print(f"Added scan with ID: {scan_id}")
    
    # Test getting user scans
    print("\n2. Testing get_user_scans...")
    scans = scan_history_db.get_user_scans(test_user_id)
    print(f"Retrieved {len(scans)} scans")
    
    # Test getting stats
    print("\n3. Testing get_user_scan_stats...")
    stats = scan_history_db.get_user_scan_stats(test_user_id)
    print(f"Total scans: {stats.get('total_scans', 0)}")
    print(f"Success rate: {stats.get('success_rate', 0)}%")
    
    # Test search
    print("\n4. Testing search_scans...")
    search_results = scan_history_db.search_scans(test_user_id, '192.168')
    print(f"Search results: {len(search_results)} scans")
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    test_scan_history()