"""
SANA Toolkit - Comprehensive Scan History Routes
Flask routes for viewing, filtering, and managing user scan history
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, send_file
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json
import io
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename
import sqlite3 # Added for scan activity data

# Import authentication decorator
try:
    from routes.auth_routes import login_required
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

# Import scan history model
try:
    from models.scan_history_model import scan_history_db
except ImportError:
    import sys
    import os
    # Add the project root to Python path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from models.scan_history_model import scan_history_db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
scan_history_bp = Blueprint('scan_history', __name__)

# ===== MAIN SCAN HISTORY PAGE ===== #

@scan_history_bp.route('/scan-history')
@login_required
def scan_history():
    """Main scan history page with filters and search"""
    user_id = session.get('user_id')
    
    # Get user's scan statistics for dashboard
    try:
        stats = scan_history_db.get_user_scan_stats(user_id)
        recent_scans = scan_history_db.get_recent_scans(user_id, limit=5)
        
        logger.info(f"📊 Displaying scan history for user {user_id}: {stats.get('total_scans', 0)} total scans")
        
        return render_template('history/scan_history.html', 
                             stats=stats, 
                             recent_scans=recent_scans,
                             page_title="My Scan History")
                             
    except Exception as e:
        logger.error(f"❌ Error loading scan history page: {e}")
        flash('Error loading scan history. Please try again.', 'error')
        return redirect(url_for('index'))

# ===== API ENDPOINTS FOR DYNAMIC LOADING ===== #

@scan_history_bp.route('/scan-history/api/scans')
@scan_history_bp.route('/api/scans')
@login_required
def api_get_scans():
    """API endpoint to get user's scans with filtering and pagination"""
    user_id = session.get('user_id')
    
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        offset = (page - 1) * per_page
        
        # Build filters from query parameters
        filters = {}
        if request.args.get('scan_type'):
            filters['scan_type'] = request.args.get('scan_type')
        if request.args.get('target'):
            filters['target'] = request.args.get('target')
        if request.args.get('status'):
            filters['status'] = request.args.get('status')
        if request.args.get('threat_level'):
            filters['threat_level'] = request.args.get('threat_level')
        if request.args.get('date_from'):
            filters['date_from'] = request.args.get('date_from')
        if request.args.get('date_to'):
            filters['date_to'] = request.args.get('date_to')
        if request.args.get('search'):
            filters['search'] = request.args.get('search')
        
        # Get scans with filters
        scans = scan_history_db.get_user_scans(
            user_id=user_id,
            filters=filters,
            limit=per_page,
            offset=offset
        )
        
        # Get total count for pagination
        total_scans = scan_history_db.get_scan_count(user_id)
        
        return jsonify({
            'success': True,
            'scans': scans,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_scans,
                'pages': (total_scans + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error getting scans via API: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve scans'
        }), 500

@scan_history_bp.route('/scan-history/api/scan/<int:scan_id>')
@login_required  
def get_scan_details(scan_id):
    """Get detailed information about a specific scan"""
    try:
        if not scan_history_db:
            return jsonify({
                'status': 'error',
                'message': 'Scan history not available'
            }), 503
            
        user_id = session['user_id']
        scan = scan_history_db.get_scan_by_id(user_id, scan_id)
        
        if not scan:
            return jsonify({
                'status': 'error',
                'message': 'Scan not found or access denied'
            }), 404
            
        # Format the scan data for the frontend
        formatted_scan = {
            'scan_id': scan['scan_id'],
            'scan_type': scan['scan_type'],
            'target': scan['target'],
            'scan_command': scan['scan_command'],
            'status': scan['status'],
            'duration': scan['duration'],
            'hosts_found': scan['hosts_found'] or 0,
            'ports_found': scan['ports_found'] or 0,
            'vulnerabilities_found': scan['vulnerabilities_found'] or 0,
            'threat_level': scan['threat_level'],
            'notes': scan['notes'],
            'timestamp': scan['timestamp'],
            'formatted_timestamp': scan.get('formatted_timestamp'),
            'time_ago': scan.get('time_ago'),
            'scan_parameters': scan.get('scan_parameters', {}),
            'scan_results': scan.get('scan_results', {})
        }
        
        logger.info(f"📋 Retrieved scan details for scan {scan_id} by user {user_id}")
        
        return jsonify(formatted_scan)
        
    except Exception as e:
        logger.error(f"❌ Error retrieving scan details for scan {scan_id}: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve scan details'
        }), 500

@scan_history_bp.route('/scan-history/api/stats')
@scan_history_bp.route('/api/stats')
@login_required
def api_get_stats():
    """API endpoint to get user's scan statistics"""
    user_id = session.get('user_id')
    
    try:
        stats = scan_history_db.get_user_scan_stats(user_id)
        
        # Map backend field names to frontend expected names
        stats['total_threats'] = stats.get('total_vulnerabilities', 0)
        stats['total_hosts'] = stats.get('total_hosts_found', 0)
        
        # Add scan activity data for timeline chart (last 30 days)
        scan_activity = {}
        today = datetime.now().date()
        
        # Initialize dict with zeros for all 30 days
        for i in range(30, -1, -1):
            day_date = today - timedelta(days=i)
            scan_activity[day_date.strftime("%Y-%m-%d")] = 0
            
        # Fill in actual values from database
        conn = scan_history_db.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT date(timestamp) as scan_date, COUNT(*) as count
                    FROM scan_history 
                    WHERE user_id = ? AND timestamp >= date('now', '-30 days')
                    GROUP BY date(timestamp)
                    ORDER BY scan_date
                """, (user_id,))
                
                for row in cursor.fetchall():
                    scan_date = row['scan_date']
                    if scan_date in scan_activity:
                        scan_activity[scan_date] = row['count']
                        
            except sqlite3.Error as e:
                logger.error(f"❌ Error getting scan activity: {e}")
            finally:
                conn.close()
                
        # Add to stats
        stats['scan_activity'] = scan_activity
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"❌ Error getting scan stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve statistics'
        }), 500

# ===== SCAN MANAGEMENT ===== #

@scan_history_bp.route('/api/scan/<int:scan_id>/delete', methods=['DELETE'])
@login_required
def api_delete_scan(scan_id):
    """API endpoint to delete a specific scan"""
    user_id = session.get('user_id')
    
    try:
        success = scan_history_db.delete_scan(user_id, scan_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Scan deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scan not found or could not be deleted'
            }), 404
            
    except Exception as e:
        logger.error(f"❌ Error deleting scan: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete scan'
        }), 500

@scan_history_bp.route('/api/scan/<int:scan_id>/notes', methods=['POST'])
@login_required
def api_update_scan_notes(scan_id):
    """API endpoint to update scan notes"""
    user_id = session.get('user_id')
    
    try:
        data = request.get_json()
        notes = data.get('notes', '')
        
        success = scan_history_db.update_scan_notes(user_id, scan_id, notes)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Notes updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scan not found or could not be updated'
            }), 404
            
    except Exception as e:
        logger.error(f"❌ Error updating scan notes: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to update notes'
        }), 500

@scan_history_bp.route('/scan-history/api/scan/<int:scan_id>/update-threat-level', methods=['POST'])
@login_required
def api_update_scan_threat_level(scan_id):
    """API endpoint to update scan threat level (for testing)"""
    user_id = session.get('user_id')
    
    try:
        data = request.get_json()
        new_threat_level = data.get('threat_level', 'low')
        
        # Validate threat level
        if new_threat_level not in ['low', 'medium', 'high', 'critical']:
            return jsonify({'error': 'Invalid threat level'}), 400
        
        # Update the scan's threat level
        conn = scan_history_db.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_history 
                    SET threat_level = ? 
                    WHERE user_id = ? AND scan_id = ?
                """, (new_threat_level, user_id, scan_id))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    logger.info(f"✅ Updated scan {scan_id} threat level to {new_threat_level}")
                    return jsonify({
                        'success': True,
                        'message': f'Threat level updated to {new_threat_level}'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Scan not found or access denied'
                    }), 404
                    
            except sqlite3.Error as e:
                logger.error(f"❌ Database error updating threat level: {e}")
                return jsonify({'error': 'Database error'}), 500
            finally:
                conn.close()
        else:
            return jsonify({'error': 'Database connection failed'}), 500
            
    except Exception as e:
        logger.error(f"❌ Error updating scan threat level: {e}")
        return jsonify({'error': 'Failed to update threat level'}), 500

@scan_history_bp.route('/api/scans/bulk-delete', methods=['DELETE'])
@login_required
def api_bulk_delete_scans():
    """API endpoint to delete multiple scans"""
    user_id = session.get('user_id')
    
    try:
        data = request.get_json()
        scan_ids = data.get('scan_ids', [])
        
        if not scan_ids:
            return jsonify({
                'success': False,
                'error': 'No scan IDs provided'
            }), 400
        
        deleted_count = 0
        for scan_id in scan_ids:
            if scan_history_db.delete_scan(user_id, scan_id):
                deleted_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} scans successfully',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        logger.error(f"❌ Error bulk deleting scans: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete scans'
        }), 500

# ===== SEARCH FUNCTIONALITY ===== #

@scan_history_bp.route('/api/search')
@login_required
def api_search_scans():
    """API endpoint to search scans"""
    user_id = session.get('user_id')
    
    try:
        search_term = request.args.get('q', '')
        limit = int(request.args.get('limit', 50))
        
        if not search_term:
            return jsonify({
                'success': False,
                'error': 'Search term is required'
            }), 400
        
        results = scan_history_db.search_scans(user_id, search_term, limit)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"❌ Error searching scans: {e}")
        return jsonify({
            'success': False,
            'error': 'Search failed'
        }), 500

# ===== EXPORT FUNCTIONALITY ===== #

@scan_history_bp.route('/export/csv')
@login_required
def export_scans_csv():
    """Export user's scans to CSV format"""
    user_id = session.get('user_id')
    
    try:
        # Get filter parameters
        filters = get_filters_from_request(request)
        include_details = request.args.get('include_details', 'false').lower() == 'true'
        
        # Get all user scans (no limit)
        scans = scan_history_db.get_user_scans(user_id, filters=filters, limit=10000)
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        header = [
            'Scan ID', 'Type', 'Target', 'Status', 'Duration (s)', 
            'Hosts Found', 'Ports Found', 'Vulnerabilities', 
            'Threat Level', 'Timestamp', 'Notes'
        ]
        
        # Add detailed headers if requested
        if include_details:
            header.extend(['Command', 'Parameters'])
            
        writer.writerow(header)
        
        # Write scan data
        for scan in scans:
            row = [
                scan['scan_id'],
                scan['scan_type'].title(),
                scan['target'],
                scan['status'].title(),
                scan['duration'],
                scan['hosts_found'],
                scan['ports_found'],
                scan['vulnerabilities_found'],
                scan['threat_level'].title(),
                scan['formatted_timestamp'],
                scan.get('notes', '')
            ]
            
            # Add detailed fields if requested
            if include_details:
                row.extend([
                    scan.get('scan_command', ''),
                    json.dumps(scan.get('scan_parameters', {}), indent=2)
                ])
                
            writer.writerow(row)
        
        # Create response
        output.seek(0)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sana_scan_history_{timestamp}.csv"
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"❌ Error exporting CSV: {e}")
        flash('Failed to export scan history to CSV', 'error')
        return redirect(url_for('scan_history.scan_history'))

@scan_history_bp.route('/export/pdf')
@login_required
def export_scans_pdf():
    """Export user's scans to PDF format with beautiful branding and modern design"""
    user_id = session.get('user_id')
    
    try:
        # Get filter parameters
        filters = get_filters_from_request(request)
        include_details = request.args.get('include_details', 'false').lower() == 'true'
        
        # Get user scans and stats
        scans = scan_history_db.get_user_scans(user_id, filters=filters, limit=1000)
        stats = scan_history_db.get_user_scan_stats(user_id)
        
        # Create PDF content
        buffer = io.BytesIO()
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, Image, PageBreak, Frame, PageTemplate
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.pdfgen import canvas
        
        # Create PDF document with custom page template
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.5*inch, leftMargin=0.5*inch, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        # Define custom colors for branding
        primary_color = colors.HexColor('#1e1e2f')  # Dark blue
        accent_color = colors.HexColor('#3b82f6')   # Blue accent
        success_color = colors.HexColor('#10b981')  # Green
        warning_color = colors.HexColor('#f59e0b')  # Orange
        danger_color = colors.HexColor('#ef4444')   # Red
        critical_color = colors.HexColor('#991b1b') # Dark red
        light_bg = colors.HexColor('#f8fafc')       # Light background
        text_color = colors.HexColor('#1f2937')     # Dark text
        
        # Create custom styles
        styles = getSampleStyleSheet()
        
        # Title style with branding
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=primary_color,
            alignment=1,  # Center
            spaceAfter=20,
            fontName='Helvetica-Bold'
        )
        
        # Subtitle style
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=accent_color,
            alignment=1,
            spaceAfter=15,
            fontName='Helvetica-Bold'
        )
        
        # Section header style
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=primary_color,
            spaceAfter=10,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=accent_color,
            borderPadding=8,
            backColor=light_bg
        )
        
        # Normal text style
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            textColor=text_color,
            spaceAfter=6,
            fontName='Helvetica'
        )
        
        # Stats card style
        stats_style = ParagraphStyle(
            'StatsCard',
            parent=styles['Normal'],
            fontSize=12,
            textColor=text_color,
            alignment=1,
            fontName='Helvetica-Bold',
            backColor=light_bg,
            borderWidth=1,
            borderColor=colors.grey,
            borderPadding=10
        )
        
        # Build content elements
        elements = []
        
        # Beautiful header with branding
        elements.append(Paragraph("🔍 SANA TOOLKIT", title_style))
        elements.append(Paragraph("Security Analysis & Network Assessment", subtitle_style))
        elements.append(Paragraph("Scan History Report", subtitle_style))
        elements.append(Spacer(1, 20))
        
        # Report metadata
        metadata_style = ParagraphStyle(
            'Metadata',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.grey,
            alignment=1,
            spaceAfter=20
        )
        elements.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", metadata_style))
        elements.append(Paragraph(f"Total Scans: {len(scans)} | User ID: {user_id}", metadata_style))
        elements.append(Spacer(1, 30))
        
        # Statistics summary with beautiful cards
        elements.append(Paragraph("📊 Scan Statistics Overview", section_style))
        
        # Create stats grid
        stats_grid_data = [
            [
                Paragraph(f"<b>{stats.get('total_scans', 0)}</b><br/>Total Scans", stats_style),
                Paragraph(f"<b>{stats.get('success_rate', 0)}%</b><br/>Success Rate", stats_style),
                Paragraph(f"<b>{stats.get('total_hosts_found', 0)}</b><br/>Hosts Found", stats_style)
            ],
            [
                Paragraph(f"<b>{stats.get('total_ports_found', 0)}</b><br/>Ports Found", stats_style),
                Paragraph(f"<b>{stats.get('total_vulnerabilities', 0)}</b><br/>Vulnerabilities", stats_style),
                Paragraph(f"<b>{format_duration(stats.get('avg_duration', 0))}</b><br/>Avg Duration", stats_style)
            ]
        ]
        
        stats_table = Table(stats_grid_data, colWidths=[2*inch, 2*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, light_bg]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROUNDEDCORNERS', [6]),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 30))
        
        # Threat level distribution
        if stats.get('threat_breakdown'):
            elements.append(Paragraph("⚠️ Threat Level Distribution", section_style))
            
            threat_data = [['Threat Level', 'Count', 'Percentage']]
            for level, count in stats['threat_breakdown'].items():
                percentage = (count / stats['total_scans'] * 100) if stats['total_scans'] > 0 else 0
                threat_data.append([
                    level.upper(),
                    str(count),
                    f"{percentage:.1f}%"
                ])
            
            threat_table = Table(threat_data, colWidths=[1.5*inch, 1*inch, 1*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), accent_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
            ]))
            elements.append(threat_table)
            elements.append(Spacer(1, 30))
        
        # Scan history table
        elements.append(Paragraph("📋 Detailed Scan History", section_style))
        
        if scans:
            # Enhanced table header
            table_header = ['Scan ID', 'Type', 'Target', 'Threat Level', 'Status', 'Date']
            
            # Table data with enhanced formatting
            table_data = [table_header]
            
            for scan in scans:
                # Color-code threat levels
                threat_level = scan['threat_level'].upper()
                if threat_level == 'CRITICAL':
                    threat_cell = f"🔴 {threat_level}"
                elif threat_level == 'HIGH':
                    threat_cell = f"🟠 {threat_level}"
                elif threat_level == 'MEDIUM':
                    threat_cell = f"🟡 {threat_level}"
                else:
                    threat_cell = f"🟢 {threat_level}"
                
                # Add scan type icons
                scan_type = scan['scan_type'].title()
                if scan_type == 'Network':
                    scan_type = f"🌐 {scan_type}"
                elif scan_type == 'Virustotal':
                    scan_type = f"🦠 {scan_type}"
                elif scan_type == 'Dns':
                    scan_type = f"🔗 {scan_type}"
                elif scan_type == 'Host Discovery':
                    scan_type = f"🔍 {scan_type}"
                
                row = [
                    str(scan['scan_id']),
                    scan_type,
                    scan['target'][:30] + "..." if len(scan['target']) > 30 else scan['target'],
                    threat_cell,
                    "✅ " + scan['status'].title() if scan['status'] == 'completed' else "⏳ " + scan['status'].title(),
                    scan['formatted_timestamp']
                ]
                table_data.append(row)
            
            # Create enhanced table
            scan_table = Table(table_data, repeatRows=1, colWidths=[0.5*inch, 1.2*inch, 2*inch, 1*inch, 1*inch, 1.2*inch])
            
            # Beautiful table styling
            scan_table.setStyle(TableStyle([
                # Header styling
                ('BACKGROUND', (0, 0), (-1, 0), primary_color),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('TOPPADDING', (0, 0), (-1, 0), 10),
                
                # Alternating row colors
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
                
                # Grid styling
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # Scan ID centered
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),  # Threat level centered
                ('ALIGN', (4, 0), (4, -1), 'CENTER'),  # Status centered
                
                # Font styling for data rows
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
            ]))
            
            elements.append(scan_table)
            elements.append(Spacer(1, 20))
            
            # Add detailed scan information if requested
            if include_details and scans:
                elements.append(PageBreak())
                elements.append(Paragraph("🔬 Detailed Scan Information", section_style))
                
                # Show details for first 5 scans to avoid PDF bloat
                for i, scan in enumerate(scans[:5]):
                    elements.append(Paragraph(f"<b>Scan #{scan['scan_id']} - {scan['scan_type'].title()}</b>", normal_style))
                    elements.append(Paragraph(f"Target: {scan['target']}", normal_style))
                    elements.append(Paragraph(f"Command: {scan.get('scan_command', 'N/A')}", normal_style))
                    elements.append(Paragraph(f"Duration: {format_duration(scan['duration'])}", normal_style))
                    elements.append(Paragraph(f"Hosts Found: {scan['hosts_found']} | Ports Found: {scan['ports_found']} | Vulnerabilities: {scan['vulnerabilities_found']}", normal_style))
                    elements.append(Paragraph(f"Notes: {scan.get('notes', 'No notes')}", normal_style))
                    elements.append(Spacer(1, 10))
        
        # Footer with branding
        elements.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=1,
            spaceBefore=20
        )
        elements.append(Paragraph("Generated by SANA Toolkit - Advanced Security Analysis Platform", footer_style))
        elements.append(Paragraph("🔒 Secure • 🚀 Fast • 📊 Comprehensive", footer_style))
        
        # Build PDF
        doc.build(elements)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sana_scan_report_{timestamp}.pdf"
        
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"❌ Error exporting PDF: {e}")
        flash('Failed to export scan history to PDF', 'error')
        return redirect(url_for('scan_history.scan_history'))

@scan_history_bp.route('/scan-history/export/json')
@login_required
def export_single_scan_json():
    """Export a single scan to JSON format"""
    user_id = session.get('user_id')
    scan_id = request.args.get('scan_id')
    
    if not scan_id:
        return jsonify({'error': 'Scan ID is required'}), 400
    
    try:
        scan_id = int(scan_id)
        scan = scan_history_db.get_scan_by_id(user_id, scan_id)
        
        if not scan:
            return jsonify({'error': 'Scan not found or access denied'}), 404
        
        # Create filename with scan details
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{scan_id}_{scan['scan_type']}_{timestamp}.json"
        
        # Return JSON response
        return send_file(
            io.BytesIO(json.dumps(scan, indent=2, default=str).encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
    except ValueError:
        return jsonify({'error': 'Invalid scan ID'}), 400
    except Exception as e:
        logger.error(f"❌ Error exporting single scan JSON: {e}")
        return jsonify({'error': 'Failed to export scan'}), 500

@scan_history_bp.route('/api/export')
@login_required
def api_export_scans():
    """API route to export scans - redirects to appropriate format handler"""
    export_format = request.args.get('format', 'csv').lower()
    
    if export_format == 'pdf':
        return redirect(url_for('scan_history.export_scans_pdf', **request.args))
    else:
        return redirect(url_for('scan_history.export_scans_csv', **request.args))

# Helper function to get filters from request
def get_filters_from_request(request):
    """Extract filter parameters from request"""
    filters = {}
    
    if request.args.get('scan_type'):
        filters['scan_type'] = request.args.get('scan_type')
    
    if request.args.get('target'):
        filters['target'] = request.args.get('target')
    
    if request.args.get('status'):
        filters['status'] = request.args.get('status')
    
    if request.args.get('threat_level'):
        filters['threat_level'] = request.args.get('threat_level')
    
    if request.args.get('date_from'):
        filters['date_from'] = request.args.get('date_from')
    
    if request.args.get('date_to'):
        filters['date_to'] = request.args.get('date_to')
    
    if request.args.get('search'):
        filters['search'] = request.args.get('search')
    
    return filters

# ===== ANALYTICS AND INSIGHTS ===== #

@scan_history_bp.route('/analytics')
@login_required
def scan_analytics():
    """Advanced analytics page for scan history"""
    user_id = session.get('user_id')
    
    try:
        stats = scan_history_db.get_user_scan_stats(user_id)
        
        # Get additional analytics data
        recent_scans = scan_history_db.get_user_scans(user_id, limit=50)
        
        # Calculate trends (simple example)
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        week_filters = {'date_from': week_ago.strftime('%Y-%m-%d')}
        month_filters = {'date_from': month_ago.strftime('%Y-%m-%d')}
        
        week_scans = scan_history_db.get_user_scans(user_id, filters=week_filters, limit=1000)
        month_scans = scan_history_db.get_user_scans(user_id, filters=month_filters, limit=1000)
        
        analytics_data = {
            'weekly_count': len(week_scans),
            'monthly_count': len(month_scans),
            'most_scanned_targets': {},  # Could implement this
            'scan_frequency': {},  # Could implement this
        }
        
        return render_template('history/scan_analytics.html',
                             stats=stats,
                             analytics=analytics_data,
                             recent_scans=recent_scans[:10])
                             
    except Exception as e:
        logger.error(f"❌ Error loading analytics: {e}")
        flash('Error loading analytics. Please try again.', 'error')
        return redirect(url_for('scan_history.scan_history'))

# ===== HELPER FUNCTIONS ===== #

def get_scan_type_icon(scan_type: str) -> str:
    """Get icon class for scan type"""
    icons = {
        'network': 'fas fa-network-wired',
        'dns': 'fas fa-globe',
        'virustotal': 'fas fa-shield-virus',
        'host_discovery': 'fas fa-server'
    }
    return icons.get(scan_type, 'fas fa-search')

def get_threat_level_color(threat_level: str) -> str:
    """Get color class for threat level"""
    colors = {
        'low': 'success',
        'medium': 'warning', 
        'high': 'danger',
        'critical': 'dark'
    }
    return colors.get(threat_level, 'secondary')

def format_duration(seconds: int) -> str:
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

# Add template filters
@scan_history_bp.app_template_filter('scan_icon')
def scan_icon_filter(scan_type):
    return get_scan_type_icon(scan_type)

@scan_history_bp.app_template_filter('threat_color')  
def threat_color_filter(threat_level):
    return get_threat_level_color(threat_level)

@scan_history_bp.app_template_filter('format_duration')
def duration_filter(seconds):
    return format_duration(seconds)

# ===== ERROR HANDLERS ===== #

@scan_history_bp.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors in scan history routes"""
    return render_template('errors/404.html'), 404

@scan_history_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors in scan history routes"""
    logger.error(f"Internal error in scan history: {error}")
    return render_template('errors/500.html'), 500

# ===== BACKWARDS COMPATIBILITY ===== #

@scan_history_bp.route('/history')
@login_required
def history_redirect():
    """Redirect old history URL to new scan history URL"""
    return redirect(url_for('scan_history.scan_history'))

# Test function
def test_scan_history_routes():
    """Test function for scan history routes"""
    print("🧪 Testing SANA Scan History Routes")
    print("=" * 50)
    
    # This would require a Flask app context to test properly
    print("✅ Routes registered successfully")
    print("📊 Available endpoints:")
    print("  • /scan-history - Main history page")
    print("  • /api/scans - Get scans with filtering")
    print("  • /api/scan/<id> - Get scan details") 
    print("  • /api/stats - Get user statistics")
    print("  • /export/csv - Export to CSV")
    print("  • /export/pdf - Export to PDF")
    print("  • /analytics - Advanced analytics")

if __name__ == "__main__":
    test_scan_history_routes()

@scan_history_bp.route('/scan-history/api/debug/threat-levels')
@login_required
def debug_threat_levels():
    """Debug endpoint to check threat levels in database"""
    user_id = session.get('user_id')
    
    try:
        conn = scan_history_db.create_connection()
        if conn:
            cursor = conn.cursor()
            
            # Get all threat levels exactly as stored
            cursor.execute("""
                SELECT threat_level, COUNT(*) as count
                FROM scan_history 
                WHERE user_id = ?
                GROUP BY threat_level
            """, (user_id,))
            
            raw_threats = cursor.fetchall()
            
            # Get some sample scans with their threat levels
            cursor.execute("""
                SELECT scan_id, scan_type, threat_level, target
                FROM scan_history 
                WHERE user_id = ?
                ORDER BY scan_id DESC
                LIMIT 10
            """, (user_id,))
            
            sample_scans = cursor.fetchall()
            
            conn.close()
            
            return jsonify({
                'success': True,
                'raw_threat_levels': {row['threat_level']: row['count'] for row in raw_threats},
                'sample_scans': [
                    {
                        'scan_id': row['scan_id'],
                        'scan_type': row['scan_type'],
                        'threat_level': row['threat_level'],
                        'target': row['target'][:50] + '...' if len(row['target']) > 50 else row['target']
                    }
                    for row in sample_scans
                ]
            })
            
    except Exception as e:
        logger.error(f"❌ Error in debug endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@scan_history_bp.route('/scan-history/api/recalculate-threat-levels', methods=['POST'])
@login_required
def recalculate_threat_levels():
    """Recalculate threat levels for all existing scans using updated logic"""
    user_id = session.get('user_id')
    
    try:
        conn = scan_history_db.create_connection()
        if conn:
            cursor = conn.cursor()
            
            # Get all scans for the user
            cursor.execute("""
                SELECT scan_id, scan_type, scan_results, vulnerabilities_found, ports_found
                FROM scan_history 
                WHERE user_id = ?
            """, (user_id,))
            
            scans = cursor.fetchall()
            updated_count = 0
            
            for scan in scans:
                scan_id = scan['scan_id']
                scan_type = scan['scan_type']
                scan_results = scan['scan_results']
                vulnerabilities_found = scan['vulnerabilities_found']
                ports_found = scan['ports_found']
                
                # Parse scan_results if it's a string
                if isinstance(scan_results, str):
                    try:
                        scan_results = json.loads(scan_results)
                    except:
                        scan_results = {}
                
                # Calculate new threat level using updated logic
                new_threat_level = scan_history_db.calculate_threat_level(
                    scan_type, scan_results, vulnerabilities_found, ports_found
                )
                
                # Update the scan with new threat level
                cursor.execute("""
                    UPDATE scan_history 
                    SET threat_level = ? 
                    WHERE scan_id = ? AND user_id = ?
                """, (new_threat_level, scan_id, user_id))
                
                if cursor.rowcount > 0:
                    updated_count += 1
                    logger.info(f"✅ Updated scan {scan_id} threat level to {new_threat_level}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Recalculated threat levels for {updated_count} scans")
            
            return jsonify({
                'success': True,
                'message': f'Updated threat levels for {updated_count} scans',
                'updated_count': updated_count
            })
            
    except Exception as e:
        logger.error(f"❌ Error recalculating threat levels: {e}")
        return jsonify({'error': 'Failed to recalculate threat levels'}), 500