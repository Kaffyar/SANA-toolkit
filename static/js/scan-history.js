/**
 * SANA Toolkit - Scan History JavaScript
 * Handles all scan history functionality including filtering, sorting, pagination, and data visualization
 */

class ScanHistoryManager {
    constructor() {
        this.currentPage = 1;
        this.itemsPerPage = 20;
        this.currentSort = { field: 'timestamp', direction: 'desc' };
        this.currentFilters = {};
        this.currentView = 'table';
        this.scans = [];
        this.filteredScans = [];
        this.totalScans = 0;
        this.scanDetailsCache = {}; // Cache for scan details
        this.selectedScans = []; // Store selected scans for comparison
        
        // API endpoints
        this.endpoints = {
            getScans: '/scan-history/api/scans',
            getScanDetails: '/scan-history/api/scan/',
            getStats: '/scan-history/api/stats',
            exportScans: '/export',
            deleteScan: '/api/scan/'
        };
        
        this.init();
    }

    async init() {
        this.initializeNotificationSystem();
        this.setupEventListeners();
        await this.loadStats();
        await this.loadScans();
        this.setupTooltips();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Search functionality
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.handleSearch(e.target.value);
                }, 300);
            });
        }

        // Filter dropdowns
        const filterSelects = [
            'scan-type-filter',
            'threat-level-filter', 
            'date-range-filter',
            'status-filter'
        ];

        filterSelects.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', () => this.applyFilters());
            }
        });

        // Date range handling
        const dateRangeFilter = document.getElementById('date-range-filter');
        if (dateRangeFilter) {
            dateRangeFilter.addEventListener('change', (e) => {
                const customRange = document.getElementById('custom-date-range');
                if (e.target.value === 'custom') {
                    customRange.style.display = 'block';
                } else {
                    customRange.style.display = 'none';
                    this.applyFilters();
                }
            });
        }

        // Custom date range apply
        const applyDateBtn = document.getElementById('apply-date-range');
        if (applyDateBtn) {
            applyDateBtn.addEventListener('click', () => this.applyFilters());
        }

        // Clear filters
        const clearFiltersBtn = document.getElementById('clear-filters');
        if (clearFiltersBtn) {
            clearFiltersBtn.addEventListener('click', () => this.clearFilters());
        }

        // View mode buttons
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.target.closest('.view-btn').dataset.view;
                this.switchView(view);
            });
        });

        // Table sorting
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', () => {
                const field = header.dataset.sort;
                this.handleSort(field);
            });
        });

        // Pagination
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');
        
        if (prevBtn) prevBtn.addEventListener('click', () => this.goToPage(this.currentPage - 1));
        if (nextBtn) nextBtn.addEventListener('click', () => this.goToPage(this.currentPage + 1));

        // Export functionality
        const exportBtn = document.getElementById('export-history');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportHistory());
        }

        // Modal controls
        const modal = document.getElementById('scan-detail-modal');
        const modalClose = document.getElementById('modal-close');
        const modalCloseBtn = document.getElementById('modal-close-btn');
        const modalBackdrop = modal?.querySelector('.modal-backdrop');

        [modalClose, modalCloseBtn, modalBackdrop].forEach(element => {
            if (element) {
                element.addEventListener('click', () => this.closeModal());
            }
        });

        // Refresh analytics button
        const refreshAnalyticsBtn = document.getElementById('refresh-analytics');
        if (refreshAnalyticsBtn) {
            refreshAnalyticsBtn.addEventListener('click', () => this.loadStats());
        }

        // Compare scans button
        const compareBtn = document.getElementById('compare-scans');
        if (compareBtn) {
            compareBtn.addEventListener('click', () => this.compareSelectedScans());
        }
        
        // Clear selection button
        const clearSelectionBtn = document.getElementById('clear-selection');
        if (clearSelectionBtn) {
            clearSelectionBtn.addEventListener('click', () => this.clearScanSelection());
        }

        // Select all checkbox
        const selectAllCheckbox = document.getElementById('select-all-scans');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', (e) => {
                this.toggleSelectAllScans(e.target.checked);
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeModal();
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                searchInput?.focus();
            }
        });
    }

    toggleSelectAllScans(checked) {
        // Clear current selection
        this.selectedScans = [];
        
        // If checked, add all filtered scans (limited to 4 max)
        if (checked) {
            // Get up to 4 scans to compare
            const maxScans = Math.min(4, this.filteredScans.length);
            this.selectedScans = [...this.filteredScans.slice(0, maxScans)];
            
            if (maxScans < this.filteredScans.length) {
                this.showNotification('Selected the first 4 scans only. Maximum 4 scans can be compared at once.', 'info');
            }
        }
        
        // Update UI
        this.renderCurrentView();
        
        // Update the "select all" checkbox state based on selection state
        const selectAllCheckbox = document.getElementById('select-all-scans');
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = this.selectedScans.length > 0 && 
                this.selectedScans.length === Math.min(4, this.filteredScans.length);
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/scan-history/api/stats');
            const data = await response.json();
            
            console.log('📊 Full API response:', data); // Debug full response
            
            if (data.success) {
                console.log('📊 Stats data structure:', data.stats); // Debug stats structure
                console.log('📊 Threat breakdown from API:', data.stats.threat_breakdown); // Debug threat breakdown specifically
                
                this.updateStatsDisplay(data.stats);
                this.renderStatisticsCharts(data.stats);
            } else {
                console.error('❌ Failed to load stats:', data.error);
            }
        } catch (error) {
            console.error('❌ Error loading stats:', error);
        }
    }

    updateStatsDisplay(stats) {
        // Update stat cards with animation
        const statElements = {
            'total-scans-count': stats.total_scans || 0,
            'threats-found-count': stats.total_threats || 0,
            'hosts-discovered-count': stats.total_hosts || 0,
            'avg-duration': this.formatDuration(stats.avg_duration || 0)
        };

        Object.entries(statElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateCounter(element, value);
            }
        });

        // Update trend indicators
        this.updateTrendIndicators(stats.trends || {});
    }

    animateCounter(element, targetValue) {
        const startValue = parseInt(element.textContent) || 0;
        const isNumeric = typeof targetValue === 'number';
        
        if (isNumeric) {
            const increment = (targetValue - startValue) / 30;
            let currentValue = startValue;
            
            const timer = setInterval(() => {
                currentValue += increment;
                if ((increment > 0 && currentValue >= targetValue) || 
                    (increment < 0 && currentValue <= targetValue)) {
                    element.textContent = targetValue.toLocaleString();
                    clearInterval(timer);
                } else {
                    element.textContent = Math.floor(currentValue).toLocaleString();
                }
            }, 50);
        } else {
            element.textContent = targetValue;
        }
    }

    updateTrendIndicators(trends) {
        // If backend doesn't provide trends, calculate them from available data
        if (!trends || Object.keys(trends).length === 0) {
            trends = {
                scans_change: { text: 'Loading...', type: 'neutral' },
                threats_change: { text: 'Loading...', type: 'neutral' },
                hosts_change: { text: 'Loading...', type: 'neutral' },
                duration_change: { text: 'Loading...', type: 'neutral' }
            };

            // Only attempt calculations if we have data in localStorage
            const previousStats = JSON.parse(localStorage.getItem('scan_history_previous_stats') || '{}');
            const currentStats = {
                total_scans: document.getElementById('total-scans-count')?.textContent || '0',
                threats_found: document.getElementById('threats-found-count')?.textContent || '0',
                hosts_discovered: document.getElementById('hosts-discovered-count')?.textContent || '0',
                avg_duration: document.getElementById('avg-duration')?.textContent || '0'
            };
            
            // Calculate scan count change
            if (previousStats.total_scans) {
                const prevScans = parseInt(previousStats.total_scans.replace(/,/g, '')) || 0;
                const currentScans = parseInt(currentStats.total_scans.replace(/,/g, '')) || 0;
                const scansDiff = currentScans - prevScans;
                
                if (scansDiff > 0) {
                    trends.scans_change = { text: `+${scansDiff} new`, type: 'positive' };
                } else if (scansDiff < 0) {
                    trends.scans_change = { text: `${scansDiff} removed`, type: 'negative' };
                } else {
                    trends.scans_change = { text: 'No change', type: 'neutral' };
                }
            }
            
            // Calculate threats change
            if (previousStats.threats_found) {
                const prevThreats = parseInt(previousStats.threats_found.replace(/,/g, '')) || 0;
                const currentThreats = parseInt(currentStats.threats_found.replace(/,/g, '')) || 0;
                const threatsDiff = currentThreats - prevThreats;
                
                if (threatsDiff > 0) {
                    trends.threats_change = { text: `+${threatsDiff} new`, type: 'negative' };
                } else if (threatsDiff < 0) {
                    trends.threats_change = { text: `${Math.abs(threatsDiff)} resolved`, type: 'positive' };
                } else {
                    trends.threats_change = { text: 'No change', type: 'neutral' };
                }
            }
            
            // Calculate hosts change
            if (previousStats.hosts_discovered) {
                const prevHosts = parseInt(previousStats.hosts_discovered.replace(/,/g, '')) || 0;
                const currentHosts = parseInt(currentStats.hosts_discovered.replace(/,/g, '')) || 0;
                const hostsDiff = currentHosts - prevHosts;
                
                if (hostsDiff > 0) {
                    trends.hosts_change = { text: `+${hostsDiff} new`, type: 'positive' };
                } else if (hostsDiff < 0) {
                    trends.hosts_change = { text: `${hostsDiff} less`, type: 'negative' };
                } else {
                    trends.hosts_change = { text: 'No change', type: 'neutral' };
                }
            }
            
            // Calculate duration change
            if (previousStats.avg_duration && currentStats.avg_duration) {
                const prevDur = this.parseDuration(previousStats.avg_duration);
                const currentDur = this.parseDuration(currentStats.avg_duration);
                
                if (prevDur > 0 && currentDur > 0) {
                    const durChange = ((currentDur - prevDur) / prevDur) * 100;
                    const rounded = Math.round(durChange);
                    
                    if (rounded < 0) {
                        trends.duration_change = { text: `${Math.abs(rounded)}% faster`, type: 'positive' };
                    } else if (rounded > 0) {
                        trends.duration_change = { text: `${rounded}% slower`, type: 'negative' };
                    } else {
                        trends.duration_change = { text: 'No change', type: 'neutral' };
                    }
                }
            }
            
            // Save current stats for next comparison
            localStorage.setItem('scan_history_previous_stats', JSON.stringify(currentStats));
        }

        const trendElements = {
            'total-scans-change': trends.scans_change,
            'threats-change': trends.threats_change,
            'hosts-change': trends.hosts_change,
            'duration-change': trends.duration_change
        };

        Object.entries(trendElements).forEach(([id, change]) => {
            const element = document.getElementById(id);
            if (element && change) {
                element.textContent = change.text || '';
                element.className = `stat-change ${change.type || 'neutral'}`;
            }
        });
    }

    // Helper method to parse duration string to seconds
    parseDuration(durationStr) {
        if (!durationStr) return 0;
        
        let seconds = 0;
        // Handle hour format: 1h 30m
        const hourMatch = durationStr.match(/(\d+)h/);
        if (hourMatch) {
            seconds += parseInt(hourMatch[1]) * 3600;
        }
        
        // Handle minute format: 30m
        const minMatch = durationStr.match(/(\d+)m/);
        if (minMatch) {
            seconds += parseInt(minMatch[1]) * 60;
        }
        
        // Handle seconds format: 45s
        const secMatch = durationStr.match(/(\d+)s/);
        if (secMatch) {
            seconds += parseInt(secMatch[1]);
        }
        
        // If it's just a number, assume it's seconds
        if (/^\d+$/.test(durationStr)) {
            seconds = parseInt(durationStr);
        }
        
        return seconds;
    }

    async loadScans() {
        this.showLoading(true);
        
        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                per_page: this.itemsPerPage, // Using per_page instead of limit to match backend
                sort_field: this.currentSort.field,
                sort_direction: this.currentSort.direction,
                ...this.currentFilters
            });

            const response = await fetch(`${this.endpoints.getScans}?${params}`);
            if (!response.ok) throw new Error('Failed to load scans');
            
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'Failed to load scans');
            }
            
            this.scans = data.scans || [];
            this.filteredScans = this.scans;
            
            // Get pagination data from API response
            if (data.pagination) {
                this.totalScans = data.pagination.total || 0;
                this.currentPage = data.pagination.page || 1;
                this.itemsPerPage = data.pagination.per_page || 20;
            } else {
                // Fallback if pagination info is missing
                this.totalScans = this.scans.length;
            }
            
            this.renderCurrentView();
            this.updatePagination();
            this.updateResultsCount();
            this.checkEmptyState();
            
        } catch (error) {
            console.error('Error loading scans:', error);
            this.showError('Failed to load scan history: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    showLoading(show) {
        const loadingState = document.getElementById('loading-state');
        const tableView = document.getElementById('table-view');
        const gridView = document.getElementById('grid-view');
        const timelineView = document.getElementById('timeline-view');
        
        if (loadingState) {
            loadingState.style.display = show ? 'flex' : 'none';
        }
        
        [tableView, gridView, timelineView].forEach(view => {
            if (view) view.style.display = show ? 'none' : (view.id === `${this.currentView}-view` ? 'block' : 'none');
        });
    }

    renderCurrentView() {
        switch (this.currentView) {
            case 'table':
                this.renderTableView();
                break;
            case 'grid':
                this.renderGridView();
                break;
            case 'timeline':
                this.renderTimelineView();
                break;
        }
        
        this.checkEmptyState();
    }

    // Calculate threat level based on scan results
    calculateThreatLevel(scan) {
        const scanType = scan.scan_type || '';
        
        // For VirusTotal scans, always calculate the threat level to ensure accuracy
        if (scanType === 'virustotal') {
            return this.calculateVirusTotalThreatLevel(scan);
        }
        
        // For other scan types, use provided threat level if available, otherwise calculate
        if (scan.threat_level) {
            return scan.threat_level.toLowerCase();
        }
        
        // Calculate based on scan type and results
        const vulnerabilitiesFound = scan.vulnerabilities_found || 0;
        
        // Define threat level thresholds for each scan type
        if (scanType === 'network') {
            return this.calculateNetworkThreatLevel(scan);
        } else if (scanType === 'host_discovery') {
            return this.calculateHostDiscoveryThreatLevel(scan);
        } else if (scanType === 'dns') {
            return this.calculateDnsThreatLevel(scan);
        }
        
        // Default threshold based on vulnerabilities
        if (vulnerabilitiesFound >= 10) return 'high';
        if (vulnerabilitiesFound >= 5) return 'medium';
        if (vulnerabilitiesFound > 0) return 'low';
        return 'low';
    }
    
    calculateVirusTotalThreatLevel(scan) {
        // Calculate VirusTotal threat level based on scan results
        if (scan.scan_results && scan.scan_results.scan_stats) {
            const stats = scan.scan_results.scan_stats;
            const malicious = stats.malicious || 0;
            const suspicious = stats.suspicious || 0;
            const total = stats.total || 0;
            
            if (total > 0) {
                const maliciousRatio = (malicious / total) * 100;
                const suspiciousRatio = (suspicious / total) * 100;
                
                // Updated logic: Consider both ratio and total threat count
                if (maliciousRatio >= 50 || malicious >= 30 || total >= 50) {
                    return 'critical';
                } else if (maliciousRatio >= 25 || malicious >= 15) {
                    return 'high';
                } else if (maliciousRatio >= 10 || malicious >= 5) {
                    return 'medium';
                } else if (maliciousRatio > 0 || suspiciousRatio >= 5) {
                    return 'low';
                }
            }
        }
        
        return 'low';
    }
    
    calculateNetworkThreatLevel(scan) {
        // Extract relevant data
        const vulnerabilitiesFound = scan.vulnerabilities_found || 0;
        const portsFound = scan.ports_found || 0;
        const results = scan.scan_results || {};
        const hosts = results.hosts || [];
        
        // Check for critical services and open ports
        let criticalServicesCount = 0;
        let sensitivePorts = new Set([21, 22, 23, 25, 53, 80, 110, 123, 443, 445, 3389, 8080, 8443]);
        let sensitivePortsFound = false;
        
        // Count critical services and check for sensitive ports
        hosts.forEach(host => {
            if (host.protocols && host.protocols.tcp) {
                const openPorts = host.protocols.tcp.filter(port => port.state === 'open');
                
                // Check if any sensitive ports are open
                openPorts.forEach(port => {
                    const portNumber = parseInt(port.port);
                    if (sensitivePorts.has(portNumber)) {
                        sensitivePortsFound = true;
                    }
                    
                    // Check for critical services
                    if (port.service && ['mssql', 'mysql', 'ftp', 'telnet', 'rdp'].includes(port.service.toLowerCase())) {
                        criticalServicesCount++;
                    }
                });
            }
        });
        
        // Determine threat level
        if (vulnerabilitiesFound >= 10 || criticalServicesCount >= 3) return 'critical';
        if (vulnerabilitiesFound >= 5 || (criticalServicesCount > 0 && sensitivePortsFound)) return 'high';
        if (vulnerabilitiesFound > 0 || sensitivePortsFound) return 'medium';
        
        return 'low';
    }
    
    calculateHostDiscoveryThreatLevel(scan) {
        // For host discovery, we mainly look at the number of hosts found
        const hostsFound = scan.hosts_found || 0;
        
        // Generally, host discovery is informational
        if (hostsFound > 100) return 'medium'; // Large network discovered
        if (hostsFound > 25) return 'low';
        
        return 'low';
    }
    
    calculateDnsThreatLevel(scan) {
        // Extract relevant data
        const results = scan.scan_results || {};
        const subdomains = results.subdomains || [];
        const records = results.dns_records || {};
        
        // Check for security-related DNS records
        const hasSPF = this.checkDnsRecordPresence(records, 'TXT', 'spf1');
        const hasDMARC = this.checkDnsRecordPresence(records, 'TXT', 'DMARC1');
        const hasDNSSEC = this.checkDnsRecordPresence(records, 'DS') || this.checkDnsRecordPresence(records, 'DNSKEY');
        
        // Count security issues
        let securityIssues = 0;
        if (!hasSPF) securityIssues++;
        if (!hasDMARC) securityIssues++;
        if (!hasDNSSEC) securityIssues++;
        
        // Excessive subdomains can indicate potential security issues
        if (subdomains.length > 100) {
            securityIssues++;
        }
        
        // Determine threat level
        if (securityIssues >= 3) return 'high';
        if (securityIssues >= 2) return 'medium';
        if (securityIssues >= 1) return 'low';
        
        return 'low';
    }
    
    checkDnsRecordPresence(records, recordType, valueContains = null) {
        if (!records || !records[recordType]) return false;
        
        const recordSet = records[recordType];
        if (!recordSet || !recordSet.records || recordSet.records.length === 0) return false;
        
        // If we're just checking record existence
        if (!valueContains) return true;
        
        // If we need to check record content
        return recordSet.records.some(record => 
            record.value && record.value.toLowerCase().includes(valueContains.toLowerCase())
        );
    }

    renderTableView() {
        const tbody = document.getElementById('history-table-body');
        if (!tbody) return;

        if (this.filteredScans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center">
                        <div style="padding: 2rem; color: var(--text-secondary);">
                            <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                            <p>No scans found matching your criteria</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.filteredScans.map(scan => {
            const calculatedThreatLevel = this.calculateThreatLevel(scan);
            const isSelected = this.selectedScans.some(s => s.scan_id === scan.scan_id);
            
            return `
                <tr data-scan-id="${scan.scan_id}" class="scan-row ${isSelected ? 'selected' : ''}">
                    <td>
                        <div class="selection-cell">
                            <input type="checkbox" class="scan-select-checkbox" 
                                ${isSelected ? 'checked' : ''} 
                                onclick="event.stopPropagation(); scanHistory.toggleScanSelection(${scan.scan_id})">
                        </div>
                    </td>
                    <td>
                        <div class="scan-date">
                            <strong>${this.formatDate(scan.timestamp)}</strong>
                            <small style="display: block; color: var(--text-secondary);">
                                ${this.formatTime(scan.timestamp)}
                            </small>
                        </div>
                    </td>
                    <td>
                        <span class="scan-type-badge ${scan.scan_type}">
                            ${this.getScanTypeIcon(scan.scan_type)}
                            ${this.formatScanType(scan.scan_type)}
                        </span>
                    </td>
                    <td>
                        <div class="scan-target">
                            <strong class="text-truncate" style="max-width: 200px; display: block;">
                                ${this.escapeHtml(scan.target)}
                            </strong>
                            ${scan.notes ? `<small class="text-truncate" style="max-width: 200px; display: block; color: var(--text-secondary);">${this.escapeHtml(scan.notes)}</small>` : ''}
                        </div>
                    </td>
                    <td>
                        <span class="duration-badge">
                            <i class="fas fa-clock"></i>
                            ${this.formatDuration(scan.duration)}
                        </span>
                    </td>
                    <td>
                        <div class="threats-info">
                            <strong>${scan.vulnerabilities_found || 0}</strong>
                            ${scan.hosts_found ? `<small style="display: block; color: var(--text-secondary);">${scan.hosts_found} hosts</small>` : ''}
                        </div>
                    </td>
                    <td>
                        <span class="threat-badge ${calculatedThreatLevel}">
                            ${this.getThreatIcon(calculatedThreatLevel)}
                            ${calculatedThreatLevel.toUpperCase()}
                        </span>
                    </td>
                    <td>
                        <div class="action-buttons">
                            <button class="action-btn" onclick="scanHistory.viewScanDetails(${scan.scan_id})" title="View Details">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="action-btn" onclick="scanHistory.exportScan(${scan.scan_id})" title="Export">
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="action-btn danger" onclick="scanHistory.deleteScan(${scan.scan_id})" title="Delete">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        // Add click handlers for rows
        tbody.querySelectorAll('.scan-row').forEach(row => {
            row.addEventListener('click', (e) => {
                if (!e.target.closest('.action-buttons') && !e.target.closest('.selection-cell')) {
                    const scanId = row.dataset.scanId;
                    this.viewScanDetails(scanId);
                }
            });
        });
        
        // Update the selection bar visibility
        this.updateSelectionBar();
    }

    renderGridView() {
        const gridContainer = document.getElementById('scan-grid');
        if (!gridContainer) return;

        if (this.filteredScans.length === 0) {
            gridContainer.innerHTML = `
                <div style="grid-column: 1 / -1; text-align: center; padding: 4rem; color: var(--text-secondary);">
                    <i class="fas fa-search" style="font-size: 3rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                    <h3>No scans found</h3>
                    <p>No scans match your current filter criteria</p>
                </div>
            `;
            return;
        }

        gridContainer.innerHTML = this.filteredScans.map(scan => {
            const calculatedThreatLevel = this.calculateThreatLevel(scan);
            return `
                <div class="scan-card" data-scan-id="${scan.scan_id}" onclick="scanHistory.viewScanDetails(${scan.scan_id})">
                    <div class="scan-card-header">
                        <span class="scan-type-badge ${scan.scan_type}">
                            ${this.getScanTypeIcon(scan.scan_type)}
                            ${this.formatScanType(scan.scan_type)}
                        </span>
                        <span class="threat-badge ${calculatedThreatLevel}">
                            ${this.getThreatIcon(calculatedThreatLevel)}
                            ${calculatedThreatLevel.toUpperCase()}
                        </span>
                    </div>
                    
                    <div class="scan-card-meta">
                        <div class="scan-card-target" title="${this.escapeHtml(scan.target)}">
                            ${this.escapeHtml(this.truncateText(scan.target, 40))}
                        </div>
                        <div class="scan-card-date">
                            ${this.formatDate(scan.timestamp)} at ${this.formatTime(scan.timestamp)}
                        </div>
                    </div>
                    
                    ${scan.notes ? `
                        <div class="scan-card-notes" style="margin: 1rem 0; padding: 0.75rem; background: rgba(102, 126, 234, 0.05); border-radius: 0.5rem; font-size: 0.9rem; color: var(--text-secondary);">
                            ${this.escapeHtml(this.truncateText(scan.notes, 100))}
                        </div>
                    ` : ''}
                    
                    <div class="scan-card-stats">
                        <div class="scan-stat">
                            <div class="scan-stat-value">${this.formatDuration(scan.duration)}</div>
                            <div class="scan-stat-label">Duration</div>
                        </div>
                        <div class="scan-stat">
                            <div class="scan-stat-value">${scan.vulnerabilities_found || 0}</div>
                            <div class="scan-stat-label">Threats</div>
                        </div>
                        ${scan.hosts_found ? `
                            <div class="scan-stat">
                                <div class="scan-stat-value">${scan.hosts_found}</div>
                                <div class="scan-stat-label">Hosts</div>
                            </div>
                        ` : ''}
                        ${scan.ports_found ? `
                            <div class="scan-stat">
                                <div class="scan-stat-value">${scan.ports_found}</div>
                                <div class="scan-stat-label">Ports</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    renderTimelineView() {
        const timelineContainer = document.getElementById('timeline-chart');
        if (!timelineContainer) return;

        // Show loading spinner while processing
        timelineContainer.innerHTML = `
            <div class="timeline-header" style="margin-bottom: 2rem;">
                <h4>Scan Activity Timeline</h4>
                <p style="color: var(--text-secondary);">Visual representation of your scanning activity over time</p>
            </div>
            <div class="loading-spinner" style="margin: 2rem auto;"></div>
        `;

        // Use a requestAnimationFrame to not block the UI
        requestAnimationFrame(() => {
            // Group scans by date - with optimized performance
            const MAX_DATES_TO_SHOW = 15; // Limit for better performance
            const groupedScans = {};
            
            // First pass: Identify unique dates
            const uniqueDates = new Set();
            this.filteredScans.forEach(scan => {
                const date = new Date(scan.timestamp).toDateString();
                uniqueDates.add(date);
            });
            
            // Convert to array and sort (newest first)
            const sortedDates = Array.from(uniqueDates).sort((a, b) => 
                new Date(b) - new Date(a)
            );
            
            // Take only the most recent dates
            const datesToShow = sortedDates.slice(0, MAX_DATES_TO_SHOW);
            
            // Second pass: Group scans by the selected dates
            this.filteredScans.forEach(scan => {
                const date = new Date(scan.timestamp).toDateString();
                if (datesToShow.includes(date)) {
                    if (!groupedScans[date]) groupedScans[date] = [];
                    groupedScans[date].push(scan);
                }
            });
            
            // Sort scans within each date (newest first)
            Object.keys(groupedScans).forEach(date => {
                groupedScans[date].sort((a, b) => 
                    new Date(b.timestamp) - new Date(a.timestamp)
                );
                
                // Limit scans per date for performance
                if (groupedScans[date].length > 10) {
                    groupedScans[date] = groupedScans[date].slice(0, 10);
                }
            });
            
            // Build timeline content
            let timelineContent = '';
            
            if (Object.keys(groupedScans).length === 0) {
                timelineContent = `
                    <div style="text-align: center; padding: 2rem;">
                        <i class="fas fa-calendar" style="font-size: 3rem; color: var(--text-secondary); margin-bottom: 1rem;"></i>
                        <p>No scan history data available for timeline view</p>
                    </div>
                `;
            } else {
                Object.entries(groupedScans).forEach(([date, scans]) => {
                    timelineContent += `
                        <div class="timeline-day" style="margin-bottom: 2rem;">
                            <div class="timeline-date" style="font-weight: 700; margin-bottom: 1rem; color: var(--history-primary);">
                                ${this.formatDate(date)}
                                <span style="font-weight: 400; color: var(--text-secondary); margin-left: 1rem;">
                                    ${scans.length} scan${scans.length !== 1 ? 's' : ''}
                                </span>
                            </div>
                            <div class="timeline-scans" style="display: grid; gap: 0.5rem; margin-left: 2rem; border-left: 2px solid var(--history-primary); padding-left: 1rem;">
                                ${scans.map(scan => {
                                    const calculatedThreatLevel = this.calculateThreatLevel(scan);
                                    return `
                                        <div class="timeline-scan" style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--surface); border-radius: 0.5rem; cursor: pointer;" onclick="scanHistory.viewScanDetails(${scan.scan_id})">
                                            <span class="scan-time">${this.formatTime(scan.timestamp)}</span>
                                            <span class="scan-type-badge ${scan.scan_type}">${this.getScanTypeIcon(scan.scan_type)}</span>
                                            <div style="flex: 1;">
                                                <strong>${this.escapeHtml(this.truncateText(scan.target, 40))}</strong>
                                                <small style="display: block; color: var(--text-secondary);">${scan.duration ? this.formatDuration(scan.duration) : ''}</small>
                                            </div>
                                            <span class="threat-badge ${calculatedThreatLevel}">${calculatedThreatLevel.toUpperCase()}</span>
                                        </div>
                                    `;
                                }).join('')}
                                
                                ${scans.length >= 10 ? `
                                <div class="load-more-timeline" style="text-align: center; padding: 0.5rem; color: var(--history-primary); cursor: pointer;" onclick="scanHistory.loadMoreTimelineItems('${date}')">
                                    <i class="fas fa-ellipsis-h"></i> Show more scans
                                </div>` : ''}
                            </div>
                        </div>
                    `;
                });
                
                // If we limited the dates, show a message
                if (sortedDates.length > MAX_DATES_TO_SHOW) {
                    const remainingDates = sortedDates.length - MAX_DATES_TO_SHOW;
                    timelineContent += `
                        <div class="timeline-pagination" style="text-align: center; padding: 1rem; margin-top: 1rem; background: var(--surface-variant); border-radius: 0.5rem;">
                            <p>Showing ${MAX_DATES_TO_SHOW} most recent dates. ${remainingDates} earlier dates not shown.</p>
                            <button class="btn btn-primary" onclick="scanHistory.loadMoreTimelineDates()">
                                <i class="fas fa-calendar-alt"></i> Load More Dates
                            </button>
                        </div>
                    `;
                }
            }
            
            // Update the container
            timelineContainer.innerHTML = `
                <div class="timeline-header" style="margin-bottom: 2rem;">
                    <h4>Scan Activity Timeline</h4>
                    <p style="color: var(--text-secondary);">Visual representation of your scanning activity over time</p>
                </div>
                <div class="timeline-content">
                    ${timelineContent}
                </div>
            `;
        });
    }

    // Helper method to load more timeline items for a specific date
    loadMoreTimelineItems(date) {
        // Implementation would fetch more scans for the specific date
        // For now, just show a notification that this is WIP
        this.showNotification('Loading more scans for ' + this.formatDate(date) + '...', 'info');
        
        // In a real implementation, you would:
        // 1. Make an API request to get more scans for this date
        // 2. Update the DOM with the new scans
    }
    
    // Helper method to load more dates in timeline view
    loadMoreTimelineDates() {
        // Implementation would fetch more dates
        // For now, just show a notification that this is WIP
        this.showNotification('Loading more historical scan dates...', 'info');
        
        // In a real implementation, you would:
        // 1. Make an API request to get more dates
        // 2. Update the DOM with the new dates and their scans
    }

    groupScansByDate(scans) {
        return scans.reduce((groups, scan) => {
            const date = new Date(scan.timestamp).toDateString();
            if (!groups[date]) groups[date] = [];
            groups[date].push(scan);
            return groups;
        }, {});
    }

    switchView(view) {
        this.currentView = view;
        
        // Update active button
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === view);
        });
        
        // Show/hide views
        ['table', 'grid', 'timeline'].forEach(viewType => {
            const viewElement = document.getElementById(`${viewType}-view`);
            if (viewElement) {
                viewElement.style.display = viewType === view ? 'block' : 'none';
            }
        });
        
        this.renderCurrentView();
        
        // Save preference
        localStorage.setItem('sana_scan_history_view', view);
    }

    handleSearch(query) {
        this.currentFilters.search = query;
        this.currentPage = 1;
        this.loadScans();
    }

    applyFilters() {
        const filters = {};
        
        // Scan type filter
        const scanType = document.getElementById('scan-type-filter')?.value;
        if (scanType) filters.scan_type = scanType;
        
        // Threat level filter
        const threatLevel = document.getElementById('threat-level-filter')?.value;
        if (threatLevel) filters.threat_level = threatLevel;
        
        // Status filter
        const status = document.getElementById('status-filter')?.value;
        if (status) filters.status = status;
        
        // Date range filter
        const dateRange = document.getElementById('date-range-filter')?.value;
        if (dateRange && dateRange !== 'custom') {
            filters.date_range = dateRange;
        } else if (dateRange === 'custom') {
            const dateFrom = document.getElementById('date-from')?.value;
            const dateTo = document.getElementById('date-to')?.value;
            if (dateFrom) filters.date_from = dateFrom;
            if (dateTo) filters.date_to = dateTo;
        }
        
        this.currentFilters = filters;
        this.currentPage = 1;
        this.loadScans();
    }

    clearFilters() {
        // Reset filter controls
        const filterElements = [
            'search-input',
            'scan-type-filter',
            'threat-level-filter',
            'date-range-filter',
            'status-filter',
            'date-from',
            'date-to'
        ];
        
        filterElements.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.value = '';
            }
        });
        
        // Hide custom date range
        const customRange = document.getElementById('custom-date-range');
        if (customRange) customRange.style.display = 'none';
        
        // Clear filters and reload
        this.currentFilters = {};
        this.currentPage = 1;
        this.loadScans();
    }

    handleSort(field) {
        if (this.currentSort.field === field) {
            this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.currentSort.field = field;
            this.currentSort.direction = 'desc';
        }
        
        // Update sort indicators
        document.querySelectorAll('.sortable').forEach(header => {
            header.classList.remove('sort-asc', 'sort-desc');
            if (header.dataset.sort === field) {
                header.classList.add(`sort-${this.currentSort.direction}`);
            }
        });
        
        this.loadScans();
    }

    updatePagination() {
        const totalPages = Math.ceil(this.totalScans / this.itemsPerPage);
        
        // Update buttons
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');
        
        if (prevBtn) prevBtn.disabled = this.currentPage <= 1;
        if (nextBtn) nextBtn.disabled = this.currentPage >= totalPages;
        
        // Update page numbers
        const pageNumbers = document.getElementById('page-numbers');
        if (pageNumbers) {
            pageNumbers.innerHTML = this.generatePageNumbers(totalPages);
        }
        
        // Update pagination info
        const start = (this.currentPage - 1) * this.itemsPerPage + 1;
        const end = Math.min(this.currentPage * this.itemsPerPage, this.totalScans);
        const paginationInfo = document.getElementById('pagination-info');
        
        if (paginationInfo) {
            paginationInfo.textContent = `Showing ${start}-${end} of ${this.totalScans} results`;
        }
    }

    generatePageNumbers(totalPages) {
        const pages = [];
        const current = this.currentPage;
        const delta = 2;
        
        for (let i = Math.max(2, current - delta); i <= Math.min(totalPages - 1, current + delta); i++) {
            pages.push(i);
        }
        
        if (current - delta > 2) {
            pages.unshift('...');
        }
        if (current + delta < totalPages - 1) {
            pages.push('...');
        }
        
        pages.unshift(1);
        if (totalPages > 1) pages.push(totalPages);
        
        return pages.map(page => {
            if (page === '...') {
                return '<span class="page-ellipsis">...</span>';
            }
            return `<button class="page-number ${page === current ? 'active' : ''}" onclick="scanHistory.goToPage(${page})">${page}</button>`;
        }).join('');
    }

    goToPage(page) {
        const totalPages = Math.ceil(this.totalScans / this.itemsPerPage);
        if (page < 1 || page > totalPages) return;
        
        this.currentPage = page;
        this.loadScans();
    }

    updateResultsCount() {
        const resultsCount = document.getElementById('results-count');
        if (resultsCount) {
            resultsCount.textContent = `${this.totalScans} scan${this.totalScans !== 1 ? 's' : ''} found`;
        }
    }

    checkEmptyState() {
        const emptyState = document.getElementById('empty-state');
        const hasData = this.filteredScans.length > 0;
        
        if (emptyState) {
            emptyState.style.display = hasData ? 'none' : 'block';
        }
        
        // Show/hide pagination
        const paginationSection = document.getElementById('pagination-section');
        if (paginationSection) {
            paginationSection.style.display = hasData ? 'flex' : 'none';
        }
    }

    async viewScanDetails(scanId) {
        try {
            // Check if the scan details are already in cache
            if (this.scanDetailsCache[scanId]) {
                this.showScanModal(this.scanDetailsCache[scanId]);
                return;
            }
            
            this.showNotification('Loading scan details...', 'info');
            const response = await fetch(`${this.endpoints.getScanDetails}${scanId}`);
            
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error('Scan details not found. The scan may have been deleted.');
                } else {
                    throw new Error(`Failed to load scan details: ${response.statusText}`);
                }
            }
            
            const scan = await response.json();
            
            // Check if the response has an error status
            if (scan.status === 'error') {
                throw new Error(scan.message || 'Failed to load scan details');
            }
            
            // Cache the scan details for future use
            this.scanDetailsCache[scanId] = scan;
            
            this.showScanModal(scan);
            
        } catch (error) {
            console.error('Error loading scan details:', error);
            this.showNotification(error.message || 'Failed to load scan details', 'error');
            
            // If the scan doesn't exist, refresh the list
            if (error.message && error.message.includes('not found')) {
                setTimeout(() => this.loadScans(), 1500);
            }
        }
    }

    showScanModal(scan) {
        const modal = document.getElementById('scan-detail-modal');
        const modalTitle = document.getElementById('modal-title');
        const modalBody = document.getElementById('modal-body');
        
        if (!modal || !modalTitle || !modalBody) return;
        
        modalTitle.textContent = `${this.formatScanType(scan.scan_type)} - ${scan.target}`;
        
        // Generate scan-type-specific content
        let specificContent = '';
        switch(scan.scan_type) {
            case 'network':
                specificContent = this.renderNetworkScanDetails(scan);
                break;
            case 'virustotal':
                specificContent = this.renderVirusTotalScanDetails(scan);
                break;
            case 'dns':
                specificContent = this.renderDnsScanDetails(scan);
                break;
            case 'host_discovery':
                specificContent = this.renderHostDiscoveryDetails(scan);
                break;
            default:
                specificContent = this.renderGenericScanDetails(scan);
        }
        
        modalBody.innerHTML = `
            <div class="scan-detail-content">
                ${this.renderCommonHeader(scan)}
                ${specificContent}
            </div>
        `;
        
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    // Common header for all scan types
    renderCommonHeader(scan) {
        // Use calculated threat level for all scan types
        const threatLevel = this.calculateThreatLevel(scan);
        return `
            <div class="detail-header">
                <div class="detail-item">
                    <label>Scan Type</label>
                    <span class="scan-type-badge ${scan.scan_type}">
                        ${this.getScanTypeIcon(scan.scan_type)}
                        ${this.formatScanType(scan.scan_type)}
                    </span>
                </div>
                <div class="detail-item">
                    <label>Threat Level</label>
                    <span class="threat-badge ${threatLevel}">
                        ${this.getThreatIcon(threatLevel)}
                        ${threatLevel.toUpperCase()}
                    </span>
                </div>
                <div class="detail-item">
                    <label>Duration</label>
                    <span>${this.formatDuration(scan.duration)}</span>
                </div>
                <div class="detail-item">
                    <label>Date</label>
                    <span>${this.formatDate(scan.timestamp)} ${this.formatTime(scan.timestamp)}</span>
                </div>
            </div>
        `;
    }

    // 🔬 NETWORK SCAN SPECIFIC DETAILS - FIXED FOR YOUR DATA STRUCTURE
    renderNetworkScanDetails(scan) {
        const results = scan.scan_results;
        const hosts = results?.hosts || [];
        
        let hostDetails = '';
        let securityIssues = '';
        
        // Build detailed host and port information - CORRECTED for your actual data structure
        hosts.forEach(host => {
            // Add OS detection information display
            let osInfoHtml = '';
            if (host.os && host.os.length > 0) {
                osInfoHtml = `
                    <div class="os-detection-section">
                        <h6><i class="fas fa-laptop"></i> OS Detection</h6>
                        <div class="os-matches">
                            ${host.os.map(os => `
                                <div class="os-match">
                                    <span class="os-name">${os.name}</span>
                                    <span class="os-accuracy">Accuracy: ${os.accuracy}%</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            if (host.protocols && host.protocols.tcp && host.protocols.tcp.length > 0) {
                hostDetails += `
                    <div class="host-section">
                        <h5><i class="fas fa-server"></i> Host: ${host.ip}</h5>
                        ${host.hostname ? `<p><strong>Hostname:</strong> ${host.hostname}</p>` : ''}
                        ${osInfoHtml}
                        <div class="ports-table-container">
                            <table class="ports-table">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>State</th>
                                        <th>Service</th>
                                        <th>Product</th>
                                        <th>Version</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${host.protocols.tcp.map(port => `
                                        <tr class="port-row">
                                            <td><strong>${port.port}</strong></td>
                                            <td><span class="port-state ${port.state}">${port.state}</span></td>
                                            <td>${port.service || '-'}</td>
                                            <td>${port.product || '-'}</td>
                                            <td>${port.version || '-'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            } else {
                hostDetails += `
                    <div class="host-section">
                        <h5><i class="fas fa-server"></i> Host: ${host.ip}</h5>
                        <p>Status: <span class="port-state ${host.state}">${host.state}</span></p>
                        ${host.hostname ? `<p><strong>Hostname:</strong> ${host.hostname}</p>` : ''}
                        ${osInfoHtml}
                        <p><em>No open ports detected or port scan not performed</em></p>
                    </div>
                `;
            }
        });
        
        // Security analysis - CORRECTED for your data structure
        if (results?.security_analysis && results.security_analysis.length > 0) {
            securityIssues = `
                <div class="detail-section">
                    <h4><i class="fas fa-shield-alt"></i> Security Analysis</h4>
                    <div class="security-issues">
                        ${results.security_analysis.map(issue => `
                            <div class="security-issue severity-${issue.severity}">
                                <div class="issue-header">
                                    <span class="severity-badge ${issue.severity}">${issue.severity?.toUpperCase()}</span>
                                    <strong>${issue.title}</strong>
                                </div>
                                <div class="issue-description">${issue.description}</div>
                                ${issue.recommendation ? 
                                    `<div class="recommendation"><strong>Recommendation:</strong> ${issue.recommendation}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        return `
            <div class="detail-section">
                <h4><i class="fas fa-bullseye"></i> Target Information</h4>
                <div class="detail-grid">
                    <div class="detail-row">
                        <label>Target:</label>
                        <span class="font-mono">${this.escapeHtml(scan.target)}</span>
                    </div>
                    <div class="detail-row">
                        <label>Command:</label>
                        <span class="font-mono">${this.escapeHtml(scan.scan_command)}</span>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4><i class="fas fa-chart-bar"></i> Scan Summary</h4>
                <div class="scan-metrics">
                    <div class="metric-card">
                        <div class="metric-number">${scan.hosts_found || 0}</div>
                        <div class="metric-label">Hosts Found</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${scan.ports_found || 0}</div>
                        <div class="metric-label">Open Ports</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${scan.vulnerabilities_found || 0}</div>
                        <div class="metric-label">Vulnerabilities</div>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4><i class="fas fa-network-wired"></i> Host & Port Details</h4>
                ${hostDetails || '<p>No host details available</p>'}
            </div>
            
            ${securityIssues}
        `;
    }

    // 🦠 VIRUSTOTAL SCAN SPECIFIC DETAILS - CORRECTED FOR YOUR DATA STRUCTURE
    renderVirusTotalScanDetails(scan) {
        const results = scan.scan_results;
        
        // Detection Statistics - CORRECTED field names
        const stats = results?.scan_stats || {};
        const maliciousCount = stats?.malicious || 0;
        const totalEngines = stats?.total || 0;
        const detectionRatio = `${maliciousCount}/${totalEngines}`;
        
        // Calculate threat level based on detection ratio
        let threatLevel = 'low';
        let threatClass = 'low';
        if (totalEngines > 0) {
            const detectionPercentage = (maliciousCount / totalEngines) * 100;
            if (detectionPercentage >= 50) {
                threatLevel = 'critical';
                threatClass = 'critical';
            } else if (detectionPercentage >= 25) {
                threatLevel = 'high';
                threatClass = 'high';
            } else if (detectionPercentage >= 10) {
                threatLevel = 'medium';
                threatClass = 'medium';
            }
        }
        
        let detectionSummary = `
            <div class="detail-section">
                <h4><i class="fas fa-shield-virus"></i> Detection Summary</h4>
                <div class="detection-summary">
                    <div class="detection-metric malicious">
                        <div class="metric-number">${maliciousCount}</div>
                        <div class="metric-label">Malicious</div>
                    </div>
                    <div class="detection-metric suspicious">
                        <div class="metric-number">${stats?.suspicious || 0}</div>
                        <div class="metric-label">Suspicious</div>
                    </div>
                    <div class="detection-metric clean">
                        <div class="metric-number">${stats?.undetected || 0}</div>
                        <div class="metric-label">Clean</div>
                    </div>
                </div>
                <div class="detail-row">
                    <label>Detection Ratio:</label>
                    <span class="detection-ratio">${detectionRatio}</span>
                </div>
                <div class="detail-row">
                    <label>Total Engines:</label>
                    <span>${totalEngines}</span>
                </div>
                <div class="detail-row">
                    <label>Threat Level:</label>
                    <span class="threat-badge ${threatClass}">${threatLevel.toUpperCase()}</span>
                </div>
            </div>
        `;
        
        // File Information - CORRECTED for your data structure
        let resourceInfo = '';
        if (results?.file_info) {
            const fileInfo = results.file_info;
            resourceInfo = `
                <div class="detail-section">
                    <h4><i class="fas fa-file"></i> File Information</h4>
                    <div class="detail-grid">
                        <div class="detail-row">
                            <label>MD5:</label>
                            <span class="font-mono">${fileInfo.md5 || '-'}</span>
                        </div>
                        <div class="detail-row">
                            <label>SHA1:</label>
                            <span class="font-mono">${fileInfo.sha1 || '-'}</span>
                        </div>
                        <div class="detail-row">
                            <label>SHA256:</label>
                            <span class="font-mono">${fileInfo.sha256 || '-'}</span>
                        </div>
                        <div class="detail-row">
                            <label>File Size:</label>
                            <span>${this.formatFileSize(fileInfo.file_size)}</span>
                        </div>
                        <div class="detail-row">
                            <label>File Type:</label>
                            <span>${fileInfo.file_type || 'Unknown'}</span>
                        </div>
                        <div class="detail-row">
                            <label>Times Submitted:</label>
                            <span>${fileInfo.times_submitted || 0}</span>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Detection Results - SHOW ALL ENGINES, not just top 10
        let detectionResults = '';
        if (results?.analysis_results && results.analysis_results.length > 0) {
            const engines = results.analysis_results; // Show ALL engines
            detectionResults = `
                <div class="detail-section">
                    <h4><i class="fas fa-microscope"></i> Engine Results (${engines.length} Total)</h4>
                    <div class="engines-table-container">
                        <table class="engines-table">
                            <thead>
                                <tr>
                                    <th>Engine Name</th>
                                    <th>Result</th>
                                    <th>Category</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${engines.map(engine => `
                                    <tr class="engine-row ${engine.category}">
                                        <td class="engine-name">${engine.engine}</td>
                                        <td class="engine-result ${engine.category}">${engine.result || 'N/A'}</td>
                                        <td><span class="engine-category ${engine.category}">${engine.category}</span></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }
        
        return `
            <div class="detail-section">
                <h4><i class="fas fa-bullseye"></i> Scan Information</h4>
                <div class="detail-grid">
                    <div class="detail-row">
                        <label>Resource:</label>
                        <span class="font-mono">${this.escapeHtml(scan.target)}</span>
                    </div>
                    <div class="detail-row">
                        <label>Resource Type:</label>
                        <span class="resource-badge">${results?.resource_type?.toUpperCase() || 'UNKNOWN'}</span>
                    </div>
                    <div class="detail-row">
                        <label>Reputation:</label>
                        <span class="reputation-badge ${results?.reputation || 'unknown'}">${results?.reputation?.toUpperCase() || 'UNKNOWN'}</span>
                    </div>
                    ${results?.hash_type ? `
                    <div class="detail-row">
                        <label>Hash Type:</label>
                        <span>${results.hash_type.toUpperCase()}</span>
                    </div>` : ''}
                </div>
            </div>
            
            ${detectionSummary}
            ${resourceInfo}
            ${detectionResults}
        `;
    }

    // 🌐 DNS SCAN SPECIFIC DETAILS - COMPLETELY NEW IMPLEMENTATION
    renderDnsScanDetails(scan) {
        const results = scan.scan_results;
        
        // DNS Records Summary
        let recordsSummary = `
            <div class="detail-section">
                <h4><i class="fas fa-list"></i> DNS Records Summary</h4>
                <div class="scan-metrics">
                    <div class="metric-card">
                        <div class="metric-number">${results?.statistics?.total_records || 0}</div>
                        <div class="metric-label">Total Records</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${results?.statistics?.subdomains_found || 0}</div>
                        <div class="metric-label">Subdomains</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${results?.statistics?.record_types_found?.length || 0}</div>
                        <div class="metric-label">Record Types</div>
                    </div>
                </div>
            </div>
        `;
        
        // DNS Records Details
        let recordsDetails = '';
        if (results?.dns_records) {
            recordsDetails = `
                <div class="detail-section">
                    <h4><i class="fas fa-server"></i> DNS Records</h4>
                    ${Object.entries(results.dns_records).map(([recordType, recordData]) => {
                        if (recordData.success && recordData.records && recordData.records.length > 0) {
                            return `
                                <div class="dns-record-type">
                                    <h5>${recordType} Records (${recordData.count})</h5>
                                    <div class="dns-records-list">
                                        ${recordData.records.map(record => `
                                            <div class="dns-record">
                                                <span class="record-value">${record.value}</span>
                                                <span class="record-ttl">TTL: ${record.ttl}</span>
                                                ${record.priority !== undefined ? 
                                                    `<span class="record-priority">Priority: ${record.priority}</span>` : ''}
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            `;
                        }
                        return '';
                    }).join('')}
                </div>
            `;
        }
        
        // Subdomains
        let subdomainsSection = '';
        if (results?.subdomains && results.subdomains.length > 0) {
            subdomainsSection = `
                <div class="detail-section">
                    <h4><i class="fas fa-sitemap"></i> Discovered Subdomains</h4>
                    <div class="subdomains-list">
                        ${results.subdomains.map(subdomain => `
                            <div class="subdomain-item">
                                <div class="subdomain-name">${subdomain.subdomain}</div>
                                <div class="subdomain-ips">
                                    ${subdomain.ip_addresses.map(ip => 
                                        `<span class="ip-badge">${ip}</span>`
                                    ).join('')}
                                </div>
                                <div class="subdomain-source">Source: ${subdomain.source}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        return `
            <div class="detail-section">
                <h4><i class="fas fa-bullseye"></i> DNS Reconnaissance Target</h4>
                <div class="detail-grid">
                    <div class="detail-row">
                        <label>Domain:</label>
                        <span class="font-mono">${this.escapeHtml(results?.domain || scan.target)}</span>
                    </div>
                    <div class="detail-row">
                        <label>Enumeration Method:</label>
                        <span>${results?.statistics?.enumeration_method || 'Unknown'}</span>
                    </div>
                    <div class="detail-row">
                        <label>Session ID:</label>
                        <span class="font-mono">${results?.session_id || 'N/A'}</span>
                    </div>
                </div>
            </div>
            
            ${recordsSummary}
            ${recordsDetails}
            ${subdomainsSection}
        `;
    }

    // 🕵️ HOST DISCOVERY SPECIFIC DETAILS - COMPLETELY NEW IMPLEMENTATION
    renderHostDiscoveryDetails(scan) {
        const results = scan.scan_results;
        const discoveryData = results?.discovery_results || results;
        
        // Discovery Summary
        let discoverySummary = `
            <div class="detail-section">
                <h4><i class="fas fa-chart-bar"></i> Discovery Summary</h4>
                <div class="scan-metrics">
                    <div class="metric-card">
                        <div class="metric-number">${discoveryData?.statistics?.alive_hosts || 0}</div>
                        <div class="metric-label">Alive Hosts</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${discoveryData?.statistics?.total_scanned || 0}</div>
                        <div class="metric-label">Total Scanned</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-number">${discoveryData?.statistics?.response_rate || 0}%</div>
                        <div class="metric-label">Response Rate</div>
                    </div>
                </div>
            </div>
        `;
        
        // Discovered Hosts
        let hostsDetails = '';
        if (discoveryData?.hosts && discoveryData.hosts.length > 0) {
            hostsDetails = `
                <div class="detail-section">
                    <h4><i class="fas fa-network-wired"></i> Discovered Hosts</h4>
                    <div class="hosts-grid">
                        ${discoveryData.hosts.map(host => `
                            <div class="host-discovery-card">
                                <div class="host-ip">
                                    <i class="fas fa-server"></i>
                                    <strong>${host.ip}</strong>
                                    <span class="host-status ${host.status}">${host.status}</span>
                                </div>
                                ${host.hostname ? `<div class="host-hostname">Hostname: ${host.hostname}</div>` : ''}
                                ${host.mac_address ? `<div class="host-mac">MAC: ${host.mac_address}</div>` : ''}
                                ${host.vendor ? `<div class="host-vendor">Vendor: ${host.vendor}</div>` : ''}
                                ${host.os_info && Object.keys(host.os_info).length > 0 ? 
                                    `<div class="host-os">OS: ${JSON.stringify(host.os_info)}</div>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        return `
            <div class="detail-section">
                <h4><i class="fas fa-bullseye"></i> Discovery Information</h4>
                <div class="detail-grid">
                    <div class="detail-row">
                        <label>Target Network:</label>
                        <span class="font-mono">${this.escapeHtml(discoveryData?.targetNetwork || scan.target)}</span>
                    </div>
                    <div class="detail-row">
                        <label>Discovery Method:</label>
                        <span>${discoveryData?.discoveryMethod || 'Unknown'}</span>
                    </div>
                    <div class="detail-row">
                        <label>Command:</label>
                        <span class="font-mono">${discoveryData?.command || scan.scan_command}</span>
                    </div>
                    <div class="detail-row">
                        <label>Duration:</label>
                        <span>${discoveryData?.duration || scan.duration}s</span>
                    </div>
                </div>
            </div>
            
            ${discoverySummary}
            ${hostsDetails}
        `;
    }

    // Helper function for file size formatting
    formatFileSize(bytes) {
        if (!bytes) return '-';
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 Bytes';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    closeModal() {
        const modal = document.getElementById('scan-detail-modal');
        if (modal) {
            modal.classList.remove('active');
            document.body.style.overflow = '';
        }
    }

    async exportHistory() {
        try {
            // Create and show the export modal
            const modal = document.createElement('div');
            modal.className = 'modal active';
            modal.id = 'export-modal';
            
            modal.innerHTML = `
                <div class="modal-backdrop"></div>
                <div class="modal-content" style="max-width: 500px;">
                    <div class="modal-header">
                        <h3>Export Scan History</h3>
                        <button class="modal-close" id="export-modal-close">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="export-options">
                            <div class="option-group">
                                <label>Export Format</label>
                                <div class="format-options">
                                    <label class="format-option" data-format="csv">
                                        <input type="radio" name="export-format" value="csv" checked>
                                        <span class="format-label">CSV</span>
                                        <span class="format-desc">Spreadsheet format, ideal for data analysis</span>
                                    </label>
                                    <label class="format-option" data-format="pdf">
                                        <input type="radio" name="export-format" value="pdf">
                                        <span class="format-label">PDF</span>
                                        <span class="format-desc">Document format, ideal for reports and printing</span>
                                    </label>
                                </div>
                            </div>
                            
                            <div class="option-group" style="margin-top: 1rem;">
                                <label>Export Options</label>
                                <div class="checkbox-options">
                                    <label class="checkbox-option">
                                        <input type="checkbox" id="apply-filters" checked>
                                        <span>Apply current filters</span>
                                    </label>
                                    <label class="checkbox-option">
                                        <input type="checkbox" id="include-details">
                                        <span>Include detailed scan results</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" id="export-cancel">Cancel</button>
                        <button class="btn btn-primary" id="export-confirm">Export</button>
                    </div>
                </div>
            `;
            
            // Add some styling
            const style = document.createElement('style');
            style.textContent = `
                .export-options {
                    padding: 1rem;
                }
                .option-group label {
                    display: block;
                    font-weight: 600;
                    margin-bottom: 0.75rem;
                    color: var(--text-primary);
                }
                .format-options {
                    display: grid;
                    gap: 1rem;
                }
                .format-option {
                    display: grid;
                    grid-template-columns: auto 1fr;
                    gap: 0.5rem;
                    align-items: center;
                    padding: 1rem;
                    border: 1px solid var(--border-color);
                    border-radius: 0.5rem;
                    cursor: pointer;
                }
                .format-option:hover {
                    background: var(--surface-variant);
                }
                .format-option input {
                    grid-row: span 2;
                }
                .format-label {
                    font-weight: 600;
                }
                .format-desc {
                    grid-column: 2;
                    font-size: 0.8rem;
                    color: var(--text-secondary);
                }
                .checkbox-options {
                    display: grid;
                    gap: 0.75rem;
                }
                .checkbox-option {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    cursor: pointer;
                }
            `;
            
            document.head.appendChild(style);
            document.body.appendChild(modal);
            
            // Add event listeners
            const closeBtn = document.getElementById('export-modal-close');
            const cancelBtn = document.getElementById('export-cancel');
            const confirmBtn = document.getElementById('export-confirm');
            const backdrop = modal.querySelector('.modal-backdrop');
            
            const closeModal = () => {
                modal.classList.remove('active');
                setTimeout(() => {
                    modal.remove();
                }, 300);
            };
            
            [closeBtn, cancelBtn, backdrop].forEach(el => {
                el?.addEventListener('click', closeModal);
            });
            
            // Handle export
            confirmBtn?.addEventListener('click', async () => {
                closeModal();
                this.showNotification('Preparing export...', 'info');
                
                try {
                    // Get selected format
                    const formatInputs = document.getElementsByName('export-format');
                    let selectedFormat = 'csv';
                    formatInputs.forEach(input => {
                        if (input.checked) {
                            selectedFormat = input.value;
                        }
                    });
                    
                    // Get options
                    const applyFilters = document.getElementById('apply-filters')?.checked || false;
                    const includeDetails = document.getElementById('include-details')?.checked || false;
                    
                    // Build query parameters
                    const params = new URLSearchParams();
                    params.append('format', selectedFormat);
                    params.append('include_details', includeDetails);
                    
                    // Add current filters if requested
                    if (applyFilters) {
                        Object.entries(this.currentFilters).forEach(([key, value]) => {
                            if (value) {
                                params.append(key, value);
                            }
                        });
                    }
                
                    // Use the correct direct export endpoint for the selected format
                    // Matching the backend routes defined in scan_history_routes.py
                    const exportUrl = `/export/${selectedFormat}?${params}`;
                    const response = await fetch(exportUrl);
                    
                    if (!response.ok) throw new Error(`Export failed: ${response.statusText}`);
                    
                    // Get the content disposition header to determine the filename
                    const contentDisposition = response.headers.get('Content-Disposition');
                    let filename = `scan-history-export.${selectedFormat}`;
                    
                    if (contentDisposition && contentDisposition.includes('filename=')) {
                        const match = contentDisposition.match(/filename="?([^"]+)"?/);
                        if (match && match[1]) {
                            filename = match[1];
                        }
                    } else {
                        // Use a default name with timestamp
                        filename = `scan-history-${new Date().toISOString().slice(0, 10)}.${selectedFormat}`;
                    }
                    
                    // Download the file
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                    
                    this.showNotification(`Export to ${selectedFormat.toUpperCase()} completed successfully`, 'success');
                } catch (error) {
                    console.error('Export error:', error);
                    this.showNotification(`Export failed: ${error.message}`, 'error');
                }
            });
        } catch (error) {
            console.error('Export modal error:', error);
            this.showNotification('Failed to prepare export options', 'error');
        }
    }

    async exportScan(scanId) {
        try {
            this.showNotification('Preparing scan export...', 'info');
            
            // Use the correct endpoint for single scan export with format parameter
            const exportUrl = `/scan-history/export/json?scan_id=${scanId}`;
            
            const response = await fetch(exportUrl);
            
            if (!response.ok) {
                throw new Error(`Export failed: ${response.statusText}`);
            }
            
            // Get content-disposition header to determine filename
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = `scan-${scanId}.json`;
            
            if (contentDisposition && contentDisposition.includes('filename=')) {
                const match = contentDisposition.match(/filename="?([^"]+)"?/);
                if (match && match[1]) {
                    filename = match[1];
                }
            } else {
                // Use default name with scan ID and timestamp
                filename = `scan-${scanId}-${new Date().toISOString().slice(0, 10)}.json`;
            }
            
            // Download the file
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            this.showNotification('Scan exported successfully', 'success');
            
        } catch (error) {
            console.error('Export error:', error);
            this.showNotification(`Failed to export scan: ${error.message}`, 'error');
        }
    }

    async deleteScan(scanId) {
        try {
            if (!confirm('Are you sure you want to delete this scan? This action cannot be undone.')) {
                return;
            }
            
            this.showNotification('Deleting scan...', 'info');
            
            // Fix the endpoint URL to match the backend route
            const deleteEndpoint = `${this.endpoints.deleteScan}${scanId}/delete`;
            
            const response = await fetch(deleteEndpoint, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `Delete failed with status ${response.status}`);
            }
            
            // Try to get response data
            const data = await response.json().catch(() => ({ success: true }));
            
            if (!data.success) {
                throw new Error(data.error || 'Delete operation failed');
            }
            
            // Remove from cache if present
            if (this.scanDetailsCache[scanId]) {
                delete this.scanDetailsCache[scanId];
            }
            
            // Remove from selected scans if present
            const selectedIndex = this.selectedScans.findIndex(scan => scan.scan_id == scanId);
            if (selectedIndex >= 0) {
                this.selectedScans.splice(selectedIndex, 1);
            }
            
            this.showNotification('Scan deleted successfully', 'success');
            
            // Reload scans to update the list
            await this.loadScans();
            
            // Also reload stats since they may have changed
            await this.loadStats();
            
        } catch (error) {
            console.error('Delete error:', error);
            this.showNotification(`Failed to delete scan: ${error.message}`, 'error');
        }
    }

    startAutoRefresh() {
        // Refresh data every 30 seconds
        setInterval(() => {
            this.loadStats();
            if (this.currentPage === 1) {
                this.loadScans();
            }
        }, 30000);
    }

    setupTooltips() {
        // Simple tooltip implementation
        document.addEventListener('mouseover', (e) => {
            if (e.target.hasAttribute('title')) {
                // Custom tooltip logic can be added here
            }
        });
    }

    // Auth-style notification system
    initializeNotificationSystem() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('notification-container')) {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }

        // Make notification function globally available
        window.showNotification = this.showNotification.bind(this);
    }

    showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        if (!container) return;

        // Check for existing notifications with the same message to prevent duplicates
        const existingNotifications = container.querySelectorAll('.notification');
        for (let i = 0; i < existingNotifications.length; i++) {
            const notificationMessage = existingNotifications[i].querySelector('.notification-message');
            if (notificationMessage && notificationMessage.textContent === message) {
                // Remove the existing notification with the same message
                existingNotifications[i].remove();
            }
        }

        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        
        const icon = this.getNotificationIcon(type);
        notification.innerHTML = `
            <i class="${icon}"></i>
            <span class="notification-message">${message}</span>
            <button class="notification-close" aria-label="Close notification">
                <i class="fas fa-times"></i>
            </button>
        `;

        container.appendChild(notification);

        // Auto-remove notification
        setTimeout(() => {
            notification.style.animation = 'slideOutNotification 0.3s ease-in forwards';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, duration);

        // Add click to dismiss
        notification.addEventListener('click', (e) => {
            if (e.target.closest('.notification-close')) {
                notification.style.animation = 'slideOutNotification 0.3s ease-in forwards';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        });
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-triangle',
            warning: 'fas fa-exclamation-circle',
            info: 'fas fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    showError(message) {
        const tableView = document.getElementById('table-view');
        const gridView = document.getElementById('grid-view');
        const timelineView = document.getElementById('timeline-view');
        
        const errorHtml = `
            <div class="error-state" style="text-align: center; padding: 4rem; color: var(--text-secondary);">
                <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: var(--history-danger); margin-bottom: 1rem;"></i>
                <h3>Error Loading Scan History</h3>
                <p>${message}</p>
                <button class="btn btn-primary" onclick="scanHistory.loadScans()">
                    <i class="fas fa-redo"></i> Try Again
                </button>
            </div>
        `;
        
        if (this.currentView === 'table' && tableView) {
            const tbody = document.getElementById('history-table-body');
            if (tbody) tbody.innerHTML = `<tr><td colspan="7">${errorHtml}</td></tr>`;
        } else if (this.currentView === 'grid' && gridView) {
            const grid = document.getElementById('scan-grid');
            if (grid) grid.innerHTML = errorHtml;
        } else if (this.currentView === 'timeline' && timelineView) {
            const timeline = document.getElementById('timeline-chart');
            if (timeline) timeline.innerHTML = errorHtml;
        }
    }

    // Utility methods
    formatDate(timestamp) {
        return new Date(timestamp).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    formatDuration(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
        return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    }

    formatScanType(type) {
        const types = {
            'network': 'Network Scan',
            'virustotal': 'VirusTotal',
            'dns': 'DNS Recon',
            'host_discovery': 'Host Discovery'
        };
        return types[type] || type;
    }

    getScanTypeIcon(type) {
        const icons = {
            'network': '<i class="fas fa-network-wired"></i>',
            'virustotal': '<i class="fas fa-shield-virus"></i>',
            'dns': '<i class="fas fa-globe"></i>',
            'host_discovery': '<i class="fas fa-search"></i>'
        };
        return icons[type] || '<i class="fas fa-scan"></i>';
    }

    getThreatIcon(level) {
        const icons = {
            'low': '<i class="fas fa-shield-alt"></i>',
            'medium': '<i class="fas fa-exclamation-triangle"></i>',
            'high': '<i class="fas fa-exclamation-circle"></i>',
            'critical': '<i class="fas fa-skull-crossbones"></i>'
        };
        return icons[level] || '<i class="fas fa-shield-alt"></i>';
    }

    truncateText(text, maxLength) {
        return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatScanResults(results) {
        if (typeof results === 'string') {
            try {
                results = JSON.parse(results);
            } catch (e) {
                return results;
            }
        }
        return JSON.stringify(results, null, 2);
    }

    renderStatisticsCharts(stats) {
        if (!stats) return;
        
        // Detect current theme
        const isDarkTheme = this.detectTheme();
        
        // Get threat distribution data and sort in correct order
        const threatData = stats.threat_breakdown || {};
        console.log('🔍 Threat breakdown data:', threatData); // Debug log
        
        const threatOrder = ['low', 'medium', 'high', 'critical'];
        // Include all threat levels, even if count is 0, for consistent display
        const threatLabels = threatOrder;
        const threatValues = threatOrder.map(level => threatData[level] || 0);
        
        console.log('🔍 Threat labels:', threatLabels); // Debug log
        console.log('🔍 Threat values:', threatValues); // Debug log
        
        // Get scan type distribution
        const scanTypeData = stats.scan_type_breakdown || [];
        const typeLabels = scanTypeData.map(item => this.formatScanType(item.scan_type));
        const typeValues = scanTypeData.map(item => item.count);
        
        // Render threat level chart if the container exists
        const threatChartContainer = document.getElementById('threat-chart');
        if (threatChartContainer) {
            this.renderPieChart(threatChartContainer, {
                labels: threatLabels,
                values: threatValues,
                title: 'Threat Level Distribution',
                // Modern gradient colors for threat levels - CORRECTED ORDER
                colors: [
                    '#22c55e', // low - green (safe)
                    '#f97316', // medium - orange (warning)
                    '#ef4444', // high - red (danger)
                    '#991b1b'  // critical - dark red (severe)
                ],
                isDarkTheme: isDarkTheme
            });
        }
        
        // Render scan type chart if the container exists
        const typeChartContainer = document.getElementById('scan-type-chart');
        if (typeChartContainer) {
            this.renderBarChart(typeChartContainer, {
                labels: typeLabels,
                values: typeValues,
                title: 'Scan Type Distribution',
                // Modern vibrant colors for scan types
                colors: [
                    '#8b5cf6', // network - purple
                    '#ec4899', // virustotal - pink
                    '#06b6d4', // dns - cyan
                    '#10b981'  // host_discovery - emerald
                ],
                isDarkTheme: isDarkTheme
            });
        }
        
        // Render scan activity timeline if container exists
        const activityChartContainer = document.getElementById('activity-chart');
        if (activityChartContainer && stats.scan_activity) {
            this.renderLineChart(activityChartContainer, {
                labels: Object.keys(stats.scan_activity || {}),
                values: Object.values(stats.scan_activity || {}),
                title: 'Scan Activity (Last 30 Days)',
                isDarkTheme: isDarkTheme
            });
        }
    }
    
    detectTheme() {
        // Check for dark-theme class on documentElement (html) or body
        const isDarkTheme = document.documentElement.classList.contains('dark-theme') || 
                           document.body.classList.contains('dark-theme');
        
        return isDarkTheme;
    }
    
    getThemeColors(isDarkTheme) {
        if (isDarkTheme) {
            return {
                background: '#1e1e2f',
                text: '#f3f4f6',
                textSecondary: '#9ca3af',
                border: 'rgba(255, 255, 255, 0.1)',
                grid: 'rgba(255, 255, 255, 0.05)',
                axis: 'rgba(255, 255, 255, 0.2)',
                shadow: 'rgba(0, 0, 0, 0.3)',
                chartBg: 'rgba(255, 255, 255, 0.02)',
                centerCircle: '#1e1e2f',
                stroke: '#1e1e2f'
            };
        } else {
            return {
                background: '#ffffff',
                text: '#1f2937',
                textSecondary: '#6b7280',
                border: '#e5e7eb',
                grid: 'rgba(0, 0, 0, 0.1)',
                axis: '#d1d5db',
                shadow: 'rgba(0, 0, 0, 0.1)',
                chartBg: 'rgba(0, 0, 0, 0.02)',
                centerCircle: '#ffffff',
                stroke: '#ffffff'
            };
        }
    }
    
    renderPieChart(container, data) {
        // Modern SVG pie chart renderer with theme detection
        const { labels, values, title, colors, isDarkTheme } = data;
        if (!values.length) return;
        
        const themeColors = this.getThemeColors(isDarkTheme);
        const width = container.clientWidth;
        const height = 300;
        const radius = Math.min(width, height) / 2 * 0.7;
        const centerX = width / 2;
        const centerY = height / 2;
        
        // Calculate total for percentages
        const total = values.reduce((sum, val) => sum + val, 0);
        
        // If all values are 0, show a message or default state
        if (total === 0) {
            container.innerHTML = `
                <div class="chart-header">
                    <h3 class="chart-title">${title}</h3>
                </div>
                <div style="text-align: center; padding: 2rem; color: ${themeColors.textSecondary};">
                    <p>No scan data available</p>
                </div>
            `;
            return;
        }
        
        // Calculate the slices
        let startAngle = 0;
        const slices = values.map((value, index) => {
            const percentage = value / total;
            const endAngle = startAngle + percentage * 2 * Math.PI;
            
            // Calculate SVG arc path
            const x1 = centerX + radius * Math.cos(startAngle);
            const y1 = centerY + radius * Math.sin(startAngle);
            const x2 = centerX + radius * Math.cos(endAngle);
            const y2 = centerY + radius * Math.sin(endAngle);
            
            const largeArcFlag = percentage > 0.5 ? 1 : 0;
            
            const pathData = [
                `M ${centerX} ${centerY}`,
                `L ${x1} ${y1}`,
                `A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`,
                'Z'
            ].join(' ');
            
            const slice = {
                path: pathData,
                color: colors[index % colors.length],
                label: labels[index],
                value: value,
                percentage: percentage * 100,
                midAngle: startAngle + (endAngle - startAngle) / 2
            };
            
            startAngle = endAngle;
            return slice;
        });
        
        // Generate SVG
        let svg = `
            <div class="chart-header">
                <h3 class="chart-title">${title}</h3>
            </div>
            <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="chart-svg">
                <!-- Chart background circle for nice aesthetics -->
                <circle cx="${centerX}" cy="${centerY}" r="${radius + 5}" fill="${themeColors.chartBg}" />
                
                <!-- Drop shadow filter -->
                <defs>
                    <filter id="drop-shadow" x="-20%" y="-20%" width="140%" height="140%">
                        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="${isDarkTheme ? '0.3' : '0.2'}" />
                    </filter>
                </defs>
                
                <!-- Slices with animation and hover effects -->
                ${slices.map((slice, index) => `
                    <path 
                        d="${slice.path}" 
                        fill="${slice.color}" 
                        stroke="${themeColors.stroke}" 
                        stroke-width="${isDarkTheme ? '1' : '2'}"
                        filter="url(#drop-shadow)"
                        opacity="${slice.value > 0 ? '0.9' : '0.3'}"
                        class="chart-slice"
                        data-index="${index}"
                        transform="scale(1)"
                        style="transition: transform 0.2s ease; transform-origin: ${centerX}px ${centerY}px;"
                        onmouseover="this.style.transform='scale(1.05)'; this.style.opacity='1';" 
                        onmouseout="this.style.transform='scale(1)'; this.style.opacity='${slice.value > 0 ? '0.9' : '0.3'}';"
                    >
                        <title>${slice.label}: ${slice.value} (${Math.round(slice.percentage)}%)</title>
                    </path>
                `).join('')}
                
                <!-- Center circle for aesthetics -->
                <circle cx="${centerX}" cy="${centerY}" r="${radius * 0.4}" fill="${themeColors.centerCircle}" stroke="${themeColors.border}" stroke-width="${isDarkTheme ? '1' : '2'}" />
                
                <!-- Legend with improved styling -->
                <g class="chart-legend" transform="translate(${width - 130}, 20)">
                    ${slices.map((slice, i) => `
                        <g transform="translate(0, ${i * 26})">
                            <rect width="14" height="14" rx="3" fill="${slice.color}" stroke="${themeColors.border}" stroke-width="1" opacity="${slice.value > 0 ? '1' : '0.5'}"></rect>
                            <text x="20" y="12" fill="${themeColors.text}" style="font-size: 12px; font-weight: 500; opacity: ${slice.value > 0 ? '1' : '0.7'};">
                                ${slice.label} (${slice.value})
                            </text>
                        </g>
                    `).join('')}
                </g>
            </svg>
        `;
        
        container.innerHTML = svg;
    }
    
    renderBarChart(container, data) {
        // Modern SVG bar chart renderer with theme detection
        const { labels, values, title, colors, isDarkTheme } = data;
        if (!values.length) return;
        
        const themeColors = this.getThemeColors(isDarkTheme);
        const width = container.clientWidth;
        const height = 300;
        const padding = { top: 40, right: 30, bottom: 60, left: 50 };
        const chartWidth = width - padding.left - padding.right;
        const chartHeight = height - padding.top - padding.bottom;
        
        // Calculate scales
        const maxValue = Math.max(...values) * 1.1;
        const barWidth = chartWidth / labels.length * 0.7;
        const barSpacing = chartWidth / labels.length * 0.3;
        
        // Generate bars
        const bars = values.map((value, index) => {
            const barHeight = (value / maxValue) * chartHeight;
            const x = padding.left + index * (barWidth + barSpacing) + barSpacing / 2;
            const y = height - padding.bottom - barHeight;
            
            return {
                x,
                y,
                width: barWidth,
                height: barHeight,
                color: colors[index % colors.length],
                label: labels[index],
                value
            };
        });
        
        // Generate SVG
        let svg = `
            <div class="chart-header">
                <h3 class="chart-title">${title}</h3>
            </div>
            <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="chart-svg">
                <!-- Drop shadow for bars -->
                <defs>
                    <filter id="bar-shadow" x="-50%" y="-50%" width="200%" height="200%">
                        <feDropShadow dx="0" dy="3" stdDeviation="3" flood-opacity="${isDarkTheme ? '0.2' : '0.15'}" />
                    </filter>
                    
                    <!-- Gradient background -->
                    <linearGradient id="grid-gradient" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="${themeColors.chartBg}" />
                        <stop offset="100%" stop-color="${isDarkTheme ? 'rgba(255,255,255,0.01)' : 'rgba(0,0,0,0.01)'}" />
                    </linearGradient>
                </defs>
            
                <!-- Chart background -->
                <rect 
                    x="${padding.left}" 
                    y="${padding.top}" 
                    width="${chartWidth}" 
                    height="${chartHeight}" 
                    fill="url(#grid-gradient)" 
                    rx="4"
                />
                
                <!-- Grid lines -->
                ${[0, 0.25, 0.5, 0.75, 1].map(tick => {
                    const y = height - padding.bottom - (tick * chartHeight);
                    return `
                        <line 
                            x1="${padding.left}" 
                            y1="${y}" 
                            x2="${width - padding.right}" 
                            y2="${y}" 
                            stroke="${themeColors.grid}" 
                            stroke-width="1"
                            stroke-dasharray="${tick === 0 ? '0' : '3,3'}"
                        />
                    `;
                }).join('')}
                
                <!-- Y-axis line -->
                <line 
                    x1="${padding.left}" 
                    y1="${padding.top}" 
                    x2="${padding.left}" 
                    y2="${height - padding.bottom}" 
                    stroke="${themeColors.axis}" 
                    stroke-width="1"
                />
                
                <!-- X-axis line -->
                <line 
                    x1="${padding.left}" 
                    y1="${height - padding.bottom}" 
                    x2="${width - padding.right}" 
                    y2="${height - padding.bottom}" 
                    stroke="${themeColors.axis}" 
                    stroke-width="1"
                />
                
                <!-- Animated bars with hover effects -->
                ${bars.map(bar => `
                    <rect 
                        x="${bar.x}" 
                        y="${bar.y}" 
                        width="${bar.width}" 
                        height="${bar.height}" 
                        rx="4"
                        fill="${bar.color}"
                        opacity="0.85"
                        filter="url(#bar-shadow)"
                        class="chart-bar"
                        onmouseover="this.style.opacity='1'; this.style.transform='scaleY(1.03)'; this.style.transformOrigin='bottom';" 
                        onmouseout="this.style.opacity='0.85'; this.style.transform='scaleY(1)';"
                        style="transition: all 0.2s ease; transform-origin: bottom;"
                    >
                        <title>${bar.label}: ${bar.value}</title>
                    </rect>
                    <text 
                        x="${bar.x + bar.width/2}" 
                        y="${bar.y - 8}" 
                        text-anchor="middle" 
                        fill="${themeColors.text}"
                        style="font-size: 12px; font-weight: 600;"
                    >${bar.value}</text>
                `).join('')}
                
                <!-- X-axis labels with improved styling -->
                ${bars.map(bar => `
                    <text 
                        x="${bar.x + bar.width/2}" 
                        y="${height - padding.bottom + 20}" 
                        text-anchor="middle" 
                        fill="${themeColors.textSecondary}"
                        style="font-size: 11px; transform: rotate(-45deg); transform-origin: ${bar.x + bar.width/2}px ${height - padding.bottom + 20}px;"
                    >${bar.label}</text>
                `).join('')}
                
                <!-- Y-axis ticks -->
                ${[0, 0.25, 0.5, 0.75, 1].map(tick => {
                    const y = height - padding.bottom - (tick * chartHeight);
                    return `
                        <line 
                            x1="${padding.left - 5}" 
                            y1="${y}" 
                            x2="${padding.left}" 
                            y2="${y}" 
                            stroke="${themeColors.axis}" 
                            stroke-width="1"
                        />
                        <text 
                            x="${padding.left - 10}" 
                            y="${y + 5}" 
                            text-anchor="end" 
                            fill="${themeColors.textSecondary}"
                            style="font-size: 11px;"
                        >${Math.round(tick * maxValue)}</text>
                    `;
                }).join('')}
            </svg>
        `;
        
        container.innerHTML = svg;
    }
    
    renderLineChart(container, data) {
        // Modern SVG line chart renderer with theme detection
        const { labels, values, title, isDarkTheme } = data;
        if (!values.length) return;
        
        const themeColors = this.getThemeColors(isDarkTheme);
        const width = container.clientWidth;
        const height = 300;
        const padding = { top: 30, right: 30, bottom: 40, left: 50 };
        const chartWidth = width - padding.left - padding.right;
        const chartHeight = height - padding.top - padding.bottom;
        
        // Calculate scales
        const maxValue = Math.max(Math.max(...values) * 1.1, 1);
        const points = values.map((value, index) => {
            const x = padding.left + (index / (labels.length - 1)) * chartWidth;
            const y = height - padding.bottom - (value / maxValue) * chartHeight;
            return { x, y, value, label: labels[index] };
        });
        
        // Create the line path
        const pathData = points.map((point, i) => {
            return `${i === 0 ? 'M' : 'L'} ${point.x} ${point.y}`;
        }).join(' ');
        
        // Create gradient for area under line
        const gradientId = `line-gradient-${Date.now()}`;
        
        // Generate SVG
        let svg = `
            <div class="chart-header">
                <h3 class="chart-title">${title}</h3>
            </div>
            <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="chart-svg">
                <!-- Drop shadow filter for line -->
                <defs>
                    <filter id="line-shadow" x="-20%" y="-20%" width="140%" height="140%">
                        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="${isDarkTheme ? '0.3' : '0.2'}" />
                    </filter>
                    
                    <!-- Gradient for line -->
                    <linearGradient id="${gradientId}" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.8" />
                        <stop offset="100%" stop-color="#3b82f6" stop-opacity="0.2" />
                    </linearGradient>
                    
                    <!-- Grid gradient -->
                    <linearGradient id="grid-line-gradient" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="${themeColors.chartBg}" />
                        <stop offset="100%" stop-color="${isDarkTheme ? 'rgba(255,255,255,0.01)' : 'rgba(0,0,0,0.01)'}" />
                    </linearGradient>
                </defs>
                
                <!-- Chart background -->
                <rect 
                    x="${padding.left}" 
                    y="${padding.top}" 
                    width="${chartWidth}" 
                    height="${chartHeight}" 
                    fill="url(#grid-line-gradient)" 
                    rx="4"
                />
                
                <!-- Grid lines -->
                ${[0, 0.25, 0.5, 0.75, 1].map(tick => {
                    const y = height - padding.bottom - (tick * chartHeight);
                    return `
                        <line 
                            x1="${padding.left}" 
                            y1="${y}" 
                            x2="${width - padding.right}" 
                            y2="${y}" 
                            stroke="${themeColors.grid}" 
                            stroke-dasharray="${tick === 0 ? '0' : '3,3'}"
                        />
                    `;
                }).join('')}
                
                <!-- Fill area under line -->
                <path 
                    d="${pathData} L ${points[points.length-1].x} ${height - padding.bottom} L ${points[0].x} ${height - padding.bottom} Z" 
                    fill="url(#${gradientId})"
                    opacity="0.3"
                />
                
                <!-- Line -->
                <path 
                    d="${pathData}" 
                    fill="none" 
                    stroke="#3b82f6" 
                    stroke-width="3"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    filter="url(#line-shadow)"
                    class="chart-line"
                />
                
                <!-- Points with hover effect -->
                ${points.map((point, i) => `
                    <circle 
                        cx="${point.x}" 
                        cy="${point.y}" 
                        r="5" 
                        fill="#3b82f6"
                        stroke="${themeColors.stroke}"
                        stroke-width="2"
                        class="chart-point"
                        onmouseover="this.setAttribute('r', '7'); this.nextElementSibling.style.opacity = '1';" 
                        onmouseout="this.setAttribute('r', '5'); this.nextElementSibling.style.opacity = '0';"
                    >
                        <title>${point.label}: ${point.value}</title>
                    </circle>
                    <g style="opacity: 0; transition: opacity 0.2s ease;">
                        <rect 
                            x="${point.x - 25}" 
                            y="${point.y - 35}" 
                            width="50" 
                            height="25" 
                            rx="4" 
                            fill="#3b82f6" 
                        />
                        <text 
                            x="${point.x}" 
                            y="${point.y - 18}" 
                            text-anchor="middle" 
                            fill="#ffffff"
                            style="font-size: 12px; font-weight: 600;"
                        >${point.value}</text>
                    </g>
                `).join('')}
                
                <!-- X-axis -->
                <line 
                    x1="${padding.left}" 
                    y1="${height - padding.bottom}" 
                    x2="${width - padding.right}" 
                    y2="${height - padding.bottom}" 
                    stroke="${themeColors.axis}" 
                />
                
                <!-- X-axis labels (show every nth label to avoid overlap) -->
                ${labels.filter((_, i) => i % Math.max(1, Math.floor(labels.length / 7)) === 0).map((label, i, filtered) => {
                    const index = labels.indexOf(label);
                    const x = padding.left + (index / (labels.length - 1)) * chartWidth;
                    return `
                        <text 
                            x="${x}" 
                            y="${height - padding.bottom + 15}" 
                            text-anchor="middle" 
                            fill="${themeColors.textSecondary}"
                            style="font-size: 10px;"
                        >${label}</text>
                    `;
                }).join('')}
                
                <!-- Y-axis -->
                <line 
                    x1="${padding.left}" 
                    y1="${padding.top}" 
                    x2="${padding.left}" 
                    y2="${height - padding.bottom}" 
                    stroke="${themeColors.axis}" 
                />
                
                <!-- Y-axis ticks and labels -->
                ${[0, 0.25, 0.5, 0.75, 1].map(tick => {
                    const y = height - padding.bottom - (tick * chartHeight);
                    const value = Math.round(tick * maxValue);
                    return `
                        <line 
                            x1="${padding.left - 5}" 
                            y1="${y}" 
                            x2="${padding.left}" 
                            y2="${y}" 
                            stroke="${themeColors.axis}" 
                        />
                        <text 
                            x="${padding.left - 10}" 
                            y="${y + 5}" 
                            text-anchor="end" 
                            fill="${themeColors.textSecondary}"
                            style="font-size: 11px;"
                        >${value}</text>
                    `;
                }).join('')}
            </svg>
        `;
        
        container.innerHTML = svg;
    }

    toggleScanSelection(scanId) {
        // Find the scan in our data
        const scan = this.filteredScans.find(s => s.scan_id == scanId);
        if (!scan) return;
        
        // Check if already selected
        const selectedIndex = this.selectedScans.findIndex(s => s.scan_id === scan.scan_id);
        
        if (selectedIndex >= 0) {
            // Remove from selection
            this.selectedScans.splice(selectedIndex, 1);
        } else {
            // Add to selection (limit to 4 scans maximum)
            if (this.selectedScans.length >= 4) {
                this.showNotification('You can select a maximum of 4 scans to compare', 'warning');
                return;
            }
            this.selectedScans.push(scan);
        }
        
        // Update the UI
        this.renderCurrentView();
    }
    
    clearScanSelection() {
        this.selectedScans = [];
        this.renderCurrentView();
    }
    
    updateSelectionBar() {
        const selectionBar = document.getElementById('selection-bar');
        if (!selectionBar) return;
        
        // Show/hide based on selection
        if (this.selectedScans.length > 0) {
            selectionBar.classList.add('active');
            
            // Update counter
            const counterElement = document.getElementById('selection-count');
            if (counterElement) {
                counterElement.textContent = `${this.selectedScans.length} scan${this.selectedScans.length !== 1 ? 's' : ''} selected`;
            }
        } else {
            selectionBar.classList.remove('active');
        }
    }
    
    compareSelectedScans() {
        if (this.selectedScans.length < 2) {
            this.showNotification('Please select at least 2 scans to compare', 'warning');
            return;
        }
        
        // Create comparison modal
        const compareModal = document.createElement('div');
        compareModal.className = 'modal active';
        compareModal.id = 'comparison-modal';
        
        // Sort selected scans by timestamp (newest first)
        const sortedScans = [...this.selectedScans].sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Generate comparison table
        let comparisonTable = `
            <table class="comparison-table">
                <thead>
                    <tr>
                        <th>Property</th>
                        ${sortedScans.map(scan => `
                            <th>
                                <div class="scan-header">
                                    <div class="scan-date">${this.formatDate(scan.timestamp)}</div>
                                    <div class="scan-target">${this.escapeHtml(this.truncateText(scan.target, 30))}</div>
                                    <div class="scan-type">${this.formatScanType(scan.scan_type)}</div>
                                </div>
                            </th>
                        `).join('')}
                    </tr>
                </thead>
                <tbody>
                    <!-- Basic Properties -->
                    <tr>
                        <td class="property-name">Duration</td>
                        ${sortedScans.map(scan => `
                            <td>${this.formatDuration(scan.duration)}</td>
                        `).join('')}
                    </tr>
                    <tr>
                        <td class="property-name">Hosts Found</td>
                        ${sortedScans.map(scan => `
                            <td>${scan.hosts_found || 0}</td>
                        `).join('')}
                    </tr>
                    <tr>
                        <td class="property-name">Ports Found</td>
                        ${sortedScans.map(scan => `
                            <td>${scan.ports_found || 0}</td>
                        `).join('')}
                    </tr>
                    <tr>
                        <td class="property-name">Threats Found</td>
                        ${sortedScans.map(scan => `
                            <td>${scan.vulnerabilities_found || 0}</td>
                        `).join('')}
                    </tr>
                    <tr>
                        <td class="property-name">Threat Level</td>
                        ${sortedScans.map(scan => {
                            const threatLevel = scan.threat_level || 'low';
                            return `
                                <td>
                                    <span class="threat-badge ${threatLevel}">
                                        ${threatLevel.toUpperCase()}
                                    </span>
                                </td>
                            `;
                        }).join('')}
                    </tr>
                    <tr>
                        <td class="property-name">Status</td>
                        ${sortedScans.map(scan => `
                            <td>${scan.status?.toUpperCase() || 'COMPLETED'}</td>
                        `).join('')}
                    </tr>
                </tbody>
            </table>
        `;
        
        compareModal.innerHTML = `
            <div class="modal-backdrop"></div>
            <div class="modal-content comparison-modal-content">
                <div class="modal-header">
                    <h3>Compare Scans (${sortedScans.length})</h3>
                    <button class="modal-close" id="compare-modal-close">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="comparison-scroll-container">
                        ${comparisonTable}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-outline" id="export-comparison">
                        <i class="fas fa-download"></i> Export Comparison
                    </button>
                    <button class="btn btn-secondary" id="compare-close-btn">Close</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(compareModal);
        
        // Add event listeners
        const closeBtn = document.getElementById('compare-modal-close');
        const closeButton = document.getElementById('compare-close-btn');
        const exportBtn = document.getElementById('export-comparison');
        const backdrop = compareModal.querySelector('.modal-backdrop');
        
        const closeCompareModal = () => {
            compareModal.classList.remove('active');
            setTimeout(() => compareModal.remove(), 300);
        };
        
        [closeBtn, closeButton, backdrop].forEach(el => {
            if (el) el.addEventListener('click', closeCompareModal);
        });
        
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportComparison(sortedScans);
                closeCompareModal();
            });
        }
    }
    
    exportComparison(scans) {
        // Create a simple text/html representation for now
        let content = `<h2>Scan Comparison Report</h2>`;
        content += `<p>Generated: ${new Date().toLocaleString()}</p>`;
        
        content += `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse;">`;
        content += `<tr><th>Property</th>`;
        
        // Headers
        scans.forEach(scan => {
            content += `<th>${this.formatDate(scan.timestamp)} - ${this.escapeHtml(scan.target)}</th>`;
        });
        content += `</tr>`;
        
        // Basic properties
        const properties = [
            { name: 'Duration', getter: scan => this.formatDuration(scan.duration) },
            { name: 'Hosts Found', getter: scan => scan.hosts_found || 0 },
            { name: 'Ports Found', getter: scan => scan.ports_found || 0 },
            { name: 'Threats Found', getter: scan => scan.vulnerabilities_found || 0 },
            { name: 'Threat Level', getter: scan => (scan.threat_level || 'low').toUpperCase() },
            { name: 'Status', getter: scan => (scan.status || 'completed').toUpperCase() }
        ];
        
        properties.forEach(property => {
            content += `<tr><td>${property.name}</td>`;
            scans.forEach(scan => {
                content += `<td>${property.getter(scan)}</td>`;
            });
            content += `</tr>`;
        });
        
        content += `</table>`;
        
        // Create a downloadable HTML file
        const blob = new Blob([`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Scan Comparison Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
                    th { background-color: #f5f5f5; }
                </style>
            </head>
            <body>
                ${content}
            </body>
            </html>
        `], { type: 'text/html' });
        
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_comparison_${new Date().toISOString().split('T')[0]}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Comparison exported successfully', 'success');
    }

    // Temporary test function to set a scan to critical threat level
    async testCriticalThreatLevel() {
        try {
            console.log('🔍 Starting critical threat level test...');
            
            // Get the first scan and update its threat level to critical
            const response = await fetch('/scan-history/api/scans?limit=1');
            const data = await response.json();
            
            console.log('📊 Scan data response:', data);
            
            if (data.success && data.scans.length > 0) {
                const scanId = data.scans[0].scan_id;
                const currentThreatLevel = data.scans[0].threat_level;
                
                console.log(`🔍 Found scan ID: ${scanId}, current threat level: ${currentThreatLevel}`);
                
                // Update the scan's threat level to critical
                const updateResponse = await fetch(`/scan-history/api/scan/${scanId}/update-threat-level`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        threat_level: 'critical'
                    })
                });
                
                console.log('📤 Update response status:', updateResponse.status);
                
                if (updateResponse.ok) {
                    const updateData = await updateResponse.json();
                    console.log('✅ Update response:', updateData);
                    
                    // Refresh the charts
                    console.log('🔄 Refreshing statistics...');
                    await this.loadStatistics();
                    console.log('✅ Statistics refreshed!');
                } else {
                    const errorData = await updateResponse.json();
                    console.log('❌ Failed to update scan threat level:', errorData);
                }
            } else {
                console.log('❌ No scans found or API error:', data);
            }
        } catch (error) {
            console.error('❌ Error testing critical threat level:', error);
        }
    }

    // Test function to check threat levels directly
    async testThreatLevels() {
        try {
            console.log('🔍 Testing threat levels directly...');
            
            // Get all scans to see their threat levels
            const response = await fetch('/scan-history/api/scans?limit=50');
            const data = await response.json();
            
            if (data.success) {
                console.log('📊 All scans with threat levels:');
                data.scans.forEach(scan => {
                    console.log(`  - Scan ${scan.scan_id}: ${scan.threat_level} (${scan.scan_type})`);
                });
                
                // Count threat levels manually
                const threatCounts = {};
                data.scans.forEach(scan => {
                    const level = scan.threat_level.toLowerCase();
                    threatCounts[level] = (threatCounts[level] || 0) + 1;
                });
                
                console.log('📊 Manual threat level counts:', threatCounts);
            }
        } catch (error) {
            console.error('❌ Error testing threat levels:', error);
        }
    }

    // Simple debug function to check database
    async debugDatabase() {
        try {
            console.log('🔍 Checking database directly...');
            
            const response = await fetch('/scan-history/api/debug/threat-levels');
            const data = await response.json();
            
            if (data.success) {
                console.log('📊 Raw threat levels from database:', data.raw_threat_levels);
                console.log('📊 Sample scans:', data.sample_scans);
                
                // Check if critical exists
                const hasCritical = Object.keys(data.raw_threat_levels).some(key => 
                    key.toLowerCase() === 'critical'
                );
                console.log('🔍 Has critical threat level:', hasCritical);
                
                if (hasCritical) {
                    console.log('✅ Critical threat level found in database!');
                } else {
                    console.log('❌ No critical threat level found in database');
                }
            }
        } catch (error) {
            console.error('❌ Error checking database:', error);
        }
    }

    // Function to update VirusTotal scans to critical
    async updateVirusTotalToCritical() {
        try {
            console.log('🔧 Updating VirusTotal scans to critical...');
            
            // Get VirusTotal scans
            const response = await fetch('/scan-history/api/scans?limit=50');
            const data = await response.json();
            
            if (data.success) {
                const vtScans = data.scans.filter(scan => scan.scan_type === 'virustotal');
                console.log(`🔍 Found ${vtScans.length} VirusTotal scans`);
                
                // Update first 3 VirusTotal scans to critical
                const scansToUpdate = vtScans.slice(0, 3);
                
                for (const scan of scansToUpdate) {
                    console.log(`🔧 Updating scan ${scan.scan_id} to critical...`);
                    
                    const updateResponse = await fetch(`/scan-history/api/scan/${scan.scan_id}/update-threat-level`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            threat_level: 'critical'
                        })
                    });
                    
                    if (updateResponse.ok) {
                        console.log(`✅ Updated scan ${scan.scan_id} to critical`);
                    } else {
                        console.log(`❌ Failed to update scan ${scan.scan_id}`);
                    }
                }
                
                // Refresh the charts
                console.log('🔄 Refreshing statistics...');
                await this.loadStatistics();
                console.log('✅ Statistics refreshed!');
            }
        } catch (error) {
            console.error('❌ Error updating VirusTotal scans:', error);
        }
    }

    // Function to recalculate all threat levels with updated logic
    async recalculateAllThreatLevels() {
        try {
            console.log('🔄 Recalculating all threat levels with updated logic...');
            
            const response = await fetch('/scan-history/api/recalculate-threat-levels', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                console.log(`✅ ${data.message}`);
                console.log(`📊 Updated ${data.updated_count} scans`);
                
                // Refresh the charts
                console.log('🔄 Refreshing statistics...');
                await this.loadStatistics();
                console.log('✅ Statistics refreshed!');
                
                // Show notification
                this.showNotification(`Updated threat levels for ${data.updated_count} scans`, 'success');
            } else {
                console.error('❌ Failed to recalculate threat levels:', data.error);
                this.showNotification('Failed to recalculate threat levels', 'error');
            }
        } catch (error) {
            console.error('❌ Error recalculating threat levels:', error);
            this.showNotification('Error recalculating threat levels', 'error');
        }
    }

    // Comprehensive test function to verify implementation
    async testImplementation() {
        try {
            console.log('🧪 Testing complete implementation...');
            
            // Test 1: Check if all functions are available
            console.log('✅ All functions available:', {
                testCriticalThreatLevel: typeof this.testCriticalThreatLevel,
                testThreatLevels: typeof this.testThreatLevels,
                debugDatabase: typeof this.debugDatabase,
                updateVirusTotalToCritical: typeof this.updateVirusTotalToCritical,
                recalculateAllThreatLevels: typeof this.recalculateAllThreatLevels
            });
            
            // Test 2: Check current threat levels
            console.log('📊 Current threat levels:');
            await this.debugDatabase();
            
            // Test 3: Check if recalculation endpoint exists
            const response = await fetch('/scan-history/api/recalculate-threat-levels', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            console.log('✅ Recalculation endpoint status:', response.status);
            
            if (response.ok) {
                const data = await response.json();
                console.log('✅ Recalculation successful:', data);
                
                // Refresh charts
                await this.loadStatistics();
                console.log('✅ Charts refreshed after recalculation');
            } else {
                console.log('❌ Recalculation endpoint not working');
            }
            
        } catch (error) {
            console.error('❌ Test failed:', error);
        }
    }

    // Test new scan threat level calculation
    async testNewScanThreatLevel() {
        try {
            console.log('🧪 Testing new scan threat level calculation...');
            
            // Get the most recent scan
            const response = await fetch('/scan-history/api/scans?limit=1');
            const data = await response.json();
            
            if (data.scans && data.scans.length > 0) {
                const latestScan = data.scans[0];
                console.log('📊 Latest scan:', {
                    scan_id: latestScan.scan_id,
                    scan_type: latestScan.scan_type,
                    threat_level: latestScan.threat_level,
                    target: latestScan.target
                });
                
                // Check if it's a VirusTotal scan
                if (latestScan.scan_type === 'virustotal' && latestScan.scan_results) {
                    const stats = latestScan.scan_results.scan_stats;
                    if (stats) {
                        const malicious = stats.malicious || 0;
                        const total = stats.total || 0;
                        const ratio = total > 0 ? (malicious / total) * 100 : 0;
                        
                        console.log('🔍 VirusTotal stats:', {
                            malicious,
                            total,
                            ratio: ratio.toFixed(2) + '%'
                        });
                        
                        // Check if it should be critical
                        const shouldBeCritical = ratio >= 50 || malicious >= 30 || total >= 50;
                        console.log('🎯 Should be critical:', shouldBeCritical);
                        console.log('📊 Current threat level:', latestScan.threat_level);
                        
                        if (shouldBeCritical && latestScan.threat_level !== 'critical') {
                            console.log('❌ ISSUE: Scan should be critical but is not!');
                            console.log('💡 This means the fix is not working for new scans');
                        } else if (shouldBeCritical && latestScan.threat_level === 'critical') {
                            console.log('✅ SUCCESS: Scan correctly marked as critical!');
                        } else {
                            console.log('ℹ️ Scan correctly not marked as critical');
                        }
                    }
                }
            } else {
                console.log('❌ No scans found');
            }
            
        } catch (error) {
            console.error('❌ Error testing new scan threat level:', error);
        }
    }

    // Force update the latest scan's threat level
    async forceUpdateLatestScan() {
        try {
            console.log('🔄 Force updating latest scan threat level...');
            
            // Get the most recent scan
            const response = await fetch('/scan-history/api/scans?limit=1');
            const data = await response.json();
            
            if (data.scans && data.scans.length > 0) {
                const latestScan = data.scans[0];
                console.log('📊 Latest scan ID:', latestScan.scan_id);
                
                // Force update to critical
                const updateResponse = await fetch(`/scan-history/api/scan/${latestScan.scan_id}/update-threat-level`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        threat_level: 'critical'
                    })
                });
                
                const updateData = await updateResponse.json();
                
                if (updateData.success) {
                    console.log('✅ Successfully updated scan to critical');
                    
                    // Refresh the page to see the changes
                    console.log('🔄 Refreshing page...');
                    window.location.reload();
                } else {
                    console.error('❌ Failed to update scan:', updateData.error);
                }
            } else {
                console.log('❌ No scans found');
            }
            
        } catch (error) {
            console.error('❌ Error force updating scan:', error);
        }
    }
}

// Make the test function globally accessible
window.testCriticalThreatLevel = () => {
    if (window.scanHistory) {
        return window.scanHistory.testCriticalThreatLevel();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the threat levels test function globally accessible
window.testThreatLevels = () => {
    if (window.scanHistory) {
        return window.scanHistory.testThreatLevels();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the debug function globally accessible
window.debugDatabase = () => {
    if (window.scanHistory) {
        return window.scanHistory.debugDatabase();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the VirusTotal update function globally accessible
window.updateVirusTotalToCritical = () => {
    if (window.scanHistory) {
        return window.scanHistory.updateVirusTotalToCritical();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the recalculation function globally accessible
window.recalculateAllThreatLevels = () => {
    if (window.scanHistory) {
        return window.scanHistory.recalculateAllThreatLevels();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the test function globally accessible
window.testImplementation = () => {
    if (window.scanHistory) {
        return window.scanHistory.testImplementation();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the new scan test function globally accessible
window.testNewScanThreatLevel = () => {
    if (window.scanHistory) {
        return window.scanHistory.testNewScanThreatLevel();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// Make the force update function globally accessible
window.forceUpdateLatestScan = () => {
    if (window.scanHistory) {
        return window.scanHistory.forceUpdateLatestScan();
    } else {
        console.error('❌ ScanHistory not initialized yet');
    }
};

// CSS for notifications
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .notification-close {
        background: none;
        border: none;
        color: inherit;
        cursor: pointer;
        padding: 0.25rem;
        margin-left: auto;
        opacity: 0.8;
        transition: opacity 0.2s ease;
    }
    
    .notification-close:hover {
        opacity: 1;
    }
    
    .detail-item {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .detail-item label {
        font-weight: 600;
        color: var(--text-secondary);
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .detail-section {
        margin-bottom: 2rem;
        padding: 1.5rem;
        background: var(--surface);
        border-radius: 0.75rem;
        border: 1px solid var(--border-color);
    }
    
    .detail-section h4 {
        margin: 0 0 1rem 0;
        color: var(--history-primary);
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .detail-grid {
        display: grid;
        gap: 1rem;
    }
    
    .detail-row {
        display: grid;
        grid-template-columns: 120px 1fr;
        gap: 1rem;
        align-items: center;
        padding: 0.75rem 0;
        border-bottom: 1px solid var(--border-color);
    }
    
    .detail-row:last-child {
        border-bottom: none;
    }
    
    .detail-row label {
        font-weight: 600;
        color: var(--text-secondary);
    }
`;
document.head.appendChild(notificationStyles);

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.scanHistory = new ScanHistoryManager();
});

// Export for global access
window.ScanHistoryManager = ScanHistoryManager;