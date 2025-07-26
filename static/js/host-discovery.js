/* Enhanced SANA Host Discovery JavaScript - Complete Implementation */
/* Following exact nmap-scanner.js patterns with Host Discovery functionality */

class HostDiscoveryManager {
    constructor() {
        // DOM Elements - Same pattern as nmap scanner
        this.discoveryForm = document.getElementById('discovery-form');
        this.discoveryBtn = document.getElementById('discovery-btn');
        this.cancelBtn = document.getElementById('cancel-discovery-btn');
        this.statusPanel = document.getElementById('scan-status');
        this.resultsSection = document.getElementById('discovery-results-section');
        
        // Discovery state - Same pattern as nmap scanner
        this.isDiscovering = false;
        this.currentDiscoveryId = null;
        this.discoveryStartTime = null;
        this.discoveryTimer = null;
        this.realTimeInterval = null;
        this.progressUpdateInterval = null;
        this.lastStatusUpdate = null;
        
        // Real-time stats - Scan Status Panel compatible
        this.realTimeStats = {
            hostsFound: 0,
            portsScanned: 0,
            openPorts: 0,
            currentPhase: 'Ready',
            activeHosts: 0,
            respondingHosts: 0,
            timeoutHosts: 0,
            avgResponseTime: 0
        };
        
        // Discovery configuration - Simplified
        this.discoveryConfig = {
            profile: 'comprehensive'
        };
        
        // Current results storage
        this.lastResults = null;
        this.activeNotifications = [];
        
        this.init();
    }
    
    init() {
        this.initializeNotificationSystem();
        this.bindEvents();
        this.initializeProfiles();
        this.initializeViewOptions();
        this.initializeFilters();
        this.initializeExampleCarousel();
        this.initializeTooltips();
        this.updateHeroStats();
        this.startNetworkAnimation();
        this.loadDiscoveryStatistics();
        
        console.log('Host Discovery Manager initialized');
    }
    
    bindEvents() {
        // Form submission - Same pattern as nmap
        if (this.discoveryForm) {
            this.discoveryForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startDiscovery();
            });
        }
        
        // Discovery control buttons
        if (this.discoveryBtn) {
            this.discoveryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.startDiscovery();
            });
        }
        
        if (this.cancelBtn) {
            this.cancelBtn.addEventListener('click', () => {
                this.stopDiscovery();
            });
        }
        
        // Quick action buttons - Same pattern as nmap
        const quickScanBtn = document.getElementById('quick-scan-btn');
        if (quickScanBtn) {
            quickScanBtn.addEventListener('click', () => {
                this.startQuickDiscovery();
            });
        }
        
        // Status control buttons
        const cancelBtn = document.getElementById('cancel-scan');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                this.stopDiscovery();
            });
        }
        
        // Result action buttons
        const newDiscoveryBtn = document.getElementById('new-discovery-btn');
        const saveResultsBtn = document.getElementById('save-discovery-btn');
        const shareResultsBtn = document.getElementById('share-discovery-btn');
        
        if (newDiscoveryBtn) {
            newDiscoveryBtn.addEventListener('click', () => {
                this.startNewDiscovery();
            });
        }
        
        if (saveResultsBtn) {
            saveResultsBtn.addEventListener('click', () => {
                this.saveResults();
            });
        }
        
        if (shareResultsBtn) {
            shareResultsBtn.addEventListener('click', () => {
                this.shareResults();
            });
        }
        
        // Export buttons - Same pattern as nmap
        this.bindExportEvents();
        
        // Input validation
        this.bindInputValidation();
        
        // Clear log button
        const clearLogBtn = document.getElementById('clear-log');
        if (clearLogBtn) {
            clearLogBtn.addEventListener('click', () => {
                this.clearScanLog();
            });
        }
        
        // Floating help button
        const floatingHelp = document.getElementById('floating-help');
        if (floatingHelp) {
            floatingHelp.addEventListener('click', () => {
                this.showHelpModal();
            });
        }
    }
    
    bindExportEvents() {
        const exportButtons = {
            'export-hosts-json': () => this.exportResults('json'),
            'export-hosts-csv': () => this.exportResults('csv'),
            'export-hosts-txt': () => this.exportResults('txt'),
            'copy-host-list': () => this.copyHostList()
        };
        
        Object.entries(exportButtons).forEach(([id, handler]) => {
            const btn = document.getElementById(id);
            if (btn) {
                btn.addEventListener('click', handler);
            }
        });
    }
    
    bindInputValidation() {
        const targetInput = document.getElementById('target-network');
        if (targetInput) {
            let validationTimeout;
            
            targetInput.addEventListener('input', (e) => {
                clearTimeout(validationTimeout);
                validationTimeout = setTimeout(() => {
                    this.validateTargetInput(e.target);
                }, 500);
            });
            
            targetInput.addEventListener('blur', (e) => {
                this.hideInputSuggestions();
            });
            
            targetInput.addEventListener('focus', (e) => {
                if (e.target.value.trim()) {
                    this.validateTargetInput(e.target);
                }
            });
        }
    }
    
    // ===== INITIALIZATION METHODS - Same pattern as nmap ===== //
    
    initializeProfiles() {
        const profileCards = document.querySelectorAll('.profile-card');
        
        profileCards.forEach(card => {
            card.addEventListener('click', () => {
                // Remove active class from all cards
                profileCards.forEach(c => c.classList.remove('active'));
                
                // Add active class to clicked card
                card.classList.add('active');
                
                // Update discovery config
                this.discoveryConfig.profile = card.getAttribute('data-profile');
                
                // Update UI based on profile
                this.updateProfileSettings(this.discoveryConfig.profile);
                
                // Add selection animation
                this.animateProfileSelection(card);
                
                // Update estimated duration
                this.updateEstimatedDuration();
            });
        });
    }
    
    initializeViewOptions() {
        const viewButtons = document.querySelectorAll('.view-btn');
        const viewContainers = document.querySelectorAll('.results-view');
        
        viewButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                const viewType = btn.getAttribute('data-view');
                
                // Update active button
                viewButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Show corresponding view
                viewContainers.forEach(container => {
                    container.classList.remove('active');
                });
                
                const targetView = document.getElementById(`${viewType}-view`);
                if (targetView) {
                    targetView.classList.add('active');
                }
                
                // Load view-specific content
                this.loadViewContent(viewType);
            });
        });
    }
    
    initializeFilters() {
        // Status filter buttons - Same pattern as nmap
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                filterButtons.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                const filterValue = btn.getAttribute('data-filter');
                this.filterResults(filterValue);
            });
        });
        
        // OS filter dropdown
        const osFilter = document.getElementById('os-filter');
        if (osFilter) {
            osFilter.addEventListener('change', (e) => {
                this.filterByOS(e.target.value);
            });
        }
        
        // Search input
        const searchInput = document.getElementById('host-search');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchHosts(e.target.value);
                }, 300);
            });
        }
    }
    
    initializeExampleCarousel() {
        const slides = document.querySelectorAll('.example-slide');
        const dots = document.querySelectorAll('.dot');
        const prevBtn = document.querySelector('.example-nav.prev');
        const nextBtn = document.querySelector('.example-nav.next');
        
        if (slides.length === 0) return;
        
        let currentSlide = 0;
        
        const showSlide = (index) => {
            slides.forEach((slide, i) => {
                slide.classList.toggle('active', i === index);
            });
            
            dots.forEach((dot, i) => {
                dot.classList.toggle('active', i === index);
            });
        };
        
        const nextSlide = () => {
            currentSlide = (currentSlide + 1) % slides.length;
            showSlide(currentSlide);
        };
        
        const prevSlide = () => {
            currentSlide = (currentSlide - 1 + slides.length) % slides.length;
            showSlide(currentSlide);
        };
        
        // Auto-advance carousel
        const carouselInterval = setInterval(nextSlide, 5000);
        
        // Manual navigation
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                clearInterval(carouselInterval);
                nextSlide();
            });
        }
        
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                clearInterval(carouselInterval);
                prevSlide();
            });
        }
        
        // Dot navigation
        dots.forEach((dot, index) => {
            dot.addEventListener('click', () => {
                clearInterval(carouselInterval);
                currentSlide = index;
                showSlide(currentSlide);
            });
        });
    }
    
    initializeTooltips() {
        const tooltipElements = document.querySelectorAll('[data-tooltip]');
        
        tooltipElements.forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target);
            });
            
            element.addEventListener('mouseleave', (e) => {
                this.hideTooltip(e.target);
            });
        });
    }
    
    startNetworkAnimation() {
        // Animate the host dots in the hero visualization
        const hostDots = document.querySelectorAll('.host-dot');
        
        hostDots.forEach((dot, index) => {
            setTimeout(() => {
                if (!dot.classList.contains('active')) {
                    dot.classList.add('active');
                }
            }, index * 500);
        });
        
        // Periodically update dot states to simulate discovery
        setInterval(() => {
            if (!this.isDiscovering) {
                hostDots.forEach(dot => {
                    const states = ['active', 'discovering', 'pending'];
                    const currentState = states.find(state => dot.classList.contains(state));
                    
                    if (Math.random() > 0.8) {
                        if (currentState) dot.classList.remove(currentState);
                        dot.classList.add(states[Math.floor(Math.random() * states.length)]);
                    }
                });
            }
        }, 3000);
    }
    
    updateHeroStats() {
        // Load initial stats from backend
        this.loadDiscoveryStatistics();
        
        // Update every 30 seconds when not discovering
        setInterval(() => {
            if (!this.isDiscovering) {
                this.loadDiscoveryStatistics();
            }
        }, 30000);
    }
    
    // ===== API INTEGRATION METHODS - Same pattern as nmap ===== //
    
    async startDiscovery() {
        if (this.isDiscovering) return;
        
        // Validate form
        if (!this.validateDiscoveryForm()) {
            return;
        }
        
        // Prepare discovery data for backend
        const discoveryData = this.prepareDiscoveryData();
        
        try {
            this.isDiscovering = true;
            this.updateDiscoveryButtonState('discovering');
            this.showScanStatus();
            this.hideResults();
            
            // Reset real-time statistics
            this.resetRealTimeStats();
            
            // Start discovery timer
            this.discoveryStartTime = Date.now();
            this.startScanTimer();
            
            // Start real-time updates
            this.simulateRealTimeUpdates();
            
            console.log('Sending discovery request:', discoveryData);
            
            // Send discovery request to backend
            const response = await fetch('/host-discovery', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(discoveryData)
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `Discovery failed: ${response.statusText}`);
            }
            
            const result = await response.json();
            console.log('Discovery started:', result);
            
            if (result.status === 'success') {
                this.currentDiscoveryId = result.discovery_id;
                
                this.addScanLogEntry(`Discovery started with ID: ${this.currentDiscoveryId}`, 'info');
                this.addScanLogEntry(`Estimated duration: ${result.estimated_duration}`, 'info');
                this.addScanLogEntry(`Target: ${discoveryData.targetNetwork}`, 'info');
                this.addScanLogEntry(`Method: ${discoveryData.discoveryMethod}`, 'info');
                
                // Show recommendations if available
                if (result.recommendations) {
                    this.displayRecommendations(result.recommendations);
                }
                
                // Monitor discovery progress using backend
                this.monitorDiscoveryProgress();
                
                // Show success notification
                this.showNotification('Host discovery started successfully', 'success');
            } else {
                throw new Error(result.message || 'Failed to start discovery');
            }
            
        } catch (error) {
            console.error('Discovery failed:', error);
            this.handleDiscoveryError(error);
        }
    }
    
    async startQuickDiscovery() {
        // Auto-detect local network and start quick discovery
        const localNetwork = await this.detectLocalNetwork();
        
        if (localNetwork) {
            const targetInput = document.getElementById('target-network');
            if (targetInput) {
                targetInput.value = localNetwork;
                await this.validateTargetInput(targetInput);
            }
            
            // Set quick discovery profile
            this.selectProfile('ping-sweep');
            
            // Start discovery
            this.startDiscovery();
        } else {
            this.showNotification('Could not detect local network. Please enter target manually.', 'warning');
        }
    }
    
    async stopDiscovery() {
        if (!this.isDiscovering || !this.currentDiscoveryId) return;
        
        try {
            const response = await fetch(`/host-discovery/cancel/${this.currentDiscoveryId}`, {
                method: 'POST'
            });
            
            if (response.ok) {
                const result = await response.json();
                this.addScanLogEntry('Discovery cancellation requested', 'warning');
                this.showNotification('Discovery cancelled successfully', 'info');
                // The status will be updated via monitoring
            } else {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Failed to cancel discovery');
            }
        } catch (error) {
            console.error('Failed to stop discovery:', error);
            this.showNotification('Failed to cancel discovery: ' + error.message, 'error');
        }
    }
    
    async monitorDiscoveryProgress() {
        if (!this.currentDiscoveryId) return;
        
        this.progressUpdateInterval = setInterval(async () => {
            try {
                console.log(`Checking status for discovery: ${this.currentDiscoveryId}`);
                const response = await fetch(`/host-discovery/status/${this.currentDiscoveryId}`);
                
                if (!response.ok) {
                    throw new Error('Failed to get discovery status');
                }
                
                const status = await response.json();
                console.log('Discovery status:', status);
                console.log('Discovery data structure:', {
                    hasDiscovery: !!status.discovery,
                    discoveryStatus: status.discovery?.status,
                    hasResults: !!status.discovery?.results,
                    resultsHosts: status.discovery?.results?.hosts?.length || 0
                });
                
                // Update UI with real progress from backend
                this.updateDiscoveryStatusFromBackend(status);
                
                if (status.discovery.status === 'completed') {
                    console.log('Discovery completed, showing results');
                    this.handleDiscoveryComplete(status.discovery.results);
                } else if (status.discovery.status === 'error') {
                    console.log('Discovery failed:', status.discovery.error);
                    this.handleDiscoveryError(new Error(status.discovery.error || 'Discovery failed'));
                } else if (status.discovery.status === 'cancelled') {
                    console.log('Discovery cancelled');
                    this.handleDiscoveryComplete(null, true);
                }
                
            } catch (error) {
                console.error('Failed to get discovery status:', error);
                // Continue monitoring but show warning
                this.addScanLogEntry('Warning: Status update failed', 'warning');
            }
        }, 2000);
    }
    
    async loadDiscoveryStatistics() {
        try {
            const response = await fetch('/host-discovery/statistics');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    this.updateHeroStatsFromBackend(data.statistics);
                }
            }
        } catch (error) {
            console.error('Failed to load statistics:', error);
        }
    }
    
    prepareDiscoveryData() {
        const targetInput = document.getElementById('target-network');
        const targetTypeSelect = document.getElementById('target-type');
        
        // Get selected profile
        const selectedProfile = document.querySelector('.profile-card.active');
        const discoveryMethod = selectedProfile ? selectedProfile.getAttribute('data-profile') : 'comprehensive';
        
        return {
            targetNetwork: targetInput?.value?.trim() || '',
            targetType: targetTypeSelect?.value || 'network-range',
            discoveryMethod: discoveryMethod,
            timingTemplate: 'T3'  // Default timing for backend compatibility
        };
    }
    
    validateDiscoveryForm() {
        const targetInput = document.getElementById('target-network');
        
        if (!targetInput || !targetInput.value.trim()) {
            this.showNotification('Please enter a target network', 'error');
            targetInput?.focus();
            return false;
        }
        
        // Check if validation has already been done
        const validation = targetInput.parentElement.querySelector('.input-validation');
        if (validation && validation.classList.contains('invalid')) {
            this.showNotification('Please enter a valid network target', 'error');
            targetInput?.focus();
            return false;
        }
        
        return true;
    }
    
    async validateTargetInput(input) {
        if (!input.value.trim()) {
            this.clearInputValidation(input);
            return;
        }
        
        try {
            // Use backend validation endpoint
            const response = await fetch('/host-discovery/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ target: input.value.trim() })
            });
            
            const result = await response.json();
            
            if (result.status === 'valid') {
                this.setInputValidation(input, 'valid');
                this.updateTargetInfo(result);
                this.hideInputSuggestions();
                this.updateEstimatedDuration();
            } else if (result.status === 'invalid') {
                this.setInputValidation(input, 'invalid');
                this.showInputSuggestions(input, result.suggestions);
            } else {
                this.setInputValidation(input, 'invalid');
            }
            
        } catch (error) {
            console.error('Validation failed:', error);
            this.setInputValidation(input, 'invalid');
        }
    }
    
    updateDiscoveryStatusFromBackend(status) {
        // Extract discovery data from nested response
        const discovery = status.discovery || status;
        
        // Update progress bar with real progress
        if (discovery.progress !== undefined) {
            this.updateScanProgress(discovery.progress);
        }
        
        // Update elapsed time
        if (discovery.elapsed_time !== undefined) {
            const timeElement = document.getElementById('discovery-time');
            if (timeElement) {
                timeElement.textContent = this.formatTime(discovery.elapsed_time * 1000);
            }
        }
        
        // Update status text
        const statusElement = document.getElementById('discovery-status-text');
        if (statusElement) {
            statusElement.textContent = this.formatStatusText(discovery.status);
        }
        
        // Update real-time statistics from backend data
        if (discovery.results) {
            this.updateRealTimeStatsFromBackend(discovery.results);
        }
        
        // Add log entry for status changes
        if (discovery.status !== this.lastStatusUpdate) {
            this.addScanLogEntry(`Status: ${this.formatStatusText(discovery.status)}`, 'info');
            this.lastStatusUpdate = discovery.status;
        }
        
        // Update current phase if scanning
        if (discovery.status === 'scanning') {
            this.updateCurrentPhase('Host Discovery in Progress');
        }
    }
    
    formatStatusText(status) {
        const statusMap = {
            'starting': 'Initializing Discovery',
            'scanning': 'Scanning Network',
            'completed': 'Discovery Complete',
            'failed': 'Discovery Failed',
            'cancelled': 'Discovery Cancelled'
        };
        
        return statusMap[status] || status;
    }
    
    updateRealTimeStatsFromBackend(results) {
        // Update real-time statistics with actual backend data
        if (results.hostCount !== undefined) {
            this.realTimeStats.hostsFound = results.hostCount;
        }
        
        if (results.totalPortsScanned !== undefined) {
            this.realTimeStats.portsScanned = results.totalPortsScanned;
        }
        
        if (results.openPortsCount !== undefined) {
            this.realTimeStats.openPorts = results.openPortsCount;
        }
        
        // Calculate additional stats from hosts data
        if (results.hosts && Array.isArray(results.hosts)) {
            let totalPorts = 0;
            let openPorts = 0;
            let respondingHosts = 0;
            let timeoutHosts = 0;
            let totalResponseTime = 0;
            
            results.hosts.forEach(host => {
                if (host.status === 'up' || host.status === 'responding') {
                    respondingHosts++;
                } else if (host.status === 'timeout' || host.status === 'down') {
                    timeoutHosts++;
                }
                
                if (host.ports && Array.isArray(host.ports)) {
                    totalPorts += host.ports.length;
                    openPorts += host.ports.filter(port => port.state === 'open').length;
                }
                
                if (host.responseTime) {
                    totalResponseTime += host.responseTime;
                }
            });
            
            // Update stats with calculated values
            this.realTimeStats.activeHosts = respondingHosts;
            this.realTimeStats.respondingHosts = respondingHosts;
            this.realTimeStats.timeoutHosts = timeoutHosts;
            this.realTimeStats.avgResponseTime = respondingHosts > 0 ? Math.round(totalResponseTime / respondingHosts) : 0;
            
            // Use calculated port stats if not provided directly
            if (results.totalPortsScanned === undefined) {
                this.realTimeStats.portsScanned = totalPorts;
            }
            if (results.openPortsCount === undefined) {
                this.realTimeStats.openPorts = openPorts;
            }
        }
        
        // Update the UI with the new statistics
        this.updateRealTimeStats();
    }
    
    handleDiscoveryComplete(results = null, cancelled = false) {
        this.isDiscovering = false;
        this.currentDiscoveryId = null;
        
        // Stop all intervals
        this.stopRealTimeUpdates();
        this.stopScanTimer();
        
        if (this.progressUpdateInterval) {
            clearInterval(this.progressUpdateInterval);
            this.progressUpdateInterval = null;
        }
        
        // Update UI
        this.updateDiscoveryButtonState('complete');
        
        if (cancelled) {
            this.addScanLogEntry('Discovery cancelled by user', 'warning');
            setTimeout(() => {
                this.hideStatus();
                this.updateDiscoveryButtonState('ready');
            }, 2000);
        } else if (results) {
            this.addScanLogEntry('Discovery completed successfully', 'success');
            this.addScanLogEntry(`Found ${results.hostCount} active hosts`, 'success');
            
            // Show completion notification
            this.showNotification(`Discovery complete! Found ${results.hostCount} hosts`, 'success');
            
            // Show results after a brief delay
            setTimeout(() => {
                this.hideStatus();
                this.displayResults(results);
                this.updateDiscoveryButtonState('ready');
            }, 1500);
        }
        
        // Reload statistics
        this.loadDiscoveryStatistics();
    }
    
    handleDiscoveryError(error) {
        this.isDiscovering = false;
        this.currentDiscoveryId = null;
        
        // Stop all intervals
        this.stopRealTimeUpdates();
        this.stopScanTimer();
        
        if (this.progressUpdateInterval) {
            clearInterval(this.progressUpdateInterval);
            this.progressUpdateInterval = null;
        }
        
        // Update UI
        this.updateDiscoveryButtonState('error');
        this.addScanLogEntry(`Error: ${error.message}`, 'error');
        
        // Show error notification
        this.showNotification('Discovery failed: ' + error.message, 'error');
        
        // Reset button after delay
        setTimeout(() => {
            this.updateDiscoveryButtonState('ready');
            this.hideStatus();
        }, 5000);
    }
    
    displayResults(results) {
        if (!results) {
            this.showNotification('No results to display', 'warning');
            return;
        }
        
        // Update results summary from real backend data
        this.updateResultsSummary(results);
        
        // Populate different views with real host data
        this.populateHostsGrid(results.hosts);
        this.populateHostsTable(results.hosts);
        
        // Show results panel
        this.showResults();
        
        // Store results for export
        this.lastResults = results;
        
        // Show command used
        this.showDiscoveryCommand(results.command);
    }
    
    updateResultsSummary(results) {
        const summaryElements = {
            'total-hosts-found': results.hostCount || 0,
            'total-subnets': 1, // Could be calculated from results if needed
            'discovery-duration': results.duration || '0:00',
            'response-percentage': results.responseRate || 0
        };
        
        Object.entries(summaryElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        });
    }
    
    populateHostsGrid(hosts) {
        const hostsGrid = document.getElementById('hosts-grid');
        if (!hostsGrid || !hosts) return;
        
        hostsGrid.innerHTML = '';
        
        hosts.forEach((host, index) => {
            const hostCard = this.createHostCard(host);
            hostCard.style.animationDelay = `${index * 0.1}s`;
            hostCard.classList.add('host-row');
            hostsGrid.appendChild(hostCard);
        });
    }
    
    createHostCard(host) {
        const card = document.createElement('div');
        card.className = 'host-card';
        card.innerHTML = `
            <div class="host-header">
                <h3 class="host-ip"><i class="fas fa-server"></i>${host.ip}</h3>
                <div class="host-status ${host.status}">
                    <i class="fas fa-${this.getStatusIcon(host.status)}"></i>
                    ${host.status.toUpperCase()}
                </div>
            </div>
            <div class="host-details">
                <div class="host-detail-item">
                    <span class="host-detail-label">Hostname:</span>
                    <span class="host-detail-value">${host.hostname || 'Unknown'}</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">Response Time:</span>
                    <span class="host-detail-value">${host.responseTime}ms</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">MAC Address:</span>
                    <span class="host-detail-value">${host.macAddress || 'Unknown'}</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">Vendor:</span>
                    <span class="host-detail-value">${host.vendor || 'Unknown'}</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">OS:</span>
                    <span class="host-detail-value">${host.os || 'Unknown'}</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">Discovery Method:</span>
                    <span class="host-detail-value discovery-method-badge">${host.discoveryMethod}</span>
                </div>
                <div class="host-detail-item">
                    <span class="host-detail-label">Last Seen:</span>
                    <span class="host-detail-value">${this.formatTimestamp(host.lastSeen)}</span>
                </div>
            </div>
            <div class="host-actions">
                <button class="host-action-btn" onclick="window.hostDiscovery.scanHost('${host.ip}')">
                    <i class="fas fa-search"></i> Scan Ports
                </button>
                <button class="host-action-btn" onclick="window.hostDiscovery.copyIP('${host.ip}')">
                    <i class="fas fa-copy"></i> Copy IP
                </button>
            </div>
        `;
        return card;
    }
    
    populateHostsTable(hosts) {
        const tableContainer = document.getElementById('hosts-table');
        if (!tableContainer || !hosts) return;
        
        const table = document.createElement('table');
        table.className = 'hosts-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>OS</th>
                    <th>Discovery Method</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${hosts.map((host, index) => `
                    <tr class="host-row" style="animation-delay: ${index * 0.05}s">
                        <td class="host-ip">${host.ip}</td>
                        <td>${host.hostname || '-'}</td>
                        <td>
                            <span class="host-status ${host.status}">
                                <i class="fas fa-${this.getStatusIcon(host.status)}"></i>
                                ${host.status}
                            </span>
                        </td>
                        <td>${host.responseTime}ms</td>
                        <td>${host.macAddress || '-'}</td>
                        <td>${host.vendor || '-'}</td>
                        <td>${host.os || '-'}</td>
                        <td>
                            <span class="discovery-method-badge">${host.discoveryMethod}</span>
                        </td>
                        <td>
                            <button class="host-action-btn" onclick="window.hostDiscovery.scanHost('${host.ip}')">
                                <i class="fas fa-search"></i>
                            </button>
                            <button class="host-action-btn" onclick="window.hostDiscovery.copyIP('${host.ip}')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        `;
        
        tableContainer.innerHTML = '';
        tableContainer.appendChild(table);
    }

    // ===== RECOMMENDATIONS DISPLAY METHOD ===== //

    displayRecommendations(recommendations) {
        // Recommendations panel removed to match nmap scanner interface
        // Only log recommendations to discovery log
        if (!recommendations) return;
        
        this.addScanLogEntry(`Recommendations: ${recommendations.recommended_method || 'comprehensive'} method, ${recommendations.recommended_timing || 'T3'} timing`, 'info');
        
        if (recommendations.notes && recommendations.notes.length > 0) {
           recommendations.notes.forEach(note => {
               this.addScanLogEntry(`Note: ${note}`, 'info');
           });
       }
   }
   
   // ===== UI UPDATE METHODS ===== //
   
   updateDiscoveryButtonState(state) {
       const btn = this.discoveryBtn;
       if (!btn) return;
       
       const icon = btn.querySelector('.launch-icon');
       const text = btn.querySelector('.btn-text');
       
       btn.classList.remove('discovering', 'complete', 'error');
       
       switch (state) {
           case 'discovering':
               btn.classList.add('discovering');
               btn.disabled = true;
               if (icon) icon.className = 'fas fa-spinner launch-icon';
               if (text) text.textContent = 'Discovering...';
               if (this.cancelBtn) this.cancelBtn.style.display = 'inline-block';
               break;
               
           case 'complete':
               btn.classList.add('complete');
               btn.disabled = true;
               if (icon) icon.className = 'fas fa-check launch-icon';
               if (text) text.textContent = 'Discovery Complete';
               if (this.cancelBtn) this.cancelBtn.style.display = 'none';
               break;
               
           case 'error':
               btn.classList.add('error');
               btn.disabled = true;
               if (icon) icon.className = 'fas fa-exclamation-triangle launch-icon';
               if (text) text.textContent = 'Discovery Failed';
               if (this.cancelBtn) this.cancelBtn.style.display = 'none';
               break;
               
           case 'ready':
           default:
               btn.disabled = false;
               if (icon) icon.className = 'fas fa-radar launch-icon';
               if (text) text.textContent = 'Start Host Discovery';
               if (this.cancelBtn) this.cancelBtn.style.display = 'none';
               break;
       }
   }
   
   // ===== SCAN STATUS METHODS - COPIED FROM NMAP ===== //

   showScanStatus() {
       const statusPanel = this.statusPanel;
       statusPanel.style.display = 'block';
       statusPanel.style.opacity = '0';
       
       setTimeout(() => {
           statusPanel.style.opacity = '1';
       }, 10);
       
       // Initialize scan log
       this.clearScanLog();
       this.addScanLogEntry('Initializing discovery engine...', 'info');
       this.addScanLogEntry('Validating target configuration...', 'info');
       this.addScanLogEntry('Starting host discovery...', 'info');
       
       // Reset progress
       this.updateScanProgress(0);
       this.updateCurrentPhase('Host Discovery');
   }

   hideStatus() {
       const statusPanel = this.statusPanel;
       statusPanel.style.opacity = '0';
       
       setTimeout(() => {
           statusPanel.style.display = 'none';
       }, 300);
   }

   showResults() {
       const resultsPanel = this.resultsSection;
       resultsPanel.style.display = 'block';
       resultsPanel.style.opacity = '0';
       
       setTimeout(() => {
           resultsPanel.style.opacity = '1';
       }, 10);
   }

   hideResults() {
       const resultsPanel = this.resultsSection;
       resultsPanel.style.opacity = '0';
       
       setTimeout(() => {
           resultsPanel.style.display = 'none';
       }, 300);
   }

   startScanTimer() {
       this.discoveryTimer = setInterval(() => {
           const elapsed = Date.now() - this.discoveryStartTime;
           const timeText = this.formatTime(elapsed);
           
           const timeElement = document.getElementById('discovery-time');
           if (timeElement) {
               timeElement.textContent = timeText;
           }
       }, 1000);
   }

   stopScanTimer() {
       if (this.discoveryTimer) {
           clearInterval(this.discoveryTimer);
           this.discoveryTimer = null;
       }
   }

   simulateRealTimeUpdates() {
       let progress = 0;
       const phases = [
           'Host Discovery',
           'Network Mapping',
           'Response Analysis',
           'Service Detection',
           'Finalizing Results'
       ];
       
       let currentPhase = 0;
       
       this.realTimeInterval = setInterval(() => {
           progress += Math.random() * 15 + 5;
           
           if (progress > 100) {
               progress = 100;
               clearInterval(this.realTimeInterval);
           }
           
           // Update phase
           const phaseProgress = Math.floor((progress / 100) * phases.length);
           if (phaseProgress !== currentPhase && phaseProgress < phases.length) {
               currentPhase = phaseProgress;
               this.updateCurrentPhase(phases[currentPhase]);
               this.addScanLogEntry(`Starting ${phases[currentPhase]}...`, 'info');
           }
           
           // Update progress
           this.updateScanProgress(progress);
           
           // Only simulate statistics if we don't have real backend data yet
           // This prevents overriding real data with simulated data
           if (!this.currentDiscoveryId || this.realTimeStats.hostsFound === 0) {
               if (Math.random() > 0.7) {
                   this.realTimeStats.hostsFound += Math.floor(Math.random() * 2);
                   this.realTimeStats.portsScanned = (this.realTimeStats.portsScanned || 0) + Math.floor(Math.random() * 50 + 10);
                   this.realTimeStats.openPorts = (this.realTimeStats.openPorts || 0) + Math.floor(Math.random() * 3);
                   
                   this.updateRealTimeStats();
                   
                   // Add some log entries
                   if (Math.random() > 0.8) {
                       const messages = [
                           'Found active host',
                           'Network response detected',
                           'Host enumeration complete',
                           'Analyzing response times'
                       ];
                       this.addScanLogEntry(messages[Math.floor(Math.random() * messages.length)], 'success');
                   }
               }
           }
       }, 500);
   }

   stopRealTimeUpdates() {
       if (this.realTimeInterval) {
           clearInterval(this.realTimeInterval);
           this.realTimeInterval = null;
       }
   }

   updateScanProgress(percentage) {
       const progressFill = document.querySelector('.progress-fill');
       const progressText = document.querySelector('.progress-text');
       
       if (progressFill) {
           progressFill.style.width = `${percentage}%`;
       }
       
       if (progressText) {
           progressText.textContent = `${Math.round(percentage)}%`;
       }
   }

   updateCurrentPhase(phase) {
       const phaseElement = document.getElementById('current-phase');
       if (phaseElement) {
           phaseElement.textContent = phase;
       }
       
       this.realTimeStats.currentPhase = phase;
   }

   updateRealTimeStats() {
       const liveHosts = document.getElementById('live-hosts');
       const livePorts = document.getElementById('live-ports');
       const liveOpenPorts = document.getElementById('live-open-ports');
       
       if (liveHosts) liveHosts.textContent = this.realTimeStats.hostsFound;
       if (livePorts) livePorts.textContent = this.realTimeStats.portsScanned || '0';
       if (liveOpenPorts) liveOpenPorts.textContent = this.realTimeStats.openPorts || '0';
       
       // Update header stats
       const hostsDiscovered = document.getElementById('hosts-discovered');
       const discoveryStatus = document.getElementById('discovery-status-text');
       
       if (hostsDiscovered) hostsDiscovered.textContent = `${this.realTimeStats.hostsFound} Hosts`;
       if (discoveryStatus) discoveryStatus.textContent = this.realTimeStats.currentPhase;
   }
   
   resetRealTimeStats() {
       // Reset all real-time statistics to initial values
       this.realTimeStats = {
           hostsFound: 0,
           portsScanned: 0,
           openPorts: 0,
           currentPhase: 'Ready',
           activeHosts: 0,
           respondingHosts: 0,
           timeoutHosts: 0,
           avgResponseTime: 0
       };
       
       // Update the UI immediately
       this.updateRealTimeStats();
   }

   addScanLogEntry(message, type = 'info') {
       const logContent = document.getElementById('scan-log');
       if (!logContent) return;
       
       const timestamp = new Date().toLocaleTimeString();
       const entry = document.createElement('div');
       entry.className = `log-entry ${type}`;
       entry.innerHTML = `
           <span class="timestamp">[${timestamp}]</span>
           <span class="message">${message}</span>
       `;
       
       logContent.appendChild(entry);
       logContent.scrollTop = logContent.scrollHeight;
   }

   clearScanLog() {
       const logContent = document.getElementById('scan-log');
       if (logContent) {
           logContent.innerHTML = '';
       }
   }
   
   // ===== UTILITY METHODS ===== //
   
   formatTime(milliseconds) {
       const seconds = Math.floor(milliseconds / 1000);
       const minutes = Math.floor(seconds / 60);
       const remainingSeconds = seconds % 60;
       
       if (minutes > 0) {
           return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
       }
       return `0:${seconds.toString().padStart(2, '0')}`;
   }
   
   formatTimestamp(timestamp) {
       if (!timestamp) return 'Unknown';
       
       const date = new Date(timestamp);
       return date.toLocaleString();
   }
   
   getStatusIcon(status) {
       const iconMap = {
           'active': 'check-circle',
           'responding': 'wifi',
           'timeout': 'times-circle',
           'unknown': 'question-circle'
       };
       return iconMap[status] || 'server';
   }
   
   getDeviceIcon(host) {
       if (host.vendor && host.vendor.toLowerCase().includes('apple')) return 'laptop';
       if (host.vendor && host.vendor.toLowerCase().includes('cisco')) return 'network-wired';
       if (host.os && host.os.toLowerCase().includes('windows')) return 'desktop';
       if (host.os && host.os.toLowerCase().includes('linux')) return 'server';
       return 'desktop';
   }
   
   // ===== PROFILE AND CONFIGURATION METHODS ===== //
   
   selectProfile(profileName) {
       const profileCard = document.querySelector(`[data-profile="${profileName}"]`);
       if (profileCard) {
           profileCard.click();
       }
   }
   
   updateProfileSettings(profile) {
       // Profile-specific settings are handled automatically
       this.discoveryConfig.profile = profile;
   }
   
   animateProfileSelection(card) {
       // Add a brief highlight animation
       card.style.transform = 'scale(1.05)';
       setTimeout(() => {
           card.style.transform = '';
       }, 200);
   }
   
   updateEstimatedDuration() {
       // Simplified duration estimation based on profile only
       const targetInput = document.getElementById('target-network');
       if (!targetInput || !targetInput.value.trim()) return;
       
       let baseDuration = 60; // seconds
       
       // Adjust based on profile
       switch (this.discoveryConfig.profile) {
           case 'ping-sweep': baseDuration *= 0.3; break;
           case 'arp-scan': baseDuration *= 0.2; break;
           case 'tcp-connect': baseDuration *= 1.5; break;
           case 'comprehensive': baseDuration *= 2; break;
       }
       
       console.log(`Estimated duration: ${Math.round(baseDuration)} seconds`);
   }
   
   // ===== INPUT VALIDATION METHODS ===== //
   
   setInputValidation(input, state) {
       const wrapper = input.parentElement;
       let validation = wrapper.querySelector('.input-validation');
       
       if (!validation) {
           validation = document.createElement('div');
           validation.className = 'input-validation';
           wrapper.appendChild(validation);
       }
       
       validation.classList.remove('valid', 'invalid');
       validation.classList.add(state);
       validation.style.display = 'block';
   }
   
   clearInputValidation(input) {
       const wrapper = input.parentElement;
       const validation = wrapper.querySelector('.input-validation');
       if (validation) {
           validation.style.display = 'none';
       }
   }
   
   showInputSuggestions(input, suggestions = []) {
       if (!suggestions || suggestions.length === 0) return;
       
       const wrapper = input.parentElement;
       let suggestionsContainer = wrapper.querySelector('.input-suggestions');
       
       if (!suggestionsContainer) {
           suggestionsContainer = document.createElement('div');
           suggestionsContainer.className = 'input-suggestions';
           wrapper.appendChild(suggestionsContainer);
       }
       
       suggestionsContainer.innerHTML = suggestions.map(suggestion => 
           `<div class="suggestion-item">${suggestion}</div>`
       ).join('');
       
       suggestionsContainer.style.display = 'block';
       
       // Add click handlers
       suggestionsContainer.querySelectorAll('.suggestion-item').forEach(item => {
           item.addEventListener('click', () => {
               // Could implement suggestion selection
               this.hideInputSuggestions();
           });
       });
   }
   
   hideInputSuggestions() {
       const suggestions = document.querySelectorAll('.input-suggestions');
       suggestions.forEach(container => {
           container.style.display = 'none';
       });
   }
   
   updateTargetInfo(info) {
       // Display additional information about the target
       console.log('Target info:', info);
       
       // Could display network type, estimated hosts, etc.
       if (info.is_private_network) {
           this.showNotification('Private network detected - faster discovery recommended', 'info');
       }
   }
   
   // ===== NETWORK DETECTION ===== //
   
   async detectLocalNetwork() {
       try {
           // Simple local network detection
           // In a real implementation, this could use WebRTC or other methods
           const commonNetworks = [
               '192.168.1.0/24',
               '192.168.0.0/24',
               '10.0.0.0/24',
               '172.16.0.0/24'
           ];
           
           // Return most common network as default
           return commonNetworks[0];
       } catch (error) {
           console.error('Failed to detect local network:', error);
           return null;
       }
   }
   
   // ===== RESULTS FILTERING AND SEARCHING ===== //
   
   filterResults(filter) {
       if (!this.lastResults || !this.lastResults.hosts) return;
       
       const hosts = this.lastResults.hosts;
       let filteredHosts = hosts;
       
       switch (filter) {
           case 'active':
               filteredHosts = hosts.filter(h => h.status === 'active');
               break;
           case 'responding':
               filteredHosts = hosts.filter(h => h.status === 'responding');
               break;
           case 'timeout':
               filteredHosts = hosts.filter(h => h.status === 'timeout');
               break;
           case 'all':
           default:
               filteredHosts = hosts;
               break;
       }
       
       this.displayFilteredResults(filteredHosts);
   }
   
   filterByOS(osFilter) {
       if (!this.lastResults || !this.lastResults.hosts) return;
       
       let filteredHosts = this.lastResults.hosts;
       
       if (osFilter) {
           filteredHosts = filteredHosts.filter(host => 
               host.os && host.os.toLowerCase().includes(osFilter.toLowerCase())
           );
       }
       
       this.displayFilteredResults(filteredHosts);
   }
   
   searchHosts(searchTerm) {
       if (!this.lastResults || !this.lastResults.hosts) return;
       
       if (!searchTerm.trim()) {
           this.displayFilteredResults(this.lastResults.hosts);
           return;
       }
       
       const term = searchTerm.toLowerCase();
       const filteredHosts = this.lastResults.hosts.filter(host => 
           host.ip.toLowerCase().includes(term) ||
           (host.hostname && host.hostname.toLowerCase().includes(term)) ||
           (host.vendor && host.vendor.toLowerCase().includes(term)) ||
           (host.os && host.os.toLowerCase().includes(term))
       );
       
       this.displayFilteredResults(filteredHosts);
   }
   
   displayFilteredResults(hosts) {
       // Update current view with filtered results
       const activeView = document.querySelector('.view-btn.active');
       if (!activeView) return;
       
       const viewType = activeView.getAttribute('data-view');
       
       switch (viewType) {
           case 'grid':
               this.populateHostsGrid(hosts);
               break;
           case 'list':
               this.populateHostsTable(hosts);
               break;
       }
   }
   
   loadViewContent(viewType) {
       if (!this.lastResults) return;
       
       switch (viewType) {
           case 'grid':
               this.populateHostsGrid(this.lastResults.hosts);
               break;
           case 'list':
               this.populateHostsTable(this.lastResults.hosts);
               break;
       }
   }
   
   // ===== EXPORT FUNCTIONALITY ===== //
   
   async exportResults(format) {
       if (!this.lastResults || !this.lastResults.hosts) {
           this.showNotification('No discovery results to export', 'warning');
           return;
       }
       
       try {
           const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
           
           if (format === 'json') {
               this.downloadJSON(this.lastResults, `host_discovery_${timestamp}.json`);
           } else if (format === 'csv') {
               const csvData = this.generateCSVData();
               this.downloadText(csvData, `host_discovery_${timestamp}.csv`, 'text/csv');
           } else if (format === 'txt') {
               const txtData = this.generateHostList();
               this.downloadText(txtData, `host_list_${timestamp}.txt`, 'text/plain');
           }
           
           this.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
           
       } catch (error) {
           console.error('Export failed:', error);
           this.showNotification('Export failed: ' + error.message, 'error');
       }
   }
   
   copyHostList() {
       if (!this.lastResults || !this.lastResults.hosts) {
           this.showNotification('No hosts to copy', 'warning');
           return;
       }
       
       const activeHosts = this.lastResults.hosts.filter(h => h.status === 'active');
       const hostList = activeHosts.map(h => h.ip).join('\n');
       
       navigator.clipboard.writeText(hostList).then(() => {
           this.showNotification(`Copied ${activeHosts.length} active host IPs to clipboard`, 'success');
       }).catch(error => {
           console.error('Failed to copy to clipboard:', error);
           this.showNotification('Failed to copy to clipboard', 'error');
       });
   }
   
   generateCSVData() {
       if (!this.lastResults || !this.lastResults.hosts) return '';
       
       let csvContent = 'IP Address,Hostname,Status,Response Time (ms),MAC Address,Vendor,OS,Discovery Method,Last Seen\n';
       
       this.lastResults.hosts.forEach(host => {
           const escapeCsv = (str) => `"${(str || '').toString().replace(/"/g, '""')}"`;
           
           csvContent += [
               escapeCsv(host.ip),
               escapeCsv(host.hostname || ''),
               escapeCsv(host.status),
               escapeCsv(host.responseTime || ''),
               escapeCsv(host.macAddress || ''),
               escapeCsv(host.vendor || ''),
               escapeCsv(host.os || ''),
               escapeCsv(host.discoveryMethod || ''),
               escapeCsv(host.lastSeen || '')
           ].join(',') + '\n';
       });
       
       return csvContent;
   }

   generateHostList() {
       if (!this.lastResults || !this.lastResults.hosts) return '';
       
       let output = `# Host Discovery Results\n`;
       output += `# Target: ${this.lastResults.targetNetwork}\n`;
       output += `# Method: ${this.lastResults.discoveryMethod}\n`;
       output += `# Date: ${new Date().toISOString()}\n\n`;
       
       this.lastResults.hosts.forEach(host => {
           output += `${host.ip}`;
           if (host.hostname) output += ` (${host.hostname})`;
           output += ` - ${host.status}`;
           if (host.vendor) output += ` - ${host.vendor}`;
           output += '\n';
       });
       
       return output;
   }
   
   downloadJSON(data, filename) {
       const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
       this.downloadBlob(blob, filename);
   }
   
   downloadText(text, filename, mimeType = 'text/plain') {
       const blob = new Blob([text], { type: mimeType });
       this.downloadBlob(blob, filename);
   }
   
   downloadBlob(blob, filename) {
       const url = URL.createObjectURL(blob);
       const a = document.createElement('a');
       a.href = url;
       a.download = filename;
       document.body.appendChild(a);
       a.click();
       document.body.removeChild(a);
       URL.revokeObjectURL(url);
   }
   
   // ===== ACTION METHODS ===== //
   
   scanHost(ip) {
       // Navigate to port scanner with pre-filled IP
       window.location.href = `/network-scanner?target=${ip}`;
   }
   
   copyIP(ip) {
       navigator.clipboard.writeText(ip).then(() => {
           this.showNotification(`Copied ${ip} to clipboard`, 'success');
       }).catch(error => {
           console.error('Failed to copy IP:', error);
           this.showNotification('Failed to copy IP', 'error');
       });
   }
   
   startNewDiscovery() {
       // Reset form and UI
       this.hideResults();
       this.hideStatus();
       this.updateDiscoveryButtonState('ready');
       
       // Clear form
       const targetInput = document.getElementById('target-network');
       if (targetInput) {
           targetInput.value = '';
           this.clearInputValidation(targetInput);
       }
       
       // Reset to default profile
       this.selectProfile('comprehensive');
       
       // Show notification
       this.showNotification('Ready for new discovery', 'info');
   }
   
   saveResults() {
       if (!this.lastResults) {
           this.showNotification('No results to save', 'warning');
           return;
       }
       
       // In a real implementation, this would save to database
       this.exportResults('json');
   }
   
   shareResults() {
       if (!this.lastResults) {
           this.showNotification('No results to share', 'warning');
           return;
       }
       
       // Generate shareable summary
       const summary = `Host Discovery Results:\n` +
                      `Target: ${this.lastResults.targetNetwork}\n` +
                      `Hosts Found: ${this.lastResults.hostCount}\n` +
                      `Response Rate: ${this.lastResults.responseRate}%\n` +
                      `Duration: ${this.lastResults.duration}`;
       
       if (navigator.share) {
           navigator.share({
               title: 'Host Discovery Results',
               text: summary
           });
       } else {
           navigator.clipboard.writeText(summary).then(() => {
               this.showNotification('Results copied to clipboard for sharing', 'success');
           });
       }
   }
   
   showDiscoveryCommand(command) {
       if (!command) return;
       
       // Find or create command display area
       let commandSection = document.querySelector('.command-section');
       if (!commandSection) {
           commandSection = document.createElement('div');
           commandSection.className = 'command-section';
           commandSection.innerHTML = `
               <div class="command-header">
                   <h4><i class="fas fa-terminal"></i> Discovery Command</h4>
                   <button class="btn btn-xs" onclick="window.hostDiscovery.copyCommand('${command}')">
                       <i class="fas fa-copy"></i> Copy 
                   </button>
              </div>
              <pre class="command-text">${command}</pre>
          `;
          
          // Insert before results content
          const resultsContent = document.querySelector('.results-content');
          if (resultsContent) {
              resultsContent.parentNode.insertBefore(commandSection, resultsContent);
          }
      } else {
          const commandText = commandSection.querySelector('.command-text');
          if (commandText) {
              commandText.textContent = command;
          }
          
          const copyBtn = commandSection.querySelector('.btn');
          if (copyBtn) {
              copyBtn.onclick = () => this.copyCommand(command);
          }
      }
  }
  
  copyCommand(command) {
      navigator.clipboard.writeText(command).then(() => {
          this.showNotification('Command copied to clipboard', 'success');
      }).catch(error => {
          console.error('Failed to copy command:', error);
          this.showNotification('Failed to copy command', 'error');
      });
  }
  
  // ===== HERO STATS UPDATE ===== //
  
  updateHeroStatsFromBackend(stats) {
      const statsElements = {
          'hero-hosts-found': stats.total_hosts_found || 0,
          'hero-networks-scanned': stats.total_discoveries || 0,
          'hero-avg-response': stats.average_hosts_per_discovery ? `${stats.average_hosts_per_discovery}` : '0'
      };
      
      Object.entries(statsElements).forEach(([id, value]) => {
          const element = document.getElementById(id);
          if (element) {
              // Animate number change
              this.animateNumber(element, parseInt(element.textContent) || 0, value);
          }
      });
  }
  
  updateHeroDuringDiscovery() {
      if (!this.isDiscovering) return;
      
      // Update hero stats during discovery
      const hostsElement = document.getElementById('hero-hosts-found');
      const responseElement = document.getElementById('hero-avg-response');
      
      if (hostsElement && this.realTimeStats.hostsFound) {
          this.animateNumber(hostsElement, parseInt(hostsElement.textContent) || 0, this.realTimeStats.hostsFound);
      }
      
      if (responseElement && this.realTimeStats.avgResponseTime) {
          responseElement.textContent = `${this.realTimeStats.avgResponseTime}ms`;
      }
  }
  
  animateNumber(element, from, to) {
      if (from === to) return;
      
      const duration = 1000; // 1 second
      const steps = 20;
      const stepValue = (to - from) / steps;
      const stepDuration = duration / steps;
      
      let current = from;
      let step = 0;
      
      const timer = setInterval(() => {
          step++;
          current += stepValue;
          
          if (step >= steps) {
              element.textContent = to;
              clearInterval(timer);
          } else {
              element.textContent = Math.round(current);
          }
      }, stepDuration);
  }
  
  // ===== AUTH-STYLE NOTIFICATION SYSTEM ===== //
  
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
  
   removeNotification(notification) {
       if (!notification || !notification.parentNode) return;
       
       notification.style.opacity = '0';
       notification.style.transform = 'translateX(100%)';
       
       setTimeout(() => {
           if (notification.parentNode) {
               notification.parentNode.removeChild(notification);
           }
       }, 300);
       
       // Remove from tracking
       if (this.activeNotifications) {
           const index = this.activeNotifications.indexOf(notification);
           if (index > -1) {
               this.activeNotifications.splice(index, 1);
           }
       }
   }
  
   getNotificationIcon(type) {
       const icons = {
           'success': 'check-circle',
           'error': 'exclamation-circle',
           'warning': 'exclamation-triangle',
           'info': 'info-circle'
       };
       return icons[type] || 'info-circle';
   }
   
   getNotificationColor(type) {
       const colors = {
           'success': '#10b981',
           'error': '#ef4444',
           'warning': '#f59e0b',
           'info': '#3b82f6'
       };
       return colors[type] || '#3b82f6';
   }
  
  // ===== TOOLTIP SYSTEM ===== //
  
  showTooltip(element) {
      const tooltipText = element.getAttribute('data-tooltip');
      if (!tooltipText) return;
      
      // Remove existing tooltips
      this.hideAllTooltips();
      
      const tooltip = document.createElement('div');
      tooltip.className = 'tooltip';
      tooltip.textContent = tooltipText;
      document.body.appendChild(tooltip);
      
      // Position tooltip
      const rect = element.getBoundingClientRect();
      const tooltipRect = tooltip.getBoundingClientRect();
      
      let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
      let top = rect.top - tooltipRect.height - 8;
      
      // Adjust if tooltip goes off screen
      if (left < 8) left = 8;
      if (left + tooltipRect.width > window.innerWidth - 8) {
          left = window.innerWidth - tooltipRect.width - 8;
      }
      if (top < 8) {
          top = rect.bottom + 8;
      }
      
      tooltip.style.left = `${left}px`;
      tooltip.style.top = `${top}px`;
      tooltip.style.opacity = '1';
      
      // Store reference for cleanup
      element._tooltip = tooltip;
  }
  
  hideTooltip(element) {
      if (element._tooltip) {
          element._tooltip.remove();
          element._tooltip = null;
      }
  }
  
  hideAllTooltips() {
      const tooltips = document.querySelectorAll('.tooltip');
      tooltips.forEach(tooltip => tooltip.remove());
  }
  
  // ===== MODAL SYSTEM ===== //
  
  showHelpModal() {
      const modal = document.createElement('div');
      modal.className = 'modal-overlay';
      modal.innerHTML = `
          <div class="modal-content">
              <div class="modal-header">
                  <h3 class="modal-title">Host Discovery Help</h3>
                  <button class="modal-close">
                      <i class="fas fa-times"></i>
                  </button>
              </div>
              <div class="modal-body">
                  <h4>Discovery Methods</h4>
                  <ul>
                      <li><strong>Ping Sweep:</strong> Fast ICMP discovery for basic host detection</li>
                      <li><strong>ARP Scan:</strong> Local network discovery using ARP requests</li>
                      <li><strong>TCP Connect:</strong> Reliable discovery using TCP connections</li>
                      <li><strong>Comprehensive:</strong> Multiple techniques for thorough discovery</li>
                  </ul>
                  
                  <h4>Network Formats</h4>
                  <ul>
                      <li><strong>Single IP:</strong> 192.168.1.1</li>
                      <li><strong>CIDR Range:</strong> 192.168.1.0/24</li>
                      <li><strong>IP Range:</strong> 192.168.1.1-254</li>
                  </ul>
                  
                  <h4>Timing Templates</h4>
                  <ul>
                      <li><strong>T1-T2:</strong> Slow and stealthy</li>
                      <li><strong>T3:</strong> Normal speed (default)</li>
                      <li><strong>T4-T5:</strong> Fast and aggressive</li>
                  </ul>
                  
                  <h4>Legal Notice</h4>
                  <p>Only scan networks you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations.</p>
              </div>
          </div>
      `;
      
      document.body.appendChild(modal);
      
      // Show modal
      setTimeout(() => {
          modal.classList.add('active');
      }, 10);
      
      // Close handlers
      const closeBtn = modal.querySelector('.modal-close');
      closeBtn.addEventListener('click', () => {
          this.hideModal(modal);
      });
      
      modal.addEventListener('click', (e) => {
          if (e.target === modal) {
              this.hideModal(modal);
          }
      });
      
      // ESC key handler
      const escHandler = (e) => {
          if (e.key === 'Escape') {
              this.hideModal(modal);
              document.removeEventListener('keydown', escHandler);
          }
      };
      document.addEventListener('keydown', escHandler);
  }
  
  hideModal(modal) {
      modal.classList.remove('active');
      setTimeout(() => {
          if (modal.parentNode) {
              modal.parentNode.removeChild(modal);
          }
      }, 300);
  }
  
  // ===== DROPDOWN FUNCTIONALITY ===== //
  
  initializeDropdowns() {
      const dropdowns = document.querySelectorAll('.dropdown');
      
      dropdowns.forEach(dropdown => {
          const toggle = dropdown.querySelector('.dropdown-toggle');
          const menu = dropdown.querySelector('.dropdown-menu');
          
          if (toggle && menu) {
              toggle.addEventListener('click', (e) => {
                  e.stopPropagation();
                  
                  // Close other dropdowns
                  dropdowns.forEach(other => {
                      if (other !== dropdown) {
                          other.classList.remove('open');
                      }
                  });
                  
                  // Toggle current dropdown
                  dropdown.classList.toggle('open');
              });
          }
      });
      
      // Close dropdowns when clicking outside
      document.addEventListener('click', () => {
          dropdowns.forEach(dropdown => {
              dropdown.classList.remove('open');
          });
      });
  }
  
  // ===== SCROLL AND ANIMATION UTILITIES ===== //
  
  scrollToResults() {
      if (this.resultsSection) {
          this.resultsSection.scrollIntoView({
              behavior: 'smooth',
              block: 'start'
          });
      }
  }
  
  addPageTransitionEffects() {
      // Add fade-in effects to elements as they come into view
      const observerOptions = {
          threshold: 0.1,
          rootMargin: '0px 0px -50px 0px'
      };
      
      const observer = new IntersectionObserver((entries) => {
          entries.forEach(entry => {
              if (entry.isIntersecting) {
                  entry.target.classList.add('visible');
              }
          });
      }, observerOptions);
      
      // Observe animated elements
      const animatedElements = document.querySelectorAll('.animate-fade-up');
      animatedElements.forEach(el => {
          observer.observe(el);
      });
  }
  
  // ===== CLEANUP AND DESTROY ===== //
  
  destroy() {
      // Clean up intervals and event listeners
      this.stopScanTimer();
      this.stopRealTimeUpdates();
      
      if (this.progressUpdateInterval) {
          clearInterval(this.progressUpdateInterval);
      }
      
      // Remove all notifications
      this.activeNotifications.forEach(notification => {
          this.removeNotification(notification);
      });
      
      // Hide all tooltips
      this.hideAllTooltips();
      
      console.log('Host Discovery Manager destroyed');
  }
}

// ===== INITIALIZATION AND GLOBAL SETUP ===== //

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Initialize discovery manager
  window.hostDiscovery = new HostDiscoveryManager();
  
  // Add global error handler
  window.addEventListener('error', (event) => {
      console.error('Global error:', event.error);
      if (window.hostDiscovery) {
          window.hostDiscovery.showNotification('An unexpected error occurred', 'error');
      }
  });
  
  // Add unload handler to cleanup
  window.addEventListener('beforeunload', () => {
      if (window.hostDiscovery) {
          window.hostDiscovery.destroy();
      }
  });
  
  // Initialize additional features
  if (window.hostDiscovery) {
      window.hostDiscovery.initializeDropdowns();
      window.hostDiscovery.addPageTransitionEffects();
  }
  
  console.log('Host Discovery page fully initialized');
});

// ===== ADDITIONAL CSS ANIMATIONS (if needed) ===== //

// Add dynamic styles for animations
const addDynamicStyles = () => {
  const style = document.createElement('style');
  style.textContent = `
      .tooltip {
          position: absolute;
          background: var(--card-bg);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 0.5rem 0.75rem;
          font-size: 0.8rem;
          color: var(--text-primary);
          box-shadow: var(--shadow-lg);
          z-index: var(--z-tooltip);
          opacity: 0;
          transition: opacity 0.2s ease;
          pointer-events: none;
          white-space: nowrap;
      }
      
      .animate-fade-up {
          opacity: 0;
          transform: translateY(20px);
          transition: all 0.6s ease;
      }
      
      .animate-fade-up.visible {
          opacity: 1;
          transform: translateY(0);
      }
      
      .discovery-phase-transition {
          animation: phaseTransition 0.5s ease-in-out;
      }
      
      @keyframes phaseTransition {
          0% { opacity: 0.7; transform: scale(0.98); }
          50% { opacity: 1; transform: scale(1.02); }
          100% { opacity: 1; transform: scale(1); }
      }
      
      .host-card.new-host {
          animation: newHostAppear 0.8s ease-out;
      }
      
      @keyframes newHostAppear {
          0% { 
              opacity: 0; 
              transform: translateY(30px) scale(0.9); 
              box-shadow: 0 0 0 rgba(46, 204, 113, 0);
          }
          50% { 
              opacity: 0.7; 
              transform: translateY(10px) scale(0.95);
              box-shadow: 0 8px 32px rgba(46, 204, 113, 0.2);
          }
          100% { 
              opacity: 1; 
              transform: translateY(0) scale(1);
              box-shadow: 0 4px 16px rgba(46, 204, 113, 0.1);
          }
      }
      
      .notification {
          position: fixed;
          top: 2rem;
          right: 2rem;
          min-width: 300px;
          max-width: 500px;
          z-index: var(--z-toast);
          opacity: 0;
          transform: translateX(100%);
          transition: all 0.3s ease;
      }
      
      .hero-stat-updating {
          animation: statUpdate 1s ease-in-out;
      }
      
      @keyframes statUpdate {
          0% { transform: scale(1); }
          50% { transform: scale(1.1); color: var(--hd-primary); }
          100% { transform: scale(1); }
      }
      
      .profile-card-selecting {
          animation: profileSelect 0.3s ease-out;
      }
      
      @keyframes profileSelect {
          0% { transform: scale(1); }
          50% { transform: scale(1.05); box-shadow: 0 8px 32px rgba(46, 204, 113, 0.2); }
          100% { transform: scale(1); }
      }
      
      .discovery-progress-pulse {
          animation: progressPulse 2s ease-in-out infinite;
      }
      
      @keyframes progressPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(46, 204, 113, 0.4); }
          50% { box-shadow: 0 0 0 10px rgba(46, 204, 113, 0); }
      }
      
      .results-appear {
          animation: resultsAppear 1s ease-out;
      }
      
      @keyframes resultsAppear {
          0% { 
              opacity: 0; 
              transform: translateY(50px); 
          }
          100% { 
              opacity: 1; 
              transform: translateY(0); 
          }
      }
  `;
  
  document.head.appendChild(style);
};

// Add styles when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', addDynamicStyles);
} else {
  addDynamicStyles();
}

// ===== EXPORT FOR MODULE SYSTEMS ===== //
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HostDiscoveryManager;
}