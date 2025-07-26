/**
 * Enhanced SANA Network Scanner JavaScript
 * Advanced functionality with real-time updates, enhanced UI interactions, and AI-powered features
 */

class NetworkScannerEnhanced {
    constructor() {
        this.scanForm = document.getElementById('scan-form');
        this.scanBtn = document.getElementById('scan-btn');
        this.scanStatus = document.getElementById('scan-status');
        this.resultsSection = document.getElementById('results-section');
        this.hostsContainer = document.getElementById('hosts-container');
        this.commandDisplay = document.getElementById('command-display');
        this.commandText = document.getElementById('command-text');
        
        this.isScanning = false;
        this.scanStartTime = null;
        this.scanTimer = null;
        this.lastResults = null;
        this.currentProfile = 'balanced';
        this.estimatedTime = 0;
        
        // Enhanced features
        this.targetSuggestions = [];
        this.scanHistory = [];
        this.realTimeStats = {
            hostsFound: 0,
            portsScanned: 0,
            openPorts: 0,
            currentPhase: 'Ready'
        };
        
        this.init();
    }

    init() {
        this.initializeNotificationSystem();
        this.setupEventListeners();
        this.initializeUI();
        this.loadScanHistory();
        this.setupTargetValidation();
        this.initializeTooltips();
        this.startStatsAnimation();
    }

    setupEventListeners() {
        // Form submission
        this.scanForm.addEventListener('submit', (e) => this.handleScanSubmit(e));
        
        // Profile selection
        document.querySelectorAll('.profile-option').forEach(option => {
            option.addEventListener('click', (e) => this.selectProfile(e));
        });
        
        // Quick action buttons
        document.getElementById('local-scan-btn')?.addEventListener('click', () => this.quickLocalScan());
        document.getElementById('focus-scan-btn')?.addEventListener('click', () => this.focusOnTarget());
        document.getElementById('new-scan-btn')?.addEventListener('click', () => this.resetForm());
        
        // Advanced options toggle
        document.querySelectorAll('.section-header.collapsible').forEach(header => {
            header.addEventListener('click', (e) => this.toggleCollapsible(e));
        });
        
        // Port presets
        document.querySelectorAll('.preset-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.applyPortPreset(e));
        });
        
        // Timing slider
        const timingSlider = document.getElementById('timing-slider');
        if (timingSlider) {
            timingSlider.addEventListener('input', (e) => this.updateTimingTemplate(e));
        }
        
        // Export functions
        document.getElementById('export-json')?.addEventListener('click', () => this.exportJson());
        document.getElementById('export-csv')?.addEventListener('click', () => this.exportCsv());
        document.getElementById('export-pdf')?.addEventListener('click', () => this.exportPdf());
        document.getElementById('copy-results')?.addEventListener('click', () => this.copyResults());
        document.getElementById('copy-command')?.addEventListener('click', () => this.copyCommand());
        
        // View switching
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchView(e));
        });
        
        // Filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.applyFilter(e));
        });
        
        document.getElementById('service-filter')?.addEventListener('change', (e) => this.filterByService(e));
        document.getElementById('results-search')?.addEventListener('input', (e) => this.searchResults(e));
        
        // Dropdown toggle
        document.querySelectorAll('.dropdown-toggle').forEach(toggle => {
            toggle.addEventListener('click', (e) => this.toggleDropdown(e));
        });
        
        // Tips carousel
        this.initTipsCarousel();
        
        // Cancel scan
        document.getElementById('cancel-scan')?.addEventListener('click', () => this.cancelScan());
        
        // Target input with suggestions
        const targetInput = document.getElementById('target');
        if (targetInput) {
            targetInput.addEventListener('input', (e) => this.handleTargetInput(e));
            targetInput.addEventListener('focus', () => this.showTargetSuggestions());
            targetInput.addEventListener('blur', () => this.hideTargetSuggestions());
        }
        
        // Custom args preview
        document.getElementById('custom-args')?.addEventListener('input', (e) => this.updateCommandPreview(e));
        
        // Floating help
        document.getElementById('floating-help')?.addEventListener('click', () => this.showHelp());
    }

    initializeUI() {
        // Set initial timing template
        this.updateTimingTemplate({ target: { value: '3' } });
        
        // Initialize command preview
        this.updateCommandPreview();
        
        // Set initial estimated time
        this.updateEstimatedTime();
        
        // Initialize real-time stats display
        this.updateRealTimeStats();
        
        // Load saved preferences
        this.loadUserPreferences();
    }

    selectProfile(e) {
        const option = e.currentTarget;
        const profile = option.dataset.profile;
        
        // Remove active class from all options
        document.querySelectorAll('.profile-option').forEach(opt => opt.classList.remove('active'));
        
        // Add active class to selected option
        option.classList.add('active');
        
        // Update current profile
        this.currentProfile = profile;
        document.getElementById('scan-type').value = profile;
        
        // Show/hide custom args
        const customArgsGroup = document.getElementById('custom-args-group');
        if (profile === 'custom') {
            customArgsGroup.style.display = 'block';
            setTimeout(() => {
                customArgsGroup.style.opacity = '1';
                customArgsGroup.style.transform = 'translateY(0)';
            }, 10);
        } else {
            customArgsGroup.style.opacity = '0';
            customArgsGroup.style.transform = 'translateY(-10px)';
            setTimeout(() => {
                customArgsGroup.style.display = 'none';
            }, 300);
        }
        
        // Update estimated time based on profile
        this.updateEstimatedTime();
        
        // Update command preview
        this.updateCommandPreview();
        
        // Animate selection
        option.style.transform = 'scale(1.05)';
        setTimeout(() => {
            option.style.transform = '';
        }, 200);
    }

    toggleCollapsible(e) {
        const header = e.currentTarget;
        const target = header.dataset.target;
        const content = document.getElementById(target);
        const icon = header.querySelector('.toggle-icon');
        
        header.classList.toggle('collapsed');
        content.classList.toggle('collapsed');
        
        // Animate icon
        if (header.classList.contains('collapsed')) {
            icon.style.transform = 'rotate(-90deg)';
        } else {
            icon.style.transform = 'rotate(0deg)';
        }
    }

    applyPortPreset(e) {
        const btn = e.currentTarget;
        const ports = btn.dataset.ports;
        const portInput = document.getElementById('port-range');
        
        portInput.value = ports;
        
        // Animate button
        btn.style.transform = 'scale(0.95)';
        btn.style.background = 'var(--primary)';
        btn.style.color = 'white';
        
        setTimeout(() => {
            btn.style.transform = '';
            btn.style.background = '';
            btn.style.color = '';
        }, 200);
        
        this.updateEstimatedTime();
        this.updateCommandPreview();
    }

    updateTimingTemplate(e) {
        const value = e.target.value;
        const templates = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
        const template = templates[value];
        
        document.getElementById('timing-template').value = template;
        
        // Update estimated time
        this.updateEstimatedTime();
        this.updateCommandPreview();
    }

    updateEstimatedTime() {
        const target = document.getElementById('target').value;
        const portRange = document.getElementById('port-range').value;
        const timing = document.getElementById('timing-template').value;
        
        let baseTime = 30; // seconds
        
        // Adjust based on target complexity
        if (target.includes('/24')) baseTime *= 10;
        else if (target.includes('-')) baseTime *= 5;
        
        // Adjust based on port range
        if (portRange) {
            if (portRange.includes('1-65535')) baseTime *= 20;
            else if (portRange.includes('1-1000')) baseTime *= 2;
        }
        
        // Adjust based on timing
        const timingMultipliers = { 'T0': 10, 'T1': 5, 'T2': 2, 'T3': 1, 'T4': 0.5, 'T5': 0.25 };
        baseTime *= timingMultipliers[timing] || 1;
        
        // Adjust based on profile
        const profileMultipliers = { 
            'stealth': 3, 
            'balanced': 1, 
            'aggressive': 0.5, 
            'comprehensive': 5,
            'custom': 1 
        };
        baseTime *= profileMultipliers[this.currentProfile] || 1;
        
        this.estimatedTime = baseTime;
        
        // Format time display
        let timeText;
        if (baseTime < 60) {
            timeText = `${Math.round(baseTime)} seconds`;
        } else if (baseTime < 3600) {
            timeText = `${Math.round(baseTime / 60)} minutes`;
        } else {
            timeText = `${Math.round(baseTime / 3600)} hours`;
        }
        
        const estimatedTimeElement = document.getElementById('estimated-time');
        if (estimatedTimeElement) {
            estimatedTimeElement.textContent = timeText;
        }
    }

    updateCommandPreview() {
        const target = document.getElementById('target').value || '[target]';
        const timing = document.getElementById('timing-template').value;
        const portRange = document.getElementById('port-range').value;
        const profile = this.currentProfile;
        const customArgs = document.getElementById('custom-args')?.value;
        
        let command = `nmap -${timing}`;
        
        // Add profile-specific arguments
        switch (profile) {
            case 'stealth':
                command += ' -sS -T2';
                break;
            case 'balanced':
                command += ' -sV';
                break;
            case 'aggressive':
                command += ' -sS -sV -sC -O';
                break;
            case 'comprehensive':
                command += ' -sS -sV -sC -O -A';
                break;
            case 'custom':
                command += customArgs ? ` ${customArgs}` : '';
                break;
        }
        
        // Add port range
        if (portRange) {
            command += ` -p ${portRange}`;
        }
        
        // Add target
        command += ` ${target}`;
        
        const previewElement = document.getElementById('command-preview-text');
        if (previewElement) {
            previewElement.textContent = command;
        }
    }

    setupTargetValidation() {
        const targetInput = document.getElementById('target');
        const validation = targetInput?.parentElement.querySelector('.input-validation');
        
        if (!targetInput || !validation) return;
        
        targetInput.addEventListener('input', () => {
            const value = targetInput.value.trim();
            const validationStatus = document.getElementById('target-validation');
            
            if (!value) {
                validation.className = 'input-validation';
                if (validationStatus) validationStatus.textContent = 'Pending';
                if (validationStatus) validationStatus.className = 'status-pending';
                return;
            }
            
            // Validate IP, hostname, or range
            const isValid = this.validateTarget(value);
            
            if (isValid) {
                validation.className = 'input-validation valid';
                if (validationStatus) validationStatus.textContent = 'Valid';
                if (validationStatus) validationStatus.className = 'status-valid';
            } else {
                validation.className = 'input-validation invalid';
                if (validationStatus) validationStatus.textContent = 'Invalid';
                if (validationStatus) validationStatus.className = 'status-invalid';
            }
        });
    }

    validateTarget(target) {
        // IP address validation
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        // CIDR notation validation
        const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
        
        // IP range validation
        const rangeRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        // Hostname validation
        const hostnameRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
        
        return ipRegex.test(target) || cidrRegex.test(target) || rangeRegex.test(target) || hostnameRegex.test(target);
    }

    handleTargetInput(e) {
        const value = e.target.value;
        this.updateCommandPreview();
        this.updateEstimatedTime();
        
        // Show suggestions based on input
        if (value.length > 2) {
            this.showRelevantSuggestions(value);
        } else {
            this.hideTargetSuggestions();
        }
    }

    showRelevantSuggestions(value) {
        const suggestions = [
            'scanme.nmap.org',
            '192.168.1.1/24',
            '10.0.0.1-254',
            '127.0.0.1',
            'localhost',
            '192.168.0.1',
            '10.0.0.1/8',
            '172.16.0.0/12'
        ].filter(suggestion => 
            suggestion.toLowerCase().includes(value.toLowerCase())
        );

        const suggestionsContainer = document.getElementById('target-suggestions');
        if (suggestionsContainer && suggestions.length > 0) {
            suggestionsContainer.innerHTML = suggestions.map(suggestion => 
                `<div class="suggestion-item" onclick="networkScanner.selectSuggestion('${suggestion}')">${suggestion}</div>`
            ).join('');
            suggestionsContainer.style.display = 'block';
        }
    }

    selectSuggestion(suggestion) {
        document.getElementById('target').value = suggestion;
        this.hideTargetSuggestions();
        this.updateCommandPreview();
        this.updateEstimatedTime();
    }

    showTargetSuggestions() {
        const suggestionsContainer = document.getElementById('target-suggestions');
        if (suggestionsContainer && suggestionsContainer.children.length > 0) {
            suggestionsContainer.style.display = 'block';
        }
    }

    hideTargetSuggestions() {
        setTimeout(() => {
            const suggestionsContainer = document.getElementById('target-suggestions');
            if (suggestionsContainer) {
                suggestionsContainer.style.display = 'none';
            }
        }, 200);
    }

    quickLocalScan() {
        this.animateFormFill('target', '192.168.1.1/24');
        
        // Select balanced profile
        document.querySelectorAll('.profile-option').forEach(opt => opt.classList.remove('active'));
        document.querySelector('[data-profile="balanced"]').classList.add('active');
        this.currentProfile = 'balanced';
        
        this.animateFormFill('port-range', '22,80,443,3389');
        document.getElementById('timing-template').value = 'T3';
        document.getElementById('timing-slider').value = '3';
        
        this.updateCommandPreview();
        this.updateEstimatedTime();
        this.showNotification('Quick scan configuration loaded!', 'success');
    }

    focusOnTarget() {
        const targetInput = document.getElementById('target');
        targetInput.focus();
        targetInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        
        // Add focus animation
        targetInput.style.transform = 'scale(1.02)';
        setTimeout(() => {
            targetInput.style.transform = '';
        }, 300);
    }

    resetForm() {
        this.scanForm.reset();
        this.hideResults();
        this.hideStatus();
        
        // Reset profile selection
        document.querySelectorAll('.profile-option').forEach(opt => opt.classList.remove('active'));
        document.querySelector('[data-profile="balanced"]').classList.add('active');
        this.currentProfile = 'balanced';
        
        // Reset timing slider
        document.getElementById('timing-slider').value = '3';
        document.getElementById('timing-template').value = 'T3';
        
        this.updateCommandPreview();
        this.updateEstimatedTime();
        
        // Focus on target
        this.focusOnTarget();
        
        this.showNotification('Form reset successfully', 'info');
    }

    animateFormFill(fieldId, value) {
        const field = document.getElementById(fieldId);
        if (!field) return;
        
        let currentValue = '';
        let index = 0;
        
        const interval = setInterval(() => {
            if (index < value.length) {
                currentValue += value[index];
                field.value = currentValue;
                index++;
                
                // Trigger input event for validation
                field.dispatchEvent(new Event('input'));
            } else {
                clearInterval(interval);
            }
        }, 50);
    }

    async handleScanSubmit(e) {
        e.preventDefault();
        
        if (this.isScanning) return;
        
        const formData = this.collectFormData();
        
        if (!this.validateFormData(formData)) {
            return;
        }
        
        this.startScan(formData);
    }

    collectFormData() {
        return {
            target: document.getElementById('target').value.trim(),
            scanType: this.currentProfile,
            portRange: document.getElementById('port-range').value.trim(),
            timingTemplate: document.getElementById('timing-template').value,
            customArgs: document.getElementById('custom-args')?.value.trim() || '',
            serviceDetection: document.getElementById('service-detection')?.checked || false,
            osDetection: document.getElementById('os-detection')?.checked || false,
            scriptScan: document.getElementById('script-scan')?.checked || false,
            aggressiveTiming: document.getElementById('aggressive-timing')?.checked || false
        };
    }

    validateFormData(data) {
        if (!data.target) {
            this.showNotification('Please enter a valid target', 'error');
            return false;
        }
        
        if (!this.validateTarget(data.target)) {
            this.showNotification('Invalid target format', 'error');
            return false;
        }
        
        return true;
    }

    async startScan(formData) {
        this.isScanning = true;
        this.scanStartTime = Date.now();
        
        // Update UI
        this.showScanStatus();
        this.hideResults();
        this.updateScanButton('scanning');
        this.startScanTimer();
        this.simulateRealTimeUpdates();
        
        try {
            const response = await fetch('/nmap-scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            // Add debugging logs
            console.log("Raw server response:", data);
            console.log("Results structure:", data.results);
            
            if (data.status === 'success') {
                this.handleScanSuccess(data);
            } else {
                this.handleScanError(data.message || 'Unknown error occurred');
            }
        } catch (error) {
            this.handleScanError(`Connection error: ${error.message}`);
        } finally {
            this.completeScan();
        }
    }

    handleScanSuccess(data) {
        this.lastResults = data;
        this.hideStatus();
        // The backend returns scan results in the data object, not in data.results
        this.displayResults(data);
        this.showResults();
        this.updateScanButton('complete');
        
        // Update stats
        this.updateFinalStats(data);
        
        // Save to history
        this.saveScanToHistory(data);
        
        // Show success notification
        const hostCount = data.hostCount || data.summary?.total_hosts || 0;
        const portCount = data.portCount || data.summary?.open_ports || 0;
        this.showNotification(
            `Scan completed! Found ${hostCount} hosts with ${portCount} open ports`,
            'success'
        );
        
        // Scroll to results
        this.scrollToResults();
    }

    handleScanError(message) {
        this.showNotification(`Scan failed: ${message}`, 'error');
        this.addScanLogEntry(`Error: ${message}`, 'error');
    }

    completeScan() {
        this.isScanning = false;
        this.stopScanTimer();
        this.stopRealTimeUpdates();
        
        setTimeout(() => {
            this.updateScanButton('ready');
        }, 2000);
    }

    updateScanButton(state) {
        const btn = this.scanBtn;
        const icon = btn.querySelector('.launch-icon');
        const text = btn.querySelector('.btn-text');
        
        btn.classList.remove('scanning', 'complete');
        
        switch (state) {
            case 'scanning':
                btn.classList.add('scanning');
                btn.disabled = true;
                icon.className = 'fas fa-spinner launch-icon';
                text.textContent = 'Scanning...';
                break;
                
            case 'complete':
                btn.classList.add('complete');
                btn.disabled = true;
                icon.className = 'fas fa-check launch-icon';
                text.textContent = 'Scan Complete';
                break;
                
            case 'ready':
            default:
                btn.disabled = false;
                icon.className = 'fas fa-rocket launch-icon';
                text.textContent = 'Launch Network Scan';
                break;
        }
    }

    showScanStatus() {
        const statusPanel = this.scanStatus;
        statusPanel.style.display = 'block';
        statusPanel.style.opacity = '0';
        
        setTimeout(() => {
            statusPanel.style.opacity = '1';
        }, 10);
        
        // Initialize scan log
        this.clearScanLog();
        this.addScanLogEntry('Initializing scan engine...', 'info');
        this.addScanLogEntry('Validating target configuration...', 'info');
        this.addScanLogEntry('Starting network discovery...', 'info');
        
        // Reset progress
        this.updateScanProgress(0);
        this.updateCurrentPhase('Host Discovery');
    }

    hideStatus() {
        const statusPanel = this.scanStatus;
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
        this.scanTimer = setInterval(() => {
            const elapsed = Date.now() - this.scanStartTime;
            const timeText = this.formatTime(elapsed);
            
            const timeElement = document.getElementById('scan-time');
            if (timeElement) {
                timeElement.textContent = timeText;
            }
        }, 1000);
    }

    stopScanTimer() {
        if (this.scanTimer) {
            clearInterval(this.scanTimer);
            this.scanTimer = null;
        }
    }

    formatTime(milliseconds) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) {
            return `${hours}:${(minutes % 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`;
        } else {
            return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
        }
    }

    simulateRealTimeUpdates() {
        let progress = 0;
        const phases = [
            'Host Discovery',
            'Port Scanning',
            'Service Detection',
            'Script Execution',
            'OS Detection',
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
            
            // Simulate finding hosts and ports
            if (Math.random() > 0.7) {
                this.realTimeStats.hostsFound += Math.floor(Math.random() * 2);
                this.realTimeStats.portsScanned += Math.floor(Math.random() * 10) + 5;
                this.realTimeStats.openPorts += Math.floor(Math.random() * 3);
                
                this.updateRealTimeStats();
                
                // Add some log entries
                if (Math.random() > 0.8) {
                    const messages = [
                        'Found active host',
                        'Discovered open port',
                        'Service detected',
                        'Checking for vulnerabilities'
                    ];
                    this.addScanLogEntry(messages[Math.floor(Math.random() * messages.length)], 'success');
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
        if (livePorts) livePorts.textContent = this.realTimeStats.portsScanned;
        if (liveOpenPorts) liveOpenPorts.textContent = this.realTimeStats.openPorts;
        
        // Update header stats
        const hostsFound = document.getElementById('hosts-found');
        const portsFound = document.getElementById('ports-found');
        const statusText = document.getElementById('scan-status-text');
        
        if (hostsFound) hostsFound.textContent = `${this.realTimeStats.hostsFound} Hosts`;
        if (portsFound) portsFound.textContent = `${this.realTimeStats.openPorts} Ports`;
        if (statusText) statusText.textContent = this.realTimeStats.currentPhase;
    }

    updateFinalStats(data) {
        const totalHosts = document.getElementById('total-hosts');
        const totalOpenPorts = document.getElementById('total-open-ports');
        const totalVulnerabilities = document.getElementById('total-vulnerabilities');
        
        // Use summary data if available, otherwise fallback to direct properties
        if (totalHosts) totalHosts.textContent = data.summary?.total_hosts || data.hostCount || 0;
        if (totalOpenPorts) totalOpenPorts.textContent = data.summary?.open_ports || data.portCount || 0;
        
        // Count vulnerabilities from security analysis if available
        if (totalVulnerabilities) {
            if (data.security_analysis) {
                totalVulnerabilities.textContent = data.security_analysis.length || 0;
            } else {
                totalVulnerabilities.textContent = this.countVulnerabilities(data.results);
            }
        }
    }

    countVulnerabilities(results) {
        // This would typically analyze the results for potential security issues
        let count = 0;
        
        console.log("Counting vulnerabilities in:", results);
        
        if (!results) return count;
        
        if (Array.isArray(results)) {
            // New format - array of hosts
            results.forEach(host => {
                if (host.protocols) {
                    Object.entries(host.protocols).forEach(([protocol, ports]) => {
                        if (Array.isArray(ports)) {
                            ports.forEach(port => {
                                if (port.state === 'open' && this.isVulnerableService(port.service)) {
                                    count++;
                                }
                            });
                        }
                    });
                }
            });
        } else {
            // Old format - object with IP keys
            Object.values(results).forEach(host => {
                if (host.ports) {
                    host.ports.forEach(port => {
                        // Simple heuristic for potential issues
                        if (port.state === 'open' && this.isVulnerableService(port.service)) {
                            count++;
                        }
                    });
                }
            });
        }
        
        console.log("Vulnerabilities found:", count);
        return count;
    }

    isVulnerableService(service) {
        const vulnerableServices = ['telnet', 'ftp', 'smtp', 'snmp', 'rlogin', 'rsh'];
        return vulnerableServices.includes(service?.toLowerCase());
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

    displayResults(data) {
        // Display command used
        if (data.command) {
            this.commandText.textContent = data.command;
            this.commandDisplay.style.display = 'block';
        }
        
        // Clear previous results
        this.hostsContainer.innerHTML = '';
        
        // Debug the data structure
        console.log("displayResults data:", data);
        
        // Check if we have valid results - handle both possible data structures
        const resultsData = data.results || data.hosts || [];
        
        if (!resultsData || (Array.isArray(resultsData) && resultsData.length === 0) || 
            (!Array.isArray(resultsData) && Object.keys(resultsData).length === 0)) {
            this.displayNoResults();
            return;
        }
        
        // Create host entries with enhanced animations
        this.createHostEntries(resultsData);
        
        // Enable export buttons
        this.enableExportButtons();
    }

    displayNoResults() {
        const noResults = document.createElement('div');
        noResults.className = 'no-results';
        noResults.innerHTML = `
            <div style="text-align: center; padding: 4rem;">
                <i class="fas fa-search fa-4x" style="color: var(--text-secondary); margin-bottom: 2rem;"></i>
                <h3 style="color: var(--text-primary); margin-bottom: 1rem;">No Results Found</h3>
                <p style="color: var(--text-secondary);">No hosts found or all ports are closed/filtered.</p>
                <button class="btn btn-primary" onclick="networkScanner.resetForm()" style="margin-top: 2rem;">
                    <i class="fas fa-redo"></i> Try Different Target
                </button>
            </div>
        `;
        this.hostsContainer.appendChild(noResults);
    }

    createHostEntries(results) {
        let delay = 0;
        
        // Add debugging
        console.log("createHostEntries called with:", results);
        console.log("Results type:", Array.isArray(results) ? "Array" : "Object");
        
        // Handle the backend data structure which has hosts in an array
        if (Array.isArray(results)) {
            // This is the new format from the backend (array of hosts)
            console.log("Processing array format, length:", results.length);
            results.forEach(host => {
                console.log("Processing host:", host);
                const hostCard = this.createHostCard(host.ip, host);
                
                // Add staggered animation
                hostCard.style.opacity = '0';
                hostCard.style.transform = 'translateY(20px)';
                
                this.hostsContainer.appendChild(hostCard);
                
                setTimeout(() => {
                    hostCard.style.transition = 'all 0.5s ease-out';
                    hostCard.style.opacity = '1';
                    hostCard.style.transform = 'translateY(0)';
                }, delay);
                
                delay += 100;
            });
        } else {
            // Handle the old format (object with IP keys)
            console.log("Processing object format, keys:", Object.keys(results));
            Object.entries(results).forEach(([hostIP, host]) => {
                console.log("Processing host with IP:", hostIP, host);
                const hostCard = this.createHostCard(hostIP, host);
                
                // Add staggered animation
                hostCard.style.opacity = '0';
                hostCard.style.transform = 'translateY(20px)';
                
                this.hostsContainer.appendChild(hostCard);
                
                setTimeout(() => {
                    hostCard.style.transition = 'all 0.5s ease-out';
                    hostCard.style.opacity = '1';
                    hostCard.style.transform = 'translateY(0)';
                }, delay);
                
                delay += 100;
            });
        }
    }

    createHostCard(hostIP, host) {
        const hostCard = document.createElement('div');
        hostCard.className = 'host-entry';
        
        console.log("Creating host card for:", hostIP, host);
        
        // Host header
        let hostTitle = hostIP;
        if (host.hostname) {
            hostTitle = `${host.hostname} (${hostIP})`;
        }
        
        const headerHtml = `
            <div class="host-header">
                <h3><i class="fas fa-server"></i> ${hostTitle}</h3>
                <div class="host-status">
                    <i class="fas fa-check-circle"></i>
                    <span>Online</span>
                </div>
            </div>
        `;
        
        // OS Detection section
        let osHtml = '';
        if (host.os && host.os.length > 0) {
            osHtml = `
                <div class="os-detection">
                    <h4><i class="fas fa-laptop"></i> Operating System Detection</h4>
                    <div class="os-details">
                        ${host.os.map(os => `
                            <p>
                                <span>${os.name}</span>
                                <span class="accuracy">
                                    <i class="fas fa-chart-bar"></i>
                                    ${os.accuracy}% Match
                                </span>
                            </p>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        // Extract ports from the host structure
        let ports = [];
        
        // Debug host structure
        console.log("Host structure:", host);
        console.log("Host protocols:", host.protocols);
        
        // Handle the new data structure from the backend
        if (host.protocols) {
            // Extract ports from protocols
            console.log("Extracting ports from protocols");
            Object.entries(host.protocols).forEach(([protocol, protocolPorts]) => {
                console.log("Protocol:", protocol, "Ports:", protocolPorts);
                if (Array.isArray(protocolPorts)) {
                    protocolPorts.forEach(port => {
                        console.log("Adding port:", port);
                        ports.push({
                            ...port,
                            protocol: protocol
                        });
                    });
                }
            });
        } else if (host.ports) {
            // Use the existing ports array if available (old format)
            console.log("Using existing ports array:", host.ports);
            ports = host.ports;
        }
        
        console.log("Final ports array:", ports);
        
        // Ports table
        const portsHtml = this.createPortsTable(ports);
        
        hostCard.innerHTML = headerHtml + osHtml + portsHtml;
        
        return hostCard;
    }

    createPortsTable(ports) {
        if (!ports || ports.length === 0) {
            return `
                <div class="table-responsive">
                    <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                        <i class="fas fa-times-circle fa-2x" style="margin-bottom: 1rem;"></i>
                        <p>No open ports found on this host</p>
                    </div>
                </div>
            `;
        }
        
        // Sort ports numerically
        ports.sort((a, b) => parseInt(a.port) - parseInt(b.port));
        
        let tableHtml = `
            <div class="table-responsive">
                <table class="port-table">
                    <thead>
                        <tr>
                            <th>Port/Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Extra Info</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        ports.forEach((port, index) => {
            const stateIcon = this.getStateIcon(port.state);
            const serviceIcon = this.getServiceIcon(port.service);
            
            tableHtml += `
                <tr class="port-row" style="animation-delay: ${index * 0.1}s;">
                    <td>
                        <span class="port-number">${port.port}</span>/${port.protocol}
                    </td>
                    <td>
                        <span class="port-state ${port.state}">
                            <i class="fas fa-${stateIcon}"></i>
                            ${port.state}
                        </span>
                    </td>
                    <td>
                        <span class="service-name">
                            <i class="fas fa-${serviceIcon}"></i>
                            ${port.service || 'unknown'}
                        </span>
                    </td>
                    <td>
                        ${port.version ? `<span class="service-version">${port.version}</span>` : ''}
                    </td>
                    <td>
                        ${port.extrainfo ? `<span class="extra-info">${port.extrainfo}</span>` : ''}
                    </td>
                </tr>
            `;
        });
        
        tableHtml += `
                    </tbody>
                </table>
            </div>
        `;
        
        return tableHtml;
    }

    getStateIcon(state) {
        const icons = {
            'open': 'check-circle',
            'closed': 'times-circle',
            'filtered': 'question-circle'
        };
        return icons[state] || 'question-circle';
    }

    getServiceIcon(service) {
        if (!service) return 'cog';
        
        const serviceIcons = {
            'http': 'globe',
            'https': 'lock',
            'ssh': 'terminal',
            'ftp': 'file-upload',
            'smtp': 'envelope',
            'dns': 'network-wired',
            'mysql': 'database',
            'postgresql': 'database',
            'mongodb': 'database',
            'redis': 'database',
            'telnet': 'terminal',
            'rdp': 'desktop',
            'smb': 'folder-open',
            'vnc': 'desktop',
            'snmp': 'chart-network',
            'ntp': 'clock',
            'ldap': 'users',
            'imap': 'envelope-open',
            'pop3': 'envelope-square',
            'docker': 'docker',
            'kubernetes': 'dharmachakra',
            'elasticsearch': 'search',
            'jenkins': 'jenkins',
            'nginx': 'server',
            'apache': 'server'
        };
        
        return serviceIcons[service.toLowerCase()] || 'cog';
    }

    enableExportButtons() {
        const buttons = ['export-json', 'export-csv', 'export-pdf', 'copy-results'];
        buttons.forEach(btnId => {
            const btn = document.getElementById(btnId);
            if (btn) {
                btn.disabled = false;
                btn.style.opacity = '1';
            }
        });
    }

    scrollToResults() {
        this.resultsSection.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
        });
    }

    // Export functions
    exportJson() {
        if (!this.lastResults) return;
        
        const dataStr = JSON.stringify(this.lastResults, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        this.downloadFile(blob, 'nmap_scan_results.json');
        
        this.showNotification('Results exported as JSON', 'success');
    }

    exportCsv() {
        if (!this.lastResults) return;
        
        let csvContent = 'Host,Port,Protocol,State,Service,Version,Extra Info\n';
        
        const results = this.lastResults.results || this.lastResults.hosts || [];
        
        if (Array.isArray(results)) {
            // New format - array of hosts
            results.forEach(host => {
                if (host.protocols) {
                    Object.entries(host.protocols).forEach(([protocol, ports]) => {
                        if (Array.isArray(ports)) {
                            ports.forEach(port => {
                                csvContent += `"${host.ip}","${port.port}","${protocol}","${port.state}","${port.service || ''}","${port.version || ''}","${port.extrainfo || ''}"\n`;
                            });
                        }
                    });
                }
            });
        } else {
            // Old format - object with IP keys
            Object.entries(results).forEach(([hostIP, host]) => {
                if (host.ports) {
                    host.ports.forEach(port => {
                        csvContent += `"${hostIP}","${port.port}","${port.protocol}","${port.state}","${port.service || ''}","${port.version || ''}","${port.extrainfo || ''}"\n`;
                    });
                }
            });
        }
        
        const blob = new Blob([csvContent], { type: 'text/csv' });
        this.downloadFile(blob, 'nmap_scan_results.csv');
        
        this.showNotification('Results exported as CSV', 'success');
    }

    exportPdf() {
        if (!this.lastResults) return;
        
        // This would typically use a PDF library like jsPDF
        this.showNotification('PDF export feature coming soon!', 'info');
    }

    copyResults() {
        if (!this.lastResults) return;
        
        let textContent = 'NMAP Scan Results\n';
        textContent += '==================\n\n';
        textContent += `Command: ${this.lastResults.command}\n`;
        textContent += `Scan Date: ${new Date().toLocaleString()}\n\n`;
        
        const results = this.lastResults.results || this.lastResults.hosts || [];
        
        if (Array.isArray(results)) {
            // New format - array of hosts
            results.forEach(host => {
                textContent += `Host: ${host.ip}\n`;
                if (host.hostname) {
                    textContent += `Hostname: ${host.hostname}\n`;
                }
                
                if (host.os && host.os.length > 0) {
                    textContent += '\nOS Detection:\n';
                    host.os.forEach(os => {
                        textContent += `- ${os.name} (${os.accuracy}% accuracy)\n`;
                    });
                }
                
                // Extract ports
                const ports = [];
                if (host.protocols) {
                    Object.entries(host.protocols).forEach(([protocol, protocolPorts]) => {
                        if (Array.isArray(protocolPorts)) {
                            protocolPorts.forEach(port => {
                                ports.push({...port, protocol});
                            });
                        }
                    });
                }
                
                if (ports.length > 0) {
                    textContent += '\nOpen Ports:\n';
                    textContent += 'PORT\t\tSTATE\t\tSERVICE\t\tVERSION\n';
                    textContent += '----\t\t-----\t\t-------\t\t-------\n';
                    ports.forEach(port => {
                        textContent += `${port.port}/${port.protocol}\t\t${port.state}\t\t${port.service || 'unknown'}\t\t${port.version || ''}\n`;
                    });
                }
                
                textContent += '\n' + '-'.repeat(50) + '\n\n';
            });
        } else {
            // Old format - object with IP keys
            Object.entries(results).forEach(([hostIP, host]) => {
                textContent += `Host: ${hostIP}\n`;
                if (host.hostname) {
                    textContent += `Hostname: ${host.hostname}\n`;
                }
                
                if (host.os && host.os.length > 0) {
                    textContent += '\nOS Detection:\n';
                    host.os.forEach(os => {
                        textContent += `- ${os.name} (${os.accuracy}% accuracy)\n`;
                    });
                }
                
                if (host.ports && host.ports.length > 0) {
                    textContent += '\nOpen Ports:\n';
                    textContent += 'PORT\t\tSTATE\t\tSERVICE\t\tVERSION\n';
                    textContent += '----\t\t-----\t\t-------\t\t-------\n';
                    host.ports.forEach(port => {
                        textContent += `${port.port}/${port.protocol}\t\t${port.state}\t\t${port.service || 'unknown'}\t\t${port.version || ''}\n`;
                    });
                }
                
                textContent += '\n' + '-'.repeat(50) + '\n\n';
            });
        }
        
        navigator.clipboard.writeText(textContent).then(() => {
            this.showNotification('Results copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy results', 'error');
        });
    }

    copyCommand() {
        if (!this.lastResults?.command) return;
        
        navigator.clipboard.writeText(this.lastResults.command).then(() => {
            this.showNotification('Command copied to clipboard', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy command', 'error');
        });
    }

    downloadFile(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }

    // View switching
    switchView(e) {
        const btn = e.currentTarget;
        const view = btn.dataset.view;
        
        // Update active button
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update active view
        document.querySelectorAll('.results-view').forEach(v => v.classList.remove('active'));
        document.getElementById(`${view}-view`)?.classList.add('active');
        
        // Handle specific view logic
        if (view === 'topology') {
            this.generateNetworkTopology();
        } else if (view === 'vulnerabilities') {
            this.generateSecurityAnalysis();
        }
    }

    generateNetworkTopology() {
        const container = document.getElementById('network-topology');
        if (!container || !this.lastResults) return;
        
        container.innerHTML = `
            <div style="text-align: center; color: var(--text-secondary);">
                <i class="fas fa-project-diagram fa-3x" style="margin-bottom: 1rem;"></i>
                <h4>Network Topology Visualization</h4>
                <p>Advanced network mapping feature coming soon!</p>
                <p>This will show visual network topology based on scan results.</p>
            </div>
        `;
    }

    generateSecurityAnalysis() {
        const container = document.getElementById('security-analysis');
        if (!container || !this.lastResults) return;
        
        const vulnerabilities = this.analyzeSecurityIssues();
        
        if (vulnerabilities.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                    <i class="fas fa-shield-check fa-3x" style="color: var(--success); margin-bottom: 1rem;"></i>
                    <h4>No Security Issues Detected</h4>
                    <p>No obvious security vulnerabilities found in the scan results.</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = vulnerabilities.map(vuln => `
            <div class="vulnerability-card">
                <div class="vulnerability-header">
                    <h5 class="vulnerability-title">${vuln.title}</h5>
                    <span class="severity-badge ${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                </div>
                <p class="vulnerability-description">${vuln.description}</p>
                <div class="vulnerability-details">
                    <span>Host: ${vuln.host}</span>
                    <span>Port: ${vuln.port}</span>
                    <span>Service: ${vuln.service}</span>
                </div>
            </div>
        `).join('');
    }

    analyzeSecurityIssues() {
        const vulnerabilities = [];
        
        if (!this.lastResults) return vulnerabilities;
        
        const results = this.lastResults.results || this.lastResults.hosts || [];
        console.log("Analyzing security issues in:", results);
        
        if (Array.isArray(results)) {
            // New format - array of hosts
            results.forEach(host => {
                if (host.protocols) {
                    Object.entries(host.protocols).forEach(([protocol, ports]) => {
                        if (Array.isArray(ports)) {
                            ports.forEach(port => {
                                if (port.state === 'open') {
                                    const issues = this.checkPortSecurity(port, host.ip);
                                    vulnerabilities.push(...issues);
                                }
                            });
                        }
                    });
                }
            });
        } else {
            // Old format - object with IP keys
            Object.entries(results).forEach(([hostIP, host]) => {
                if (host.ports) {
                    host.ports.forEach(port => {
                        if (port.state === 'open') {
                            const issues = this.checkPortSecurity(port, hostIP);
                            vulnerabilities.push(...issues);
                        }
                    });
                }
            });
        }
        
        return vulnerabilities;
    }

    checkPortSecurity(port, host) {
        const issues = [];
        const service = port.service?.toLowerCase() || '';
        
        // Check for insecure services
        const insecureServices = {
            'telnet': 'Unencrypted remote access protocol',
            'ftp': 'Unencrypted file transfer protocol',
            'http': 'Unencrypted web traffic',
            'smtp': 'Potentially unencrypted email',
            'snmp': 'Network management protocol with weak authentication'
        };
        
        if (insecureServices[service]) {
            issues.push({
                title: `Insecure Service: ${service.toUpperCase()}`,
                description: insecureServices[service],
                severity: 'medium',
                host: host,
                port: port.port,
                service: service
            });
        }
        
        // Check for common vulnerable ports
        const vulnerablePorts = {
            23: 'Telnet - Unencrypted remote access',
            21: 'FTP - Unencrypted file transfer',
            69: 'TFTP - Trivial file transfer protocol',
            161: 'SNMP - Often uses default community strings',
            1433: 'SQL Server - Database access',
            3389: 'RDP - Remote desktop access'
        };
        
        if (vulnerablePorts[port.port]) {
            issues.push({
                title: `Potentially Vulnerable Port: ${port.port}`,
                description: vulnerablePorts[port.port],
                severity: 'low',
                host: host,
                port: port.port,
                service: service
            });
        }
        
        return issues;
    }

    // Filter functions
    applyFilter(e) {
        const btn = e.currentTarget;
        const filter = btn.dataset.filter;
        
        // Update active filter
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Apply filter to port rows
        document.querySelectorAll('.port-row').forEach(row => {
            const state = row.querySelector('.port-state')?.textContent.trim().toLowerCase();
            
            if (filter === 'all' || state.includes(filter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    filterByService(e) {
        const serviceFilter = e.target.value.toLowerCase();
        
        document.querySelectorAll('.port-row').forEach(row => {
            const service = row.querySelector('.service-name')?.textContent.trim().toLowerCase();
            
            if (!serviceFilter || service.includes(serviceFilter)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    searchResults(e) {
        const searchTerm = e.target.value.toLowerCase();
        
        document.querySelectorAll('.host-entry').forEach(hostEntry => {
            const hostText = hostEntry.textContent.toLowerCase();
            
            if (!searchTerm || hostText.includes(searchTerm)) {
                hostEntry.style.display = '';
            } else {
                hostEntry.style.display = 'none';
            }
        });
    }

    // Dropdown functions
    toggleDropdown(e) {
        const dropdown = e.currentTarget.closest('.dropdown');
        dropdown.classList.toggle('open');
        
        // Close other dropdowns
        document.querySelectorAll('.dropdown').forEach(dd => {
            if (dd !== dropdown) {
                dd.classList.remove('open');
            }
        });
    }

    // Tips carousel
    initTipsCarousel() {
        let currentTip = 0;
        const tips = document.querySelectorAll('.tip-slide');
        const dots = document.querySelectorAll('.dot');
        
        const showTip = (index) => {
            tips.forEach((tip, i) => {
                tip.classList.remove('active', 'prev');
                if (i === index) {
                    tip.classList.add('active');
                } else if (i < index) {
                    tip.classList.add('prev');
                }
            });
            
            dots.forEach((dot, i) => {
                dot.classList.toggle('active', i === index);
            });
        };
        
        document.querySelector('.tip-nav.next')?.addEventListener('click', () => {
            currentTip = (currentTip + 1) % tips.length;
            showTip(currentTip);
        });
        
        document.querySelector('.tip-nav.prev')?.addEventListener('click', () => {
            currentTip = (currentTip - 1 + tips.length) % tips.length;
            showTip(currentTip);
        });
        
        dots.forEach((dot, i) => {
            dot.addEventListener('click', () => {
                currentTip = i;
                showTip(currentTip);
            });
        });
        
        // Auto-advance tips
        setInterval(() => {
            currentTip = (currentTip + 1) % tips.length;
            showTip(currentTip);
        }, 5000);
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

    // Cancel scan
    cancelScan() {
        if (!this.isScanning) return;
        
        this.showNotification('Scan cancelled by user', 'warning');
        this.addScanLogEntry('Scan cancelled by user', 'warning');
        
        // Stop all timers and intervals
        this.stopScanTimer();
        this.stopRealTimeUpdates();
        
        // Reset state
        this.isScanning = false;
        this.hideStatus();
        this.updateScanButton('ready');
    }

    // Help system
    showHelp() {
        const helpContent = `
            <div class="modal-overlay active">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">Scanner Help & Documentation</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        <h4>Getting Started</h4>
                        <p>The SANA Network Scanner is a powerful tool for discovering and analyzing network infrastructure. Here's how to use it effectively:</p>
                        
                        <h5>Target Selection</h5>
                        <ul>
                            <li><strong>Single IP:</strong> 192.168.1.1</li>
                            <li><strong>IP Range:</strong> 192.168.1.1-254</li>
                            <li><strong>CIDR Notation:</strong> 192.168.1.0/24</li>
                            <li><strong>Hostname:</strong> example.com</li>
                        </ul>
                        
                        <h5>Scan Profiles</h5>
                        <ul>
                            <li><strong>Stealth:</strong> Slow, low-detection scanning</li>
                            <li><strong>Balanced:</strong> Good speed/stealth balance</li>
                            <li><strong>Aggressive:</strong> Fast scanning, more detectable</li>
                            <li><strong>Deep Analysis:</strong> Comprehensive service/OS detection</li>
                        </ul>
                        
                        <h5>Legal Notice</h5>
                        <p><strong>Important:</strong> Only scan networks you own or have explicit permission to test. Unauthorized network scanning may violate laws and regulations.</p>
                        
                        <h5>Tips for Best Results</h5>
                        <ul>
                            <li>Start with a stealth scan on external targets</li>
                            <li>Use aggressive timing only on internal networks</li>
                            <li>Specify port ranges to focus on services of interest</li>
                            <li>Enable service detection for better insights</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', helpContent);
        
        // Close modal handlers
        document.querySelector('.modal-close').addEventListener('click', this.closeModal);
        document.querySelector('.modal-overlay').addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-overlay')) {
                this.closeModal();
            }
        });
    }

    closeModal() {
        const modal = document.querySelector('.modal-overlay');
        if (modal) {
            modal.classList.remove('active');
            setTimeout(() => {
                modal.remove();
            }, 300);
        }
    }

    // Data persistence
    saveScanToHistory(data) {
        const scanData = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            target: data.target || this.collectFormData().target,
            scanType: this.currentProfile,
            hostCount: data.hostCount || 0,
            portCount: data.portCount || 0,
            command: data.command,
            duration: this.scanStartTime ? Date.now() - this.scanStartTime : 0
        };
        
        this.scanHistory.unshift(scanData);
        
        // Keep only last 50 scans
        if (this.scanHistory.length > 50) {
            this.scanHistory = this.scanHistory.slice(0, 50);
        }
        
        this.saveToStorage();
    }

    loadScanHistory() {
        try {
            const saved = localStorage.getItem('sana_scan_history');
            if (saved) {
                this.scanHistory = JSON.parse(saved);
            }
        } catch (e) {
            console.warn('Failed to load scan history:', e);
        }
    }

    saveToStorage() {
        try {
            localStorage.setItem('sana_scan_history', JSON.stringify(this.scanHistory));
        } catch (e) {
            console.warn('Failed to save scan history:', e);
        }
    }

    loadUserPreferences() {
        try {
            const prefs = localStorage.getItem('sana_scanner_prefs');
            if (prefs) {
                const preferences = JSON.parse(prefs);
                
                // Apply saved preferences
                if (preferences.defaultProfile) {
                    this.currentProfile = preferences.defaultProfile;
                    document.querySelectorAll('.profile-option').forEach(opt => {
                        opt.classList.toggle('active', opt.dataset.profile === preferences.defaultProfile);
                    });
                }
                
                if (preferences.defaultTiming) {
                    document.getElementById('timing-template').value = preferences.defaultTiming;
                    const sliderValue = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'].indexOf(preferences.defaultTiming);
                    document.getElementById('timing-slider').value = sliderValue;
                }
            }
        } catch (e) {
            console.warn('Failed to load user preferences:', e);
        }
    }

    saveUserPreferences() {
        try {
            const preferences = {
                defaultProfile: this.currentProfile,
                defaultTiming: document.getElementById('timing-template').value,
                lastTarget: document.getElementById('target').value
            };
            
            localStorage.setItem('sana_scanner_prefs', JSON.stringify(preferences));
        } catch (e) {
            console.warn('Failed to save user preferences:', e);
        }
    }

    // Stats animation
    startStatsAnimation() {
        const statValues = document.querySelectorAll('.stat-value');
        
        statValues.forEach(stat => {
            const finalValue = parseInt(stat.textContent);
            let currentValue = 0;
            const increment = finalValue / 100;
            
            const timer = setInterval(() => {
                currentValue += increment;
                if (currentValue >= finalValue) {
                    currentValue = finalValue;
                    clearInterval(timer);
                }
                stat.textContent = Math.floor(currentValue).toLocaleString();
            }, 20);
        });
    }

    // Initialize tooltips
    initializeTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.classList.add('enhanced-tooltip');
        });
    }

    // Accessibility features
    initializeAccessibility() {
        // Add keyboard navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isScanning) {
                this.cancelScan();
            }
        });
        
        // Focus management
        document.querySelectorAll('.btn, .form-control, .profile-option').forEach(element => {
            element.addEventListener('focus', () => {
                element.classList.add('focus-visible');
            });
            
            element.addEventListener('blur', () => {
                element.classList.remove('focus-visible');
            });
        });
    }

    // Performance monitoring
    initializePerformanceMonitoring() {
        // Monitor memory usage
        if ('memory' in performance) {
            setInterval(() => {
                const memory = performance.memory;
                if (memory.usedJSHeapSize > 50 * 1024 * 1024) { // 50MB
                    console.warn('High memory usage detected');
                }
            }, 30000);
        }
        
        // Monitor render performance
        let lastFrameTime = performance.now();
        const monitorFrame = (currentTime) => {
            const frameDuration = currentTime - lastFrameTime;
            if (frameDuration > 16.67) { // > 60fps
                console.warn('Frame rate drop detected');
            }
            lastFrameTime = currentTime;
            requestAnimationFrame(monitorFrame);
        };
        
        requestAnimationFrame(monitorFrame);
    }

    // Error handling
    handleError(error, context = 'Unknown') {
        console.error(`Error in ${context}:`, error);
        
        this.showNotification(
            `An error occurred: ${error.message || 'Unknown error'}`,
            'error'
        );
        
        // Log error for debugging
        this.addScanLogEntry(`Error: ${error.message}`, 'error');
    }

    // Cleanup
    destroy() {
        // Stop all timers
        this.stopScanTimer();
        this.stopRealTimeUpdates();
        
        // Save preferences
        this.saveUserPreferences();
        
        // Remove event listeners
        // (In a real implementation, you'd track and remove all listeners)
        
        console.log('NetworkScannerEnhanced destroyed');
    }
}

// Global event handlers for dynamic content
window.networkScanner = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.networkScanner = new NetworkScannerEnhanced();
        console.log('Enhanced Network Scanner initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Enhanced Network Scanner:', error);
    }
});

// Global utility functions for dynamic content
window.selectSuggestion = function(suggestion) {
    if (window.networkScanner) {
        window.networkScanner.selectSuggestion(suggestion);
    }
};

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.hidden && window.networkScanner?.isScanning) {
        // Optionally pause updates when page is hidden
        window.networkScanner.stopRealTimeUpdates();
    } else if (!document.hidden && window.networkScanner?.isScanning) {
        // Resume updates when page becomes visible
        window.networkScanner.simulateRealTimeUpdates();
    }
});

// Handle beforeunload for cleanup
window.addEventListener('beforeunload', () => {
    if (window.networkScanner) {
        window.networkScanner.destroy();
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NetworkScannerEnhanced;
}