/**
 * Enhanced DNS Reconnaissance JavaScript
 * Advanced DNS analysis functionality with comprehensive domain intelligence gathering
 */

class DNSReconnaissanceManager {
    constructor() {
        // DOM Elements - Following exact pattern from other modules
        this.dnsForm = document.getElementById('dns-form');
        this.dnsBtn = document.getElementById('dns-btn');
        this.cancelBtn = document.getElementById('cancel-dns');
        this.statusPanel = document.getElementById('dns-status-panel');
        this.resultsSection = document.getElementById('dns-results-section');
        this.domainInput = document.getElementById('domain');
        
        // DNS state management
        this.isAnalyzing = false;
        this.currentSessionId = null;
        this.analysisStartTime = null;
        this.analysisTimer = null;
        this.realTimeInterval = null;
        this.progressUpdateInterval = null;
        this.lastStatusUpdate = null;
        
        // Real-time statistics
        this.realTimeStats = {
            recordsFound: 0,
            subdomainsFound: 0,
            securityFeatures: 0,
            currentPhase: 'Ready',
            responseTime: 0,
            queriesPerformed: 0
        };
        
        // DNS configuration
        this.dnsConfig = {
            lookupType: 'comprehensive',
            recordTypes: ['A', 'AAAA', 'MX', 'NS', 'TXT'],
            includeSubdomains: false,
            includeZoneTransfer: false,
            includeWhois: false,
            includeSecurity: false
        };
        
        // Current results storage
        this.lastResults = null;
        this.activeNotifications = [];
        this.progressAnimationFrame = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeUI();
        this.setupDomainValidation();
        this.initializeTooltips();
        this.startStatsAnimation();
        this.setupEnhancedAnimations();
        this.initializeExampleCarousel();
        this.loadDNSStatistics();
        this.setupDNSVisualization();
        
        console.log('DNS Reconnaissance Manager initialized');
    }

    // ===== EVENT LISTENERS SETUP ===== //
    
    setupEventListeners() {
        // Form submission
        if (this.dnsForm) {
            this.dnsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.startDNSAnalysis();
            });
        }
        
        // DNS control buttons
        if (this.dnsBtn) {
            this.dnsBtn.addEventListener('click', (e) => {
                if (!this.isAnalyzing) {
                    e.preventDefault();
                    this.startDNSAnalysis();
                }
            });
        }
        
        if (this.cancelBtn) {
            this.cancelBtn.addEventListener('click', () => {
                this.cancelDNSAnalysis();
            });
        }
        
        // Quick action buttons
        document.getElementById('focus-dns-btn')?.addEventListener('click', () => {
            this.focusOnDomain();
        });
        
        document.getElementById('quick-reverse-btn')?.addEventListener('click', () => {
            this.showReverseDNSDialog();
        });
        
        document.getElementById('new-dns-analysis')?.addEventListener('click', () => {
            this.resetForm();
        });
        
        // Lookup type change
        document.getElementById('lookup-type')?.addEventListener('change', (e) => {
            this.updateLookupTypeConfig(e.target.value);
        });
        
        // Record type checkboxes
        document.querySelectorAll('input[name="recordTypes"]').forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.updateRecordTypesConfig();
            });
        });
        
        // Advanced options toggles
        document.querySelectorAll('input[name^="include"]').forEach(toggle => {
            toggle.addEventListener('change', () => {
                this.updateAdvancedOptionsConfig();
            });
        });
        
        // Export buttons
        document.getElementById('export-dns-json')?.addEventListener('click', () => {
            this.exportResults('json');
        });
        
        document.getElementById('export-dns-csv')?.addEventListener('click', () => {
            this.exportResults('csv');
        });
        
        // Window events
        window.addEventListener('beforeunload', (e) => {
            if (this.isAnalyzing) {
                e.preventDefault();
                e.returnValue = '';
            }
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'Enter':
                        if (!this.isAnalyzing) {
                            e.preventDefault();
                            this.startDNSAnalysis();
                        }
                        break;
                    case 'Escape':
                        if (this.isAnalyzing) {
                            e.preventDefault();
                            this.cancelDNSAnalysis();
                        }
                        break;
                }
            }
        });
    }

    // ===== UI INITIALIZATION ===== //
    
    initializeUI() {
        // Initialize form state
        this.updateDNSButtonState('ready');
        this.updateDomainValidationStatus('pending');
        
        // Setup form animations
        this.setupFormAnimations();
        
        // Initialize progress tracking
        this.initializeProgressTracking();
        
        // Setup notification system
        this.initializeNotificationSystem();
        
        console.log('DNS UI initialized');
    }

    setupFormAnimations() {
        // Staggered animation for form sections
        document.querySelectorAll('.form-section').forEach((section, index) => {
            section.style.animationDelay = `${index * 0.1}s`;
            section.classList.add('animate-fade-up');
        });
        
        // Enhanced hover effects for record type cards
        document.querySelectorAll('.record-type-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.classList.add('gpu-accelerated');
                card.style.transform = 'translateY(-3px) translateZ(0)';
            });
            
            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0) translateZ(0)';
            });
        });
        
        // Enhanced hover effects for option toggles
        document.querySelectorAll('.option-toggle').forEach(toggle => {
            toggle.addEventListener('mouseenter', () => {
                toggle.classList.add('gpu-accelerated');
                toggle.style.transform = 'translateY(-2px) translateZ(0)';
            });
            
            toggle.addEventListener('mouseleave', () => {
                toggle.style.transform = 'translateY(0) translateZ(0)';
            });
        });
    }

    setupEnhancedAnimations() {
        // Add staggered animation to cards
        document.querySelectorAll('.record-type-card, .option-toggle').forEach((card, index) => {
            card.style.animationDelay = `${index * 0.05}s`;
            card.classList.add('animate-fade-up');
        });
        
        // Setup advanced button effects
        this.setupEnhancedButtons();
    }

    setupEnhancedButtons() {
        // Enhanced button animations
        document.querySelectorAll('.btn-dns-launch, .btn-hero-primary').forEach(btn => {
            btn.addEventListener('mouseenter', () => {
                btn.classList.add('gpu-accelerated');
                btn.style.transform = 'translateY(-2px) translateZ(0)';
            });
            
            btn.addEventListener('mouseleave', () => {
                btn.style.transform = 'translateY(0) translateZ(0)';
            });
        });
    }

    // ===== DOMAIN VALIDATION ===== //
    
    setupDomainValidation() {
        if (!this.domainInput) return;
        
        const validation = document.getElementById('domain-validation');
        const message = document.getElementById('domain-message');
        
        this.domainInput.addEventListener('input', () => {
            const domain = this.domainInput.value.trim();
            this.validateDomain(domain, validation, message);
        });
        
        this.domainInput.addEventListener('blur', () => {
            const domain = this.domainInput.value.trim();
            if (domain) {
                this.validateDomain(domain, validation, message);
            }
        });
    }

    validateDomain(domain, validation, message) {
        const validationStatus = document.getElementById('domain-validation-status');
        
        if (!domain) {
            this.updateValidationUI(validation, message, validationStatus, 'pending', 'Enter a domain name');
            return false;
        }
        
        // Remove protocol if present
        domain = domain.replace(/^https?:\/\//, '');
        
        // Remove path if present
        domain = domain.split('/')[0];
        
        // Domain regex pattern
        const domainPattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
        
        if (domainPattern.test(domain) && domain.length <= 253) {
            this.updateValidationUI(validation, message, validationStatus, 'success', 'Valid domain name');
            this.estimateAnalysisTime(domain);
            return true;
        } else {
            this.updateValidationUI(validation, message, validationStatus, 'error', 'Invalid domain format');
            return false;
        }
    }

    updateValidationUI(validation, message, status, type, text) {
        if (validation) {
            validation.className = `input-validation ${type}`;
            validation.style.display = type === 'pending' ? 'none' : 'flex';
            validation.innerHTML = type === 'success' ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>';
        }
        
        if (message) {
            message.className = `validation-message ${type}`;
            message.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${text}`;
            message.style.display = type === 'pending' ? 'none' : 'flex';
        }
        
        if (status) {
            status.textContent = type === 'success' ? 'Valid' : type === 'error' ? 'Invalid' : 'Pending';
            status.className = `status-${type}`;
        }
    }

    estimateAnalysisTime(domain) {
        const estimatedTimeElement = document.getElementById('estimated-time');
        if (!estimatedTimeElement) return;
        
        let baseTime = 30; // Base 30 seconds
        
        // Add time for additional options
        if (this.dnsConfig.includeSubdomains) baseTime += 15;
        if (this.dnsConfig.includeZoneTransfer) baseTime += 10;
        if (this.dnsConfig.includeWhois) baseTime += 10;
        if (this.dnsConfig.includeSecurity) baseTime += 5;
        
        estimatedTimeElement.textContent = `~${baseTime} seconds`;
    }

    // ===== CONFIGURATION UPDATES ===== //
    
    updateLookupTypeConfig(type) {
        this.dnsConfig.lookupType = type;
        
        // Update record types based on lookup type
        const recordCheckboxes = document.querySelectorAll('input[name="recordTypes"]');
        
        switch (type) {
            case 'basic':
                this.dnsConfig.recordTypes = ['A', 'AAAA', 'MX'];
                break;
            case 'comprehensive':
                this.dnsConfig.recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
                break;
            case 'security':
                this.dnsConfig.recordTypes = ['A', 'TXT', 'CAA'];
                this.dnsConfig.includeSecurity = true;
                break;
            case 'subdomain':
                this.dnsConfig.recordTypes = ['A', 'AAAA'];
                this.dnsConfig.includeSubdomains = true;
                break;
        }
        
        // Update checkboxes
        recordCheckboxes.forEach(checkbox => {
            checkbox.checked = this.dnsConfig.recordTypes.includes(checkbox.value);
        });
        
        // Update advanced options
        document.getElementById('include-security').checked = this.dnsConfig.includeSecurity;
        document.getElementById('include-subdomains').checked = this.dnsConfig.includeSubdomains;
        
        this.estimateAnalysisTime(this.domainInput?.value || '');
    }

    updateRecordTypesConfig() {
        const checkedTypes = Array.from(document.querySelectorAll('input[name="recordTypes"]:checked'))
            .map(cb => cb.value);
        this.dnsConfig.recordTypes = checkedTypes;
        this.estimateAnalysisTime(this.domainInput?.value || '');
    }

    updateAdvancedOptionsConfig() {
        this.dnsConfig.includeSubdomains = document.getElementById('include-subdomains')?.checked || false;
        this.dnsConfig.includeZoneTransfer = document.getElementById('include-zone-transfer')?.checked || false;
        this.dnsConfig.includeWhois = document.getElementById('include-whois')?.checked || false;
        this.dnsConfig.includeSecurity = document.getElementById('include-security')?.checked || false;
        
        this.estimateAnalysisTime(this.domainInput?.value || '');
    }

    // ===== DNS ANALYSIS CORE ===== //
    
    async startDNSAnalysis() {
        if (this.isAnalyzing) return;
        
        const domain = this.domainInput?.value.trim();
        if (!domain || !this.validateDomain(domain)) {
            this.showNotification('Please enter a valid domain name', 'error');
            return;
        }
        
        this.isAnalyzing = true;
        this.analysisStartTime = Date.now();
        this.currentSessionId = `dns_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        // Update UI state
        this.updateDNSButtonState('analyzing');
        this.showStatusPanel();
        this.hideResultsSection();
        this.startRealTimeTracking();
        this.addDNSLogEntry('Starting DNS analysis...', 'info');
        
        // Prepare analysis data
        const analysisData = {
            domain: domain.replace(/^https?:\/\//, '').split('/')[0],
            recordTypes: this.dnsConfig.recordTypes,
            includeSubdomains: this.dnsConfig.includeSubdomains,
            includeZoneTransfer: this.dnsConfig.includeZoneTransfer,
            includeWhois: this.dnsConfig.includeWhois,
            includeSecurity: this.dnsConfig.includeSecurity
        };
        
        try {
            // Start DNS analysis
            this.addDNSLogEntry(`Analyzing domain: ${analysisData.domain}`, 'info');
            this.updateCurrentPhase('Initializing DNS Resolution');
            
            const response = await fetch('/dns-lookup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(analysisData)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            if (result.status === 'success') {
                this.addDNSLogEntry('DNS analysis completed successfully', 'success');
                this.handleAnalysisComplete(result);
            } else {
                throw new Error(result.message || 'DNS analysis failed');
            }
            
        } catch (error) {
            console.error('DNS Analysis Error:', error);
            this.addDNSLogEntry(`Analysis failed: ${error.message}`, 'error');
            this.handleAnalysisError(error);
        }
    }

    async cancelDNSAnalysis() {
        if (!this.isAnalyzing) return;
        
        this.isAnalyzing = false;
        this.stopRealTimeTracking();
        
        this.addDNSLogEntry('Analysis cancelled by user', 'warning');
        this.updateDNSButtonState('ready');
        this.hideStatusPanel();
        
        this.showNotification('DNS analysis cancelled', 'warning');
    }

    handleAnalysisComplete(result) {
        this.isAnalyzing = false;
        this.lastResults = result.results;
        
        // Stop real-time tracking
        this.stopRealTimeTracking();
        
        // Update UI
        this.updateDNSButtonState('complete');
        this.hideStatusPanel();
        this.displayResults(result.results);
        
        // Calculate analysis duration
        const duration = ((Date.now() - this.analysisStartTime) / 1000).toFixed(1);
        this.addDNSLogEntry(`Analysis completed in ${duration} seconds`, 'success');
        
        // Show completion notification
        this.showNotification(
            `DNS analysis completed! Found ${result.results.statistics?.total_records || 0} records`,
            'success'
        );
    }

    handleAnalysisError(error) {
        this.isAnalyzing = false;
        this.stopRealTimeTracking();
        
        this.updateDNSButtonState('ready');
        this.hideStatusPanel();
        
        this.showNotification(`Analysis failed: ${error.message}`, 'error');
    }

    // ===== REAL-TIME TRACKING ===== //
    
    startRealTimeTracking() {
        this.updateProgress(0);
        
        // Simulate real-time progress updates
        let progress = 0;
        const phases = [
            'Initializing DNS Resolution',
            'Querying DNS Records',
            'Performing Subdomain Enumeration',
            'Testing Zone Transfers',
            'Gathering WHOIS Information',
            'Analyzing Security Features',
            'Finalizing Results'
        ];
        
        let currentPhaseIndex = 0;
        let recordCount = 0;
        let subdomainCount = 0;
        
        this.realTimeInterval = setInterval(() => {
            if (!this.isAnalyzing) {
                clearInterval(this.realTimeInterval);
                return;
            }
            
            // Update progress
            progress += Math.random() * 5;
            progress = Math.min(progress, 95);
            
            // Update phase
            const newPhaseIndex = Math.floor((progress / 100) * phases.length);
            if (newPhaseIndex !== currentPhaseIndex && newPhaseIndex < phases.length) {
                currentPhaseIndex = newPhaseIndex;
                this.updateCurrentPhase(phases[currentPhaseIndex]);
                this.addDNSLogEntry(`Phase: ${phases[currentPhaseIndex]}`, 'info');
            }
            
            // Simulate findings
            if (Math.random() > 0.7) {
                recordCount += Math.floor(Math.random() * 3) + 1;
                this.updateLiveStats('records', recordCount);
            }
            
            if (this.dnsConfig.includeSubdomains && Math.random() > 0.8) {
                subdomainCount += Math.floor(Math.random() * 2) + 1;
                this.updateLiveStats('subdomains', subdomainCount);
            }
            
            // Update response time
            const responseTime = 50 + Math.random() * 200;
            this.updateLiveStats('response-time', Math.round(responseTime));
            
            this.updateProgress(progress);
            
        }, 500 + Math.random() * 300);
    }

    stopRealTimeTracking() {
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
            this.realTimeInterval = null;
        }
        
        if (this.progressAnimationFrame) {
            cancelAnimationFrame(this.progressAnimationFrame);
            this.progressAnimationFrame = null;
        }
    }

    updateProgress(percentage) {
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.querySelector('.progress-text');
        const liveProgress = document.getElementById('live-dns-progress');
        
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
            progressFill.classList.add('gpu-accelerated');
        }
        
        if (progressText) {
            progressText.textContent = `${Math.round(percentage)}%`;
        }
        
        if (liveProgress) {
            const currentValue = parseInt(liveProgress.textContent) || 0;
            if (Math.abs(percentage - currentValue) >= 1) {
                this.animateValue(liveProgress, currentValue, Math.round(percentage), 300);
            }
        }
    }

    updateCurrentPhase(phase) {
        const phaseElement = document.getElementById('current-dns-phase');
        const statusElement = document.getElementById('dns-status');
        
        if (phaseElement) {
            phaseElement.style.opacity = '0';
            phaseElement.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                phaseElement.textContent = phase;
                phaseElement.style.opacity = '1';
                phaseElement.style.transform = 'translateY(0)';
            }, 150);
        }
        
        if (statusElement) {
            statusElement.textContent = 'Analyzing';
        }
        
        this.realTimeStats.currentPhase = phase;
    }

    updateLiveStats(type, value) {
        const elements = {
            'records': document.getElementById('live-records'),
            'subdomains': document.getElementById('live-subdomains'),
            'response-time': document.getElementById('live-response-time')
        };
        
        const element = elements[type];
        if (element) {
            const currentValue = parseInt(element.textContent) || 0;
            
            if (type === 'response-time') {
                element.textContent = `${value}ms`;
            } else {
                this.animateValue(element, currentValue, value, 300);
            }
        }
        
        // Update hero stats
        this.updateHeroStatValue(type, value);
    }

    // ===== RESULTS DISPLAY ===== //
    
    displayResults(results) {
        if (!results) return;
        
        // Show results section
        this.showResultsSection();
        
        // Update overview stats
        this.updateDNSOverview(results);
        
        // Display DNS records
        this.displayDNSRecords(results.dns_records);
        
        // Display subdomains if available
        if (results.subdomains && results.subdomains.length > 0) {
            this.displaySubdomains(results.subdomains);
        }
        
        // Display security analysis if available
        if (results.security_analysis && Object.keys(results.security_analysis).length > 0) {
            this.displaySecurityAnalysis(results.security_analysis);
        }
        
        // Display WHOIS information if available
        if (results.whois_info && results.whois_info.success) {
            this.displayWhoisInfo(results.whois_info.whois_data);
        }
        
        // Enable export buttons
        this.enableExportButtons();
        
        console.log('DNS results displayed successfully');
    }

    updateDNSOverview(results) {
        const stats = results.statistics || {};
        
        // Update overview cards
        document.getElementById('total-records-found').textContent = stats.total_records || 0;
        document.getElementById('total-subdomains-found').textContent = stats.subdomains_found || 0;
        
        // Calculate security score
        const securityScore = this.calculateSecurityScore(results.security_analysis);
        document.getElementById('security-score').textContent = securityScore;
        
        // Analysis duration
        const duration = ((Date.now() - this.analysisStartTime) / 1000).toFixed(1);
        document.getElementById('analysis-duration').textContent = `${duration}s`;
    }

    displayDNSRecords(dnsRecords) {
        const container = document.getElementById('records-container');
        if (!container || !dnsRecords) return;
        
        container.innerHTML = '';
        
        Object.entries(dnsRecords).forEach(([recordType, recordData]) => {
            if (recordData.success && recordData.records.length > 0) {
                const recordGroup = this.createRecordGroup(recordType, recordData.records);
                container.appendChild(recordGroup);
            }
        });
        
        // Show the records section
        document.getElementById('dns-records-section').style.display = 'block';
    }

    createRecordGroup(recordType, records) {
        const group = document.createElement('div');
        group.className = 'record-group';
        
        group.innerHTML = `
            <div class="record-type-header">
                <h5 class="record-type-title">${recordType} Records</h5>
                <span class="record-count">${records.length}</span>
            </div>
            <div class="record-list">
                ${records.map(record => `
                    <div class="record-item">
                        <span class="record-value">${record.value}</span>
                        <span class="record-ttl">TTL: ${record.ttl || 'N/A'}</span>
                    </div>
                `).join('')}
            </div>
        `;
        
        return group;
    }

    displaySubdomains(subdomains) {
        const container = document.getElementById('subdomains-container');
        const section = document.getElementById('subdomains-section');
        
        if (!container || !section || !subdomains.length) return;
        
        container.innerHTML = '';
        
        subdomains.forEach(subdomain => {
            const subdomainElement = this.createSubdomainElement(subdomain);
            container.appendChild(subdomainElement);
        });
        
        section.style.display = 'block';
    }

    createSubdomainElement(subdomain) {
        const element = document.createElement('div');
        element.className = 'subdomain-item';
        
        element.innerHTML = `
            <h6 class="subdomain-name">${subdomain.subdomain}</h6>
            <div class="subdomain-ips">
                ${subdomain.ip_addresses.map(ip => `
                    <span class="ip-badge">${ip}</span>
                `).join('')}
            </div>
        `;
        
        return element;
    }

    displaySecurityAnalysis(securityAnalysis) {
        const container = document.getElementById('security-features');
        const section = document.getElementById('security-section');
        
        if (!container || !section) return;
        
        container.innerHTML = '';
        
        const features = [
            { key: 'dnssec', name: 'DNSSEC', icon: 'shield-alt' },
            { key: 'spf', name: 'SPF Record', icon: 'envelope' },
            { key: 'dmarc', name: 'DMARC', icon: 'lock' },
            { key: 'caa', name: 'CAA Record', icon: 'certificate' }
        ];
        
        features.forEach(feature => {
            const isEnabled = securityAnalysis[feature.key] || false;
            const featureElement = this.createSecurityFeatureElement(feature, isEnabled);
            container.appendChild(featureElement);
        });
        
        section.style.display = 'block';
    }

    createSecurityFeatureElement(feature, enabled) {
        const element = document.createElement('div');
        element.className = `security-feature ${enabled ? 'enabled' : 'disabled'}`;
        
        element.innerHTML = `
            <div class="security-icon">
                <i class="fas fa-${feature.icon}"></i>
            </div>
            <h6 class="security-name">${feature.name}</h6>
            <p class="security-status">${enabled ? 'Enabled' : 'Disabled'}</p>
        `;
        
        return element;
    }

    displayWhoisInfo(whoisData) {
        const container = document.getElementById('whois-container');
        const section = document.getElementById('whois-section');
        
        if (!container || !section || !whoisData) return;
        
        const whoisGrid = document.createElement('div');
        whoisGrid.className = 'whois-grid';
        
        const groups = {
            'Registration': ['registrar', 'creation_date', 'expiration_date'],
            'Contact': ['admin_email', 'tech_email'],
            'Technical': ['name_servers', 'status']
        };
        
        Object.entries(groups).forEach(([groupName, fields]) => {
            const groupElement = this.createWhoisGroup(groupName, fields, whoisData);
            if (groupElement) {
                whoisGrid.appendChild(groupElement);
            }
        });
        
        container.innerHTML = '';
        container.appendChild(whoisGrid);
        section.style.display = 'block';
    }

    createWhoisGroup(groupName, fields, whoisData) {
        const validFields = fields.filter(field => whoisData[field]);
        if (validFields.length === 0) return null;
        
        const group = document.createElement('div');
        group.className = 'whois-group';
        
        group.innerHTML = `
            <h5>${groupName}</h5>
            ${validFields.map(field => `
                <div class="whois-item">
                    <span class="whois-label">${this.formatFieldName(field)}:</span>
                    <span class="whois-value">${this.formatWhoisValue(whoisData[field])}</span>
                </div>
            `).join('')}
        `;
        
        return group;
    }

    // ===== UTILITY METHODS ===== //
    
    calculateSecurityScore(securityAnalysis) {
        if (!securityAnalysis) return '--';
        
        const features = ['dnssec', 'spf', 'dmarc', 'caa'];
        const enabledCount = features.filter(feature => securityAnalysis[feature]).length;
        const score = Math.round((enabledCount / features.length) * 100);
        
        return `${score}%`;
    }

    formatFieldName(field) {
        return field.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatWhoisValue(value) {
        if (Array.isArray(value)) {
            return value.join(', ');
        }
        if (typeof value === 'string' && value.length > 50) {
            return value.substring(0, 50) + '...';
        }
        return value || 'N/A';
    }
 
    // ===== UI STATE MANAGEMENT ===== //
 
    updateDNSButtonState(state) {
        const btn = this.dnsBtn;
        if (!btn) return;
 
        const icon = btn.querySelector('.launch-icon');
        const text = btn.querySelector('.btn-text');
 
        btn.classList.remove('analyzing', 'complete', 'error');
 
        switch (state) {
            case 'analyzing':
                btn.classList.add('analyzing');
                btn.disabled = true;
                if (icon) icon.className = 'fas fa-spinner launch-icon';
                if (text) text.textContent = 'Analyzing...';
                this.startButtonLoadingAnimation(btn);
                break;
 
            case 'complete':
                btn.classList.add('complete');
                btn.disabled = true;
                if (icon) icon.className = 'fas fa-check launch-icon';
                if (text) text.textContent = 'Analysis Complete';
                this.playSuccessAnimation(btn);
                break;
 
            case 'ready':
            default:
                btn.disabled = false;
                btn.classList.remove('gpu-accelerated');
                if (icon) icon.className = 'fas fa-globe launch-icon';
                if (text) text.textContent = 'Start DNS Analysis';
                this.stopButtonLoadingAnimation(btn);
                break;
        }
    }
 
    startButtonLoadingAnimation(button) {
        if (!button.querySelector('.loading-spinner')) {
            const spinner = document.createElement('div');
            spinner.className = 'loading-spinner';
            button.appendChild(spinner);
        }
    }
 
    stopButtonLoadingAnimation(button) {
        const spinner = button.querySelector('.loading-spinner');
        if (spinner) spinner.remove();
    }
 
    playSuccessAnimation(button) {
        button.style.transform = 'scale(1.05)';
        setTimeout(() => {
            button.style.transform = 'scale(1)';
        }, 300);
 
        // Success particles effect
        this.createSuccessParticles(button);
    }
 
    createSuccessParticles(element) {
        const rect = element.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
 
        for (let i = 0; i < 6; i++) {
            const particle = document.createElement('div');
            particle.className = 'success-particle';
            particle.style.cssText = `
                position: fixed;
                left: ${centerX}px;
                top: ${centerY}px;
                width: 4px;
                height: 4px;
                background: var(--dns-success);
                border-radius: 50%;
                pointer-events: none;
                z-index: 9999;
            `;
 
            document.body.appendChild(particle);
 
            const angle = (i / 6) * Math.PI * 2;
            const distance = 50 + Math.random() * 30;
            const endX = centerX + Math.cos(angle) * distance;
            const endY = centerY + Math.sin(angle) * distance;
 
            particle.animate([
                { transform: 'translate(0, 0) scale(1)', opacity: 1 },
                { transform: `translate(${endX - centerX}px, ${endY - centerY}px) scale(0)`, opacity: 0 }
            ], {
                duration: 800,
                easing: 'cubic-bezier(0.25, 0.46, 0.45, 0.94)'
            }).onfinish = () => particle.remove();
        }
    }
 
    showStatusPanel() {
        if (this.statusPanel) {
            this.statusPanel.style.display = 'block';
            this.statusPanel.classList.add('animate-fade-up');
        }
    }
 
    hideStatusPanel() {
        if (this.statusPanel) {
            this.statusPanel.style.display = 'none';
            this.statusPanel.classList.remove('animate-fade-up');
        }
    }
 
    showResultsSection() {
        if (this.resultsSection) {
            this.resultsSection.style.display = 'block';
            this.resultsSection.classList.add('active', 'animate-fade-up');
        }
    }
 
    hideResultsSection() {
        if (this.resultsSection) {
            this.resultsSection.style.display = 'none';
            this.resultsSection.classList.remove('active', 'animate-fade-up');
        }
    }
 
    updateDomainValidationStatus(status) {
        const statusElement = document.getElementById('domain-validation-status');
        if (statusElement) {
            statusElement.textContent = status === 'success' ? 'Valid' : 
                                      status === 'error' ? 'Invalid' : 'Pending';
            statusElement.className = `status-${status}`;
        }
    }
 
    // ===== EXPORT FUNCTIONALITY ===== //
 
    enableExportButtons() {
        document.getElementById('export-dns-json')?.removeAttribute('disabled');
        document.getElementById('export-dns-csv')?.removeAttribute('disabled');
    }
 
    exportResults(format) {
        if (!this.lastResults) {
            this.showNotification('No results to export', 'warning');
            return;
        }
 
        try {
            let content, filename, mimeType;
 
            if (format === 'json') {
                content = JSON.stringify(this.lastResults, null, 2);
                filename = `dns-analysis-${this.lastResults.domain}-${new Date().toISOString().split('T')[0]}.json`;
                mimeType = 'application/json';
            } else if (format === 'csv') {
                content = this.convertToCSV(this.lastResults);
                filename = `dns-analysis-${this.lastResults.domain}-${new Date().toISOString().split('T')[0]}.csv`;
                mimeType = 'text/csv';
            }
 
            this.downloadFile(content, filename, mimeType);
            this.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
 
        } catch (error) {
            console.error('Export error:', error);
            this.showNotification('Export failed', 'error');
        }
    }
 
    convertToCSV(results) {
        const lines = [];
        lines.push('Domain,Record Type,Value,TTL');
 
        // Export DNS records
        if (results.dns_records) {
            Object.entries(results.dns_records).forEach(([type, data]) => {
                if (data.success && data.records) {
                    data.records.forEach(record => {
                        lines.push(`${results.domain},${type},"${record.value}",${record.ttl || 'N/A'}`);
                    });
                }
            });
        }
 
        // Export subdomains
        if (results.subdomains) {
            results.subdomains.forEach(subdomain => {
                subdomain.ip_addresses.forEach(ip => {
                    lines.push(`${subdomain.subdomain},A,"${ip}",N/A`);
                });
            });
        }
 
        return lines.join('\n');
    }
 
    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        
        link.href = url;
        link.download = filename;
        link.style.display = 'none';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        URL.revokeObjectURL(url);
    }
 
    // ===== STATS AND ANIMATIONS ===== //
 
    startStatsAnimation() {
        this.animateHeroStats();
        this.startDNSVisualization();
    }
 
    animateHeroStats() {
        const statElements = document.querySelectorAll('.stat-value');
        
        statElements.forEach((element, index) => {
            const finalValue = parseInt(element.textContent) || 0;
            element.textContent = '0';
            
            setTimeout(() => {
                this.animateValue(element, 0, finalValue, 2000);
            }, index * 200);
        });
    }
 
    animateValue(element, start, end, duration) {
        const startTime = performance.now();
        const change = end - start;
 
        const updateValue = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const easeOutCubic = 1 - Math.pow(1 - progress, 3);
            const currentValue = Math.round(start + change * easeOutCubic);
            
            element.textContent = currentValue;
 
            if (progress < 1) {
                requestAnimationFrame(updateValue);
            }
        };
 
        requestAnimationFrame(updateValue);
    }
 
    updateHeroStatValue(type, value) {
        const elements = {
            'records': document.getElementById('total-dns-lookups'),
            'subdomains': document.getElementById('subdomains-found'),
            'response-time': document.getElementById('domains-analyzed')
        };
 
        const element = elements[type];
        if (element) {
            const currentValue = parseInt(element.textContent) || 0;
            this.animateValue(element, currentValue, value, 500);
        }
    }
 
    // ===== DNS VISUALIZATION ===== //
 
    setupDNSVisualization() {
        this.startDNSVisualization();
        this.initializeQueryFlow();
    }
 
    startDNSVisualization() {
        const nodes = document.querySelectorAll('.dns-node');
        
        nodes.forEach((node, index) => {
            setTimeout(() => {
                node.style.opacity = '1';
                node.style.transform = 'scale(1)';
            }, index * 300);
        });
        
        // Start query flow animation
        setTimeout(() => {
            this.animateQueryFlow();
        }, 1000);
    }
 
    initializeQueryFlow() {
        const queryPath = document.getElementById('query-path');
        if (queryPath) {
            queryPath.style.opacity = '0.6';
        }
    }
 
    animateQueryFlow() {
        const queryFlow = document.getElementById('query-flow');
        if (queryFlow) {
            queryFlow.style.opacity = '1';
            queryFlow.style.animation = 'dns-flow 2s ease-in-out infinite';
        }
    }
 
    // ===== EXAMPLES CAROUSEL ===== //
 
    initializeExampleCarousel() {
        let currentExample = 0;
        const examples = document.querySelectorAll('.example-slide');
        const dots = document.querySelectorAll('.dot');
        
        if (examples.length === 0) return;
 
        const showExample = (index) => {
            examples.forEach((example, i) => {
                example.classList.remove('active', 'prev');
                if (i === index) {
                    example.classList.add('active');
                } else if (i < index) {
                    example.classList.add('prev');
                }
            });
 
            dots.forEach((dot, i) => {
                dot.classList.toggle('active', i === index);
            });
        };
 
        document.querySelector('.example-nav.next')?.addEventListener('click', () => {
            currentExample = (currentExample + 1) % examples.length;
            showExample(currentExample);
        });
 
        document.querySelector('.example-nav.prev')?.addEventListener('click', () => {
            currentExample = (currentExample - 1 + examples.length) % examples.length;
            showExample(currentExample);
        });
 
        dots.forEach((dot, i) => {
            dot.addEventListener('click', () => {
                currentExample = i;
                showExample(currentExample);
            });
        });
 
        // Auto-advance examples
        setInterval(() => {
            currentExample = (currentExample + 1) % examples.length;
            showExample(currentExample);
        }, 6000);
    }
 
    // ===== QUICK ACTIONS ===== //
 
    focusOnDomain() {
        if (this.domainInput) {
            this.domainInput.focus();
            this.domainInput.select();
        }
    }
 
    showReverseDNSDialog() {
        const ip = prompt('Enter IP address for reverse DNS lookup:');
        if (ip && this.validateIP(ip)) {
            this.performReverseDNSLookup(ip);
        } else if (ip) {
            this.showNotification('Invalid IP address format', 'error');
        }
    }
 
    validateIP(ip) {
        const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipPattern.test(ip);
    }
 
    async performReverseDNSLookup(ip) {
        try {
            this.showNotification('Performing reverse DNS lookup...', 'info');
 
            const response = await fetch('/reverse-dns', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ ip: ip })
            });
 
            const result = await response.json();
 
            if (result.status === 'success' && result.result.success) {
                this.showNotification(
                    `Reverse DNS: ${ip} → ${result.result.hostname}`,
                    'success',
                    8000
                );
            } else {
                this.showNotification(
                    `No reverse DNS record found for ${ip}`,
                    'warning'
                );
            }
 
        } catch (error) {
            console.error('Reverse DNS Error:', error);
            this.showNotification('Reverse DNS lookup failed', 'error');
        }
    }
 
    resetForm() {
        if (this.dnsForm) {
            this.dnsForm.reset();
        }
 
        // Reset configuration
        this.dnsConfig = {
            lookupType: 'comprehensive',
            recordTypes: ['A', 'AAAA', 'MX', 'NS', 'TXT'],
            includeSubdomains: false,
            includeZoneTransfer: false,
            includeWhois: false,
            includeSecurity: false
        };
 
        // Reset UI state
        this.updateDNSButtonState('ready');
        this.updateDomainValidationStatus('pending');
        this.hideStatusPanel();
        this.hideResultsSection();
 
        // Clear results
        this.lastResults = null;
 
        // Focus on domain input
        this.focusOnDomain();
 
        this.showNotification('Form reset', 'info');
    }
 
    // ===== TOOLTIPS SYSTEM ===== //
 
    initializeTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.addEventListener('mouseenter', (e) => {
                this.showTooltip(e.target, e.target.getAttribute('data-tooltip'));
            });
 
            element.addEventListener('mouseleave', () => {
                this.hideTooltip();
            });
        });
    }
 
    showTooltip(element, text) {
        const tooltip = document.createElement('div');
        tooltip.className = 'dns-tooltip';
        tooltip.textContent = text;
        
        document.body.appendChild(tooltip);
 
        const rect = element.getBoundingClientRect();
        tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
        tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
 
        setTimeout(() => tooltip.classList.add('visible'), 10);
    }
 
    hideTooltip() {
        const tooltip = document.querySelector('.dns-tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }
 
    // ===== NOTIFICATION SYSTEM ===== //
 
    initializeNotificationSystem() {
        // Create notification container if it doesn't exist
        if (!document.getElementById('dns-notifications')) {
            const container = document.createElement('div');
            container.id = 'dns-notifications';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
    }
 
    showNotification(message, type = 'info', duration = 4000) {
        const container = document.getElementById('dns-notifications');
        if (!container) return;
 
        const notification = document.createElement('div');
        notification.className = `dns-notification ${type}`;
 
        const iconMap = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
 
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas fa-${iconMap[type]}"></i>
            </div>
            <div class="notification-content">
                <p>${message}</p>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;
 
        // Add click to close
        notification.querySelector('.notification-close').addEventListener('click', () => {
            this.removeNotification(notification);
        });
 
        container.appendChild(notification);
 
        // Animate in
        setTimeout(() => notification.classList.add('show'), 10);
 
        // Auto remove
        if (duration > 0) {
            setTimeout(() => {
                this.removeNotification(notification);
            }, duration);
        }
 
        this.activeNotifications.push(notification);
    }
 
    removeNotification(notification) {
        notification.classList.add('hide');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
 
        const index = this.activeNotifications.indexOf(notification);
        if (index > -1) {
            this.activeNotifications.splice(index, 1);
        }
    }
 
    // ===== DNS LOG SYSTEM ===== //
 
    addDNSLogEntry(message, type = 'info') {
        const logContent = document.getElementById('dns-log-content');
        if (!logContent) return;
 
        const timestamp = new Date().toLocaleTimeString();
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        entry.style.opacity = '0';
        entry.style.transform = 'translateX(-20px)';
        entry.innerHTML = `
            <span class="timestamp">[${timestamp}]</span>
            <span class="message">${message}</span>
        `;
 
        logContent.appendChild(entry);
 
        // Animate in
        setTimeout(() => {
            entry.style.transition = 'all 0.3s ease';
            entry.style.opacity = '1';
            entry.style.transform = 'translateX(0)';
        }, 10);
 
        logContent.scrollTop = logContent.scrollHeight;
 
        // Remove old entries to prevent memory issues
        if (logContent.children.length > 50) {
            const firstChild = logContent.firstChild;
            if (firstChild) {
                firstChild.style.opacity = '0';
                setTimeout(() => firstChild.remove(), 300);
            }
        }
    }
 
    clearDNSLog() {
        const logContent = document.getElementById('dns-log-content');
        if (logContent) {
            logContent.innerHTML = '';
        }
    }
 
    // ===== STATISTICS LOADING ===== //
 
    async loadDNSStatistics() {
        try {
            const response = await fetch('/dns-stats');
            if (response.ok) {
                const stats = await response.json();
                if (stats.status === 'success') {
                    this.updateHeroStatsFromServer(stats.stats);
                }
            }
        } catch (error) {
            console.warn('Failed to load DNS statistics:', error);
        }
    }
 
    updateHeroStatsFromServer(stats) {
        if (stats.total_lookups) {
            document.getElementById('total-dns-lookups').textContent = stats.total_lookups;
        }
        if (stats.total_domains) {
            document.getElementById('domains-analyzed').textContent = stats.total_domains;
        }
        if (stats.total_subdomains) {
            document.getElementById('subdomains-found').textContent = stats.total_subdomains;
        }
    }
 
    // ===== PROGRESS TRACKING INITIALIZATION ===== //
 
    initializeProgressTracking() {
        // Initialize progress elements
        const progressElements = document.querySelectorAll('.progress-fill');
        progressElements.forEach(element => {
            element.style.width = '0%';
        });
 
        // Initialize progress info
        const progressInfo = document.getElementById('dns-progress-info');
        if (progressInfo) {
            progressInfo.style.display = 'none';
        }
    }
 
    // ===== CLEANUP ===== //
 
    destroy() {
        // Clean up intervals
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
        }
        
        if (this.analysisTimer) {
            clearInterval(this.analysisTimer);
        }
 
        if (this.progressAnimationFrame) {
            cancelAnimationFrame(this.progressAnimationFrame);
        }
 
        // Remove notifications
        this.activeNotifications.forEach(notification => {
            this.removeNotification(notification);
        });
 
        // Remove event listeners
        document.removeEventListener('keydown', this.keyboardHandler);
        window.removeEventListener('beforeunload', this.beforeUnloadHandler);
 
        console.log('DNS Reconnaissance Manager destroyed');
    }
 }
 
 // ===== INITIALIZATION ===== //
 
 // Initialize DNS Reconnaissance Manager when DOM is loaded
 document.addEventListener('DOMContentLoaded', () => {
    window.dnsRecon = new DNSReconnaissanceManager();
 });
 
 // Cleanup on page unload
 window.addEventListener('beforeunload', () => {
    if (window.dnsRecon) {
        window.dnsRecon.destroy();
    }
 });
 
 // Export for potential module usage
 if (typeof module !== 'undefined' && module.exports) {
    module.exports = DNSReconnaissanceManager;
 }