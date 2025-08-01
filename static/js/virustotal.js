/**
 * Enhanced VirusTotal Scanner JavaScript
 * Advanced threat analysis functionality with perfect animations and UX
 */

class VirusTotalScanner {
    constructor() {
        this.analysisForm = document.getElementById('analysis-form');
        this.analysisBtn = document.getElementById('analysis-btn');
        this.analysisStatus = document.getElementById('analysis-status-panel');
        this.resultsSection = document.getElementById('results-section');
        this.resourceInput = document.getElementById('resource');
        
        this.isAnalyzing = false;
        this.analysisStartTime = null;
        this.analysisTimer = null;
        this.lastResults = null;
        this.currentOption = 'auto';
        this.pollingScanId = null;
        this.realTimeInterval = null;
        this.progressAnimationFrame = null;
        this.visibilityChangeHandler = null;
        this.resizeHandler = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeUI();
        this.setupResourceValidation();
        this.initializeTooltips();
        this.startStatsAnimation();
        this.setupEnhancedAnimations();
        this.initializePerformanceOptimizations();
        this.setupIntersectionObserver();
    }

    // Enhanced animations setup
    setupEnhancedAnimations() {
        // Add staggered animation to cards
        document.querySelectorAll('.option-card').forEach((card, index) => {
            card.style.animationDelay = `${index * 0.1}s`;
            card.classList.add('animate-fade-up');
        });
        
        // Enhanced hover effects for interactive elements
        this.setupAdvancedHoverEffects();
        
        // Setup enhanced button effects
        this.setupEnhancedButtons();
    }

    // Advanced hover effects
    setupAdvancedHoverEffects() {
        document.querySelectorAll('.option-card').forEach(card => {
            card.addEventListener('mouseenter', (e) => {
                card.classList.add('gpu-accelerated');
                card.style.transform = 'translateY(-8px) scale(1.02) translateZ(0)';
            });
            
            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0) scale(1) translateZ(0)';
                setTimeout(() => card.classList.remove('gpu-accelerated'), 300);
            });
            
            // Enhanced click effect
            card.addEventListener('click', (e) => {
                this.createRippleEffect(e, card);
            });
        });

        // Enhanced button hover effects
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('mouseenter', () => {
                btn.classList.add('will-change-transform');
            });
            
            btn.addEventListener('mouseleave', () => {
                setTimeout(() => btn.classList.remove('will-change-transform'), 300);
            });
        });
    }

    // Enhanced button setup
    setupEnhancedButtons() {
        const launchBtn = this.analysisBtn;
        if (launchBtn) {
            launchBtn.addEventListener('mousedown', () => {
                launchBtn.style.transform = 'scale(0.98) translateY(-2px)';
            });
            
            launchBtn.addEventListener('mouseup', () => {
                launchBtn.style.transform = '';
            });
        }
    }

    // Ripple effect
    createRippleEffect(event, element) {
        const ripple = document.createElement('div');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: radial-gradient(circle, rgba(231,76,60,0.3) 0%, transparent 70%);
            border-radius: 50%;
            transform: scale(0);
            animation: rippleAnimation 0.6s ease-out;
            pointer-events: none;
            z-index: 1;
        `;
        
        element.style.position = 'relative';
        element.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    }

    setupEventListeners() {
        // Form submission
        this.analysisForm.addEventListener('submit', (e) => this.handleAnalysisSubmit(e));
        
        // Option selection (auto-selected, but keep for future expansion)
        document.querySelectorAll('.option-card').forEach(option => {
            option.addEventListener('click', (e) => this.selectOption(e));
        });
        
        // Quick action buttons
        document.getElementById('focus-analyzer-btn')?.addEventListener('click', () => this.focusOnAnalyzer());
        document.getElementById('quick-hash-btn')?.addEventListener('click', () => this.quickHashAnalysis());
        document.getElementById('new-analysis-btn')?.addEventListener('click', () => this.resetForm());
        
        // View switching
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchView(e));
        });
        
        // Export functions
        document.getElementById('export-json')?.addEventListener('click', () => this.exportJson());
        document.getElementById('export-csv')?.addEventListener('click', () => this.exportCsv());
        document.getElementById('copy-results')?.addEventListener('click', () => this.copyResults());
        document.getElementById('share-results')?.addEventListener('click', () => this.shareResults());
        document.getElementById('save-results-btn')?.addEventListener('click', () => this.saveResults());
        
        // Dropdown toggle
        document.querySelectorAll('.dropdown-toggle').forEach(toggle => {
            toggle.addEventListener('click', (e) => this.toggleDropdown(e));
        });
        
        // Cancel analysis
        document.getElementById('cancel-analysis')?.addEventListener('click', () => this.cancelAnalysis());
        
        // Clear log
        document.getElementById('clear-log')?.addEventListener('click', () => this.clearAnalysisLog());
        
        // Resource input with enhanced validation
        this.setupEnhancedInputValidation();
        
        // Examples carousel
        this.initExamplesCarousel();
        
        // Floating help
        document.getElementById('floating-help')?.addEventListener('click', () => this.showHelp());
        
        // Rescan button
        document.getElementById('rescan-btn')?.addEventListener('click', () => this.rescanResource());
        
        // Click outside dropdown to close
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.dropdown')) {
                document.querySelectorAll('.dropdown.open').forEach(dropdown => {
                    dropdown.classList.remove('open');
                });
            }
        });
    }

    // Enhanced input validation
    setupEnhancedInputValidation() {
        let validationTimeout;
        
        this.resourceInput.addEventListener('input', (e) => {
            clearTimeout(validationTimeout);
            this.resourceInput.classList.remove('error', 'success');
            
            validationTimeout = setTimeout(() => {
                this.handleResourceInputEnhanced(e);
            }, 300);
        });
        
        this.resourceInput.addEventListener('focus', () => {
            this.resourceInput.classList.add('will-change-transform');
            this.showResourceSuggestions();
        });
        
        this.resourceInput.addEventListener('blur', () => {
            this.resourceInput.classList.remove('will-change-transform');
            this.hideResourceSuggestions();
        });
        
        // Enhanced keyboard navigation
        this.resourceInput.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                this.handleSuggestionNavigation(e);
            } else if (e.key === 'Enter' && this.getActiveSuggestion()) {
                e.preventDefault();
                this.selectActiveSuggestion();
            }
        });
    }

    // Enhanced resource input handling - FIXED VERSION
    handleResourceInputEnhanced(e) {
        const value = e.target.value.trim();
        const validationStatus = document.getElementById('resource-validation');
        const validationMessage = document.getElementById('validation-message');
        
        // Clear previous validation states
        this.clearValidationMessages();
        
        if (!value) {
            this.updateValidationState('pending', 'Pending', validationMessage, validationStatus);
            this.updateEstimatedTime('~30 seconds');
            return;
        }
        
        const resourceType = this.detectResourceType(value);
        const isValid = resourceType !== 'unknown';
        
        if (isValid) {
            this.updateValidationState('valid', `Detected: ${resourceType}`, validationMessage, validationStatus);
            this.resourceInput.classList.add('success');
            this.showValidationMessage(`✓ Detected: ${resourceType}`, 'success');
            this.updateEstimatedTime(this.getEstimatedTime(resourceType));
        } else {
            this.updateValidationState('invalid', 'Invalid format', validationMessage, validationStatus);
            this.resourceInput.classList.add('error');
            this.showValidationMessage('⚠ Please enter a valid hash, URL, domain, or IP address', 'error');
            this.updateEstimatedTime('Unknown');
        }
        
        // Show relevant suggestions
        if (value.length > 2) {
            this.showRelevantSuggestions(value);
        }
    }

    // Clear validation messages
    clearValidationMessages() {
        const validationMessage = document.getElementById('validation-message');
        if (validationMessage) {
            validationMessage.style.display = 'none';
            validationMessage.innerHTML = '';
        }
    }

    // Show validation message - IMPROVED VERSION
    showValidationMessage(message, type) {
        const validationMessage = document.getElementById('validation-message');
        if (validationMessage) {
            validationMessage.className = `validation-message ${type}`;
            validationMessage.innerHTML = message;
            validationMessage.style.display = 'flex';
            
            // Auto-hide success messages after 3 seconds
            if (type === 'success') {
                setTimeout(() => {
                    if (validationMessage.classList.contains('success')) {
                        validationMessage.style.display = 'none';
                    }
                }, 3000);
            }
        }
    }

    // Update estimated time
    updateEstimatedTime(time) {
        const estimatedTimeElement = document.getElementById('estimated-time');
        if (estimatedTimeElement) {
            estimatedTimeElement.textContent = time;
        }
    }

    // Get estimated time based on resource type
    getEstimatedTime(resourceType) {
        const timeMap = {
            'MD5 hash': '~5 seconds',
            'SHA1 hash': '~5 seconds', 
            'SHA256 hash': '~5 seconds',
            'URL': '~45 seconds',
            'IPv4 address': '~15 seconds',
            'domain': '~20 seconds'
        };
        return timeMap[resourceType] || '~30 seconds';
    }

    // Update validation state
    updateValidationState(state, text, validationElement, statusElement) {
        if (statusElement) {
            statusElement.textContent = text;
            statusElement.className = `status-${state}`;
        }
    }

    selectOption(e) {
        const option = e.currentTarget;
        
        // Remove active class from all options
        document.querySelectorAll('.option-card').forEach(opt => opt.classList.remove('active'));
        
        // Add active class to selected option
        option.classList.add('active');
        
        // Always set to auto since that's our only option
        this.currentOption = 'auto';
        document.getElementById('analysis-option').value = 'auto';
        
        // Enhanced selection animation
        option.style.transform = 'translateY(-8px) scale(1.05) translateZ(0)';
        setTimeout(() => {
            option.style.transform = 'translateY(-8px) scale(1.02) translateZ(0)';
        }, 200);
        
        this.showEnhancedNotification('Auto-detection mode selected', 'info', 2000);
    }

    detectResourceType(resource) {
        // Enhanced detection with better regex patterns
        if (/^[a-f0-9]{32}$/i.test(resource)) return 'MD5 hash';
        if (/^[a-f0-9]{40}$/i.test(resource)) return 'SHA1 hash';
        if (/^[a-f0-9]{64}$/i.test(resource)) return 'SHA256 hash';
        
        // Enhanced URL validation
        try {
            const url = new URL(resource);
            return url.protocol === 'http:' || url.protocol === 'https:' ? 'URL' : 'unknown';
        } catch {}
        
        // Enhanced IP validation (including IPv6 basic check)
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(resource)) {
            return 'IPv4 address';
        }
        
        // Enhanced domain validation
        if (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(resource)) {
            return 'domain';
        }
        
        return 'unknown';
    }

    // Handle suggestion navigation
    handleSuggestionNavigation(e) {
        e.preventDefault();
        const suggestions = document.querySelectorAll('.suggestion-item');
        const active = document.querySelector('.suggestion-item.active');
        
        if (suggestions.length === 0) return;
        
        let newIndex = 0;
        if (active) {
            const currentIndex = Array.from(suggestions).indexOf(active);
            newIndex = e.key === 'ArrowDown' 
                ? (currentIndex + 1) % suggestions.length
                : (currentIndex - 1 + suggestions.length) % suggestions.length;
        }
        
        suggestions.forEach(s => s.classList.remove('active'));
        suggestions[newIndex].classList.add('active');
    }

    // Get active suggestion
    getActiveSuggestion() {
        return document.querySelector('.suggestion-item.active');
    }

    // Select active suggestion
    selectActiveSuggestion() {
        const active = this.getActiveSuggestion();
        if (active) {
            this.selectSuggestion(active.dataset.suggestion);
        }
    }

    selectSuggestion(suggestion) {
        this.resourceInput.value = suggestion;
        this.hideResourceSuggestions();
        this.handleResourceInputEnhanced({ target: this.resourceInput });
        
        // Focus effect
        this.resourceInput.focus();
        this.resourceInput.style.transform = 'scale(1.02)';
        setTimeout(() => {
            this.resourceInput.style.transform = '';
        }, 300);
        
        this.showEnhancedNotification(`Selected: ${suggestion}`, 'success', 2000);
    }

    showResourceSuggestions() {
        const suggestionsContainer = document.getElementById('resource-suggestions');
        if (suggestionsContainer && suggestionsContainer.children.length > 0) {
            suggestionsContainer.style.display = 'block';
            suggestionsContainer.classList.add('animate-fade-down');
        }
    }

    hideResourceSuggestions() {
        setTimeout(() => {
            const suggestionsContainer = document.getElementById('resource-suggestions');
            if (suggestionsContainer) {
                suggestionsContainer.style.display = 'none';
                suggestionsContainer.classList.remove('animate-fade-down');
            }
        }, 200);
    }

    // Quick action methods
    quickHashAnalysis() {
        this.animateFormFill('resource', 'd41d8cd98f00b204e9800998ecf8427e');
        
        // Select basic option
        document.querySelectorAll('.option-card').forEach(opt => opt.classList.remove('active'));
        document.querySelector('[data-option="auto"]').classList.add('active');
        this.currentOption = 'auto';
        
        document.getElementById('analysis-type').value = 'hash';
        
        this.handleResourceInputEnhanced({ target: this.resourceInput });
        this.showEnhancedNotification('Quick hash analysis ready!', 'success');
    }

    focusOnAnalyzer() {
        this.resourceInput.focus();
        
        // Add focus animation
        this.resourceInput.style.transform = 'scale(1.02)';
        setTimeout(() => {
            this.resourceInput.style.transform = '';
        }, 300);
    }

    resetForm() {
        this.analysisForm.reset();
        this.hideResults();
        this.hideStatus();
        
        // Reset option selection
        document.querySelectorAll('.option-card').forEach(opt => opt.classList.remove('active'));
        document.querySelector('[data-option="auto"]').classList.add('active');
        this.currentOption = 'auto';
        
        this.clearValidationMessages();
        this.resourceInput.classList.remove('error', 'success');
        this.updateValidationState('pending', 'Pending', 
            document.getElementById('validation-message'), 
            document.getElementById('resource-validation'));
        this.updateEstimatedTime('~30 seconds');
        
        this.focusOnAnalyzer();
        this.showEnhancedNotification('Form reset successfully', 'info');
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

    async handleAnalysisSubmit(e) {
        e.preventDefault();
        
        if (this.isAnalyzing) return;
        
        const formData = this.collectFormData();
        
        if (!this.validateFormData(formData)) {
            return;
        }
        
        this.startAnalysis(formData);
    }

    collectFormData() {
        return {
            resource: this.resourceInput.value.trim(),
            analysisType: document.getElementById('analysis-type').value,
            analysisOption: this.currentOption
        };
    }

    validateFormData(data) {
        if (!data.resource) {
            this.showEnhancedNotification('Please enter a resource to analyze', 'error');
            this.resourceInput.focus();
            this.resourceInput.classList.add('error');
            this.showValidationMessage('⚠ Resource is required', 'error');
            return false;
        }
        
        if (this.detectResourceType(data.resource) === 'unknown') {
            this.showEnhancedNotification('Invalid resource format', 'error');
            this.resourceInput.focus();
            this.resourceInput.classList.add('error');
            this.showValidationMessage('⚠ Please enter a valid resource format', 'error');
            return false;
        }
        
        return true;
    }

    async startAnalysis(formData) {
        this.isAnalyzing = true;
        this.analysisStartTime = Date.now();
        
        // Enhanced UI updates
        this.showAnalysisStatusEnhanced();
        this.hideResults();
        this.updateAnalysisButtonEnhanced('analyzing');
        this.startAnalysisTimer();
        this.simulateRealTimeUpdatesEnhanced();
        
        try {
            const response = await fetch('/virustotal-analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.handleAnalysisSuccess(data);
            } else if (data.status === 'scanning') {
                this.handleScanningStatus(data);
            } else {
                this.handleAnalysisError(data.message || 'Unknown error occurred');
            }
        } catch (error) {
            this.handleAnalysisError(`Connection error: ${error.message}`);
        }
    }

    // Enhanced real-time updates
    simulateRealTimeUpdatesEnhanced() {
        let progress = 0;
        const phases = [
            'Connecting to Engines',
            'Validating Resource Format',
            'Submitting to VirusTotal',
            'Scanning with Multiple Engines',
            'Analyzing Threat Patterns',
            'Collecting Intelligence Data',
            'Processing Detection Results',
            'Generating Threat Report'
        ];
        
        let currentPhase = 0;
        let engineCount = 0;
        let threatCount = 0;
        let lastProgressUpdate = 0;
        
        this.realTimeInterval = setInterval(() => {
            // Realistic progress increment with easing
            const progressIncrement = Math.max(1, Math.random() * 8 + 2);
            progress = Math.min(100, progress + progressIncrement);
            
            // Update phase with smooth transitions
            const phaseProgress = Math.floor((progress / 100) * phases.length);
            if (phaseProgress !== currentPhase && phaseProgress < phases.length) {
                currentPhase = phaseProgress;
                this.updateCurrentPhaseEnhanced(phases[currentPhase]);
                this.addAnalysisLogEntryEnhanced(`${phases[currentPhase]}...`, 'info');
            }
            
            // Smooth progress updates
            if (progress - lastProgressUpdate >= 1) {
                this.updateAnalysisProgressEnhanced(progress);
                lastProgressUpdate = progress;
            }
            
            // Realistic engine scanning simulation
            if (Math.random() > 0.6 && engineCount < 70) {
                const increment = Math.floor(Math.random() * 4) + 1;
                engineCount = Math.min(70, engineCount + increment);
                this.animateCounterUpdate('live-engines', engineCount);
                
                // Add log entry for significant engine milestones
                if (engineCount % 10 === 0) {
                    this.addAnalysisLogEntryEnhanced(`${engineCount} engines completed`, 'success');
                }
            }
            
            // Realistic threat detection
            if (Math.random() > 0.92 && progress > 40 && threatCount < 5) {
                threatCount = Math.min(5, threatCount + 1);
                this.animateCounterUpdate('live-threats', threatCount);
                this.showThreatDetectionAlert();
                this.addAnalysisLogEntryEnhanced(`Potential threat detected by engine ${engineCount}`, 'warning');
            }
            
            // Update performance indicator
            const performance = progress < 50 ? 'Optimal' : progress < 80 ? 'Good' : 'Completing';
            const performanceElement = document.getElementById('live-performance');
            if (performanceElement) {
                performanceElement.textContent = performance;
            }
            
            // Update all displays
            this.updateRealTimeDisplaysEnhanced(phases[currentPhase] || 'Processing', threatCount, engineCount, progress);
            
            if (progress >= 100) {
                clearInterval(this.realTimeInterval);
                this.completeAnalysisEnhanced();
            }
        }, 500 + Math.random() * 300); // Variable timing for realism
    }

    // Enhanced progress update with smooth animation
    updateAnalysisProgressEnhanced(percentage) {
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.querySelector('.progress-text');
        
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
            progressFill.classList.add('gpu-accelerated');
        }
        
        if (progressText) {
            progressText.textContent = `${Math.round(percentage)}%`;
        }
        
        // Update live progress with animation
        const liveProgress = document.getElementById('live-progress');
        if (liveProgress) {
            const currentValue = parseInt(liveProgress.textContent) || 0;
            if (Math.abs(percentage - currentValue) >= 1) {
                this.animateValue(liveProgress, currentValue, Math.round(percentage), 300);
            }
        }
    }

    // Enhanced phase update
    updateCurrentPhaseEnhanced(phase) {
        const phaseElement = document.getElementById('current-phase');
        const statusElement = document.getElementById('analysis-status');
        
        if (phaseElement) {
            phaseElement.style.opacity = '0';
            phaseElement.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                phaseElement.textContent = phase;
                phaseElement.style.transition = 'all 0.3s ease';
                phaseElement.style.opacity = '1';
                phaseElement.style.transform = 'translateY(0)';
            }, 150);
        }
        
        if (statusElement) {
            statusElement.style.opacity = '0';
            setTimeout(() => {
                statusElement.textContent = phase;
                statusElement.style.opacity = '1';
            }, 150);
        }
    }

    // Update real-time displays
    updateRealTimeDisplaysEnhanced(phase, threats, engines, progress) {
        // Update header stats
        const analysisStatus = document.getElementById('analysis-status');
        const threatsFound = document.getElementById('threats-found');
        const enginesScanned = document.getElementById('engines-scanned');
        
        if (analysisStatus) analysisStatus.textContent = phase;
        if (threatsFound) threatsFound.textContent = `${threats} Threats`;
        if (enginesScanned) enginesScanned.textContent = `${engines}/70+ Engines`;
        
        // Update live stats in the scanning panel
        const liveEngines = document.getElementById('live-engines');
        const liveThreats = document.getElementById('live-threats');
        
        if (liveEngines && parseInt(liveEngines.textContent) !== engines) {
            liveEngines.textContent = engines;
        }
        if (liveThreats && parseInt(liveThreats.textContent) !== threats) {
            liveThreats.textContent = threats;
        }
    }

    // Enhanced analysis button states
    updateAnalysisButtonEnhanced(state) {
        const btn = this.analysisBtn;
        const icon = btn.querySelector('.launch-icon');
        const text = btn.querySelector('.btn-text');
        
        btn.classList.remove('analyzing', 'complete', 'loading');
        
        switch (state) {
            case 'analyzing':
                btn.classList.add('analyzing', 'gpu-accelerated');
                btn.disabled = true;
                icon.className = 'fas fa-spinner launch-icon';
                text.textContent = 'Analyzing...';
                this.startButtonLoadingAnimation(btn);
                break;
                
            case 'complete':
                btn.classList.add('complete');
                btn.disabled = true;
                icon.className = 'fas fa-check launch-icon';
                text.textContent = 'Analysis Complete';
                this.playSuccessAnimation(btn);
                break;
                
            case 'ready':
            default:
                btn.disabled = false;
                btn.classList.remove('gpu-accelerated');
                icon.className = 'fas fa-shield-virus launch-icon';
                text.textContent = 'Start Threat Analysis';
                this.stopButtonLoadingAnimation(btn);
                break;
        }
    }

    // Button loading animation
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

    // Success animation for button
    playSuccessAnimation(button) {
        button.style.transform = 'scale(1.05)';
        setTimeout(() => {
            button.style.transform = 'scale(1)';
        }, 300);
        
        // Confetti-like effect
        this.createSuccessParticles(button);
    }

    // Enhanced counter animation
    animateCounterUpdate(elementId, newValue) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const currentValue = parseInt(element.textContent) || 0;
        
        if (newValue === currentValue) return;
        
        element.classList.add('will-change-transform');
        this.animateValue(element, currentValue, newValue, 400);
        
        // Add pulse effect
        element.style.transform = 'scale(1.1)';
        element.style.color = '#e74c3c';
        
        setTimeout(() => {
            element.style.transform = 'scale(1)';
            element.style.color = '';
            element.classList.remove('will-change-transform');
        }, 400);
    }

    // Enhanced value animation
    animateValue(element, start, end, duration) {
        if (!element) return;
        
        const startTime = performance.now();
        const difference = end - start;
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeOutCubic = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(start + (difference * easeOutCubic));
            
            if (element.id === 'live-progress') {
                element.textContent = `${value}%`;
            } else {
                element.textContent = value;
            }
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }

    // Enhanced threat detection alert
    showThreatDetectionAlert() {
        const alert = document.createElement('div');
        alert.className = 'threat-alert animate-fade-scale';
        alert.innerHTML = `
            <div class="alert-icon">
                <i class="fas fa-exclamation-triangle"></i>
            </div>
            <div class="alert-content">
                <div class="alert-title">Threat Detected!</div>
                <div class="alert-message">Potential malware identified</div>
            </div>
        `;
        
        alert.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            z-index: 1001;
            box-shadow: 0 10px 30px rgba(231, 76, 60, 0.4);
            display: flex;
            align-items: center;
            gap: 1rem;
            min-width: 280px;
            backdrop-filter: blur(10px);
        `;
        
        document.body.appendChild(alert);
        
        // Auto remove with animation
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100%)';
            setTimeout(() => alert.remove(), 300);
        }, 4000);
        
        // Add sound effect (optional)
        this.playNotificationSound();
    }

    // Show analysis status enhanced
    showAnalysisStatusEnhanced() {
        const statusPanel = this.analysisStatus;
        statusPanel.style.display = 'block';
        statusPanel.style.opacity = '0';
        statusPanel.classList.add('animate-fade-up');
        
        setTimeout(() => {
            statusPanel.style.opacity = '1';
        }, 10);
        
        // Initialize analysis log
        this.clearAnalysisLog();
        this.addAnalysisLogEntryEnhanced('Initializing VirusTotal analysis...', 'info');
        this.addAnalysisLogEntryEnhanced('Validating resource format...', 'info');
        this.addAnalysisLogEntryEnhanced('Connecting to threat intelligence APIs...', 'info');
        
        // Reset progress
        this.updateAnalysisProgressEnhanced(0);
        this.updateCurrentPhaseEnhanced('Initializing');
        
        // Reset live stats
        document.getElementById('live-engines').textContent = '0';
        document.getElementById('live-threats').textContent = '0';
        document.getElementById('live-progress').textContent = '0%';
        document.getElementById('live-performance').textContent = 'Optimal';
    }

    hideStatus() {
        const statusPanel = this.analysisStatus;
        statusPanel.style.opacity = '0';
        
        setTimeout(() => {
            statusPanel.style.display = 'none';
        }, 300);
    }

    showResults() {
        const resultsPanel = this.resultsSection;
        resultsPanel.style.display = 'block';
        resultsPanel.style.opacity = '0';
        resultsPanel.classList.add('animate-fade-up');
        
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

    startAnalysisTimer() {
        this.analysisTimer = setInterval(() => {
            const elapsed = Date.now() - this.analysisStartTime;
            const timeText = this.formatTime(elapsed);
            
            const timeElement = document.getElementById('analysis-time');
            if (timeElement) {
                timeElement.textContent = timeText;
            }
        }, 1000);
    }

    stopAnalysisTimer() {
        if (this.analysisTimer) {
            clearInterval(this.analysisTimer);
            this.analysisTimer = null;
        }
    }

    formatTime(milliseconds) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        
        return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
    }

    // Handle analysis success
    handleAnalysisSuccess(data) {
        this.lastResults = data;
        this.hideStatus();
        this.displayResults(data);
        this.showResults();
        this.updateAnalysisButtonEnhanced('complete');
        
        // Update final stats
        this.updateFinalStats(data);
        
        // Show success notification
        const detections = this.countDetections(data.scan_stats);
        this.showEnhancedNotification(
            `Analysis completed! ${detections.malicious} threats detected from ${detections.total} engines`,
            detections.malicious > 0 ? 'warning' : 'success'
        );
        
        // Scroll to results
        
        this.completeAnalysisEnhanced();
    }

    handleScanningStatus(data) {
        this.pollingScanId = data.scan_id;
        this.addAnalysisLogEntryEnhanced('URL submitted for scanning. Waiting for results...', 'info');
        this.updateCurrentPhaseEnhanced('URL Scanning');
        
        // Start polling for results
        this.startResultsPolling();
    }

    startResultsPolling() {
        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`/virustotal-scan-status/${this.pollingScanId}`);
                const data = await response.json();
                
                if (data.status === 'completed') {
                    clearInterval(pollInterval);
                    
                    // Transform the data to match expected format
                    const transformedData = {
                        status: 'success',
                        resource_type: 'url',
                        resource: this.resourceInput.value.trim(),
                        scan_date: data.scan_date,
                        scan_stats: data.scan_stats,
                        reputation: data.reputation
                    };
                    
                    this.handleAnalysisSuccess(transformedData);
                } else if (data.status === 'error') {
                    clearInterval(pollInterval);
                    this.handleAnalysisError(data.message);
                } else {
                    this.addAnalysisLogEntryEnhanced(`Scan ${data.status}...`, 'info');
                }
            } catch (error) {
                clearInterval(pollInterval);
                this.handleAnalysisError(`Polling error: ${error.message}`);
            }
        }, 5000); // Poll every 5 seconds
    }

    handleAnalysisError(message) {
        this.showEnhancedNotification(`Analysis failed: ${message}`, 'error');
        this.addAnalysisLogEntryEnhanced(`Error: ${message}`, 'error');
        this.completeAnalysisEnhanced();
    }

    completeAnalysisEnhanced() {
        this.isAnalyzing = false;
        this.stopAnalysisTimer();
        
        // Stop real-time updates
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
            this.realTimeInterval = null;
        }
        
        setTimeout(() => {
            this.updateAnalysisButtonEnhanced('ready');
        }, 2000);
    }

    // Update final stats
    updateFinalStats(data) {
        const totalDetections = document.getElementById('total-detections');
        const totalEngines = document.getElementById('total-engines');
        const scanDate = document.getElementById('scan-date');
        const analysisDuration = document.getElementById('analysis-duration');
        
        if (data.scan_stats) {
            const detections = this.countDetections(data.scan_stats);
            if (totalDetections) totalDetections.textContent = detections.malicious + detections.suspicious;
            if (totalEngines) totalEngines.textContent = detections.total;
        }
        
        if (scanDate && data.scan_date) {
            const date = new Date(data.scan_date * 1000);
            scanDate.textContent = date.toLocaleDateString();
        }
        
        if (analysisDuration && this.analysisStartTime) {
            const duration = Date.now() - this.analysisStartTime;
            analysisDuration.textContent = this.formatTime(duration);
        }
    }

    countDetections(scanStats) {
        if (!scanStats) return { malicious: 0, suspicious: 0, total: 0 };
        
        return {
            malicious: scanStats.malicious || 0,
            suspicious: scanStats.suspicious || 0,
            harmless: scanStats.harmless || 0,
            total: scanStats.total || 0
        };
    }

    // Add analysis log entry enhanced
    addAnalysisLogEntryEnhanced(message, type = 'info') {
        const logContent = document.getElementById('analysis-log');
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
        if (logContent.children.length > 20) {
            const firstChild = logContent.firstChild;
            if (firstChild) {
                firstChild.style.opacity = '0';
                setTimeout(() => firstChild.remove(), 300);
            }
        }
    }

    clearAnalysisLog() {
        const logContent = document.getElementById('analysis-log');
        if (logContent) {
            logContent.innerHTML = '';
        }
    }

    // Display results - FIXED VERSION FOR BETTER DATA HANDLING
    displayResults(data) {
        console.log('Displaying results:', data); // Debug log
        
        // Update threat overview
        this.updateThreatOverview(data);
        
        // Update resource info
        this.updateResourceInfo(data);
        
        // Update detection results - FIXED
        this.updateDetectionResults(data);
        
        // Enable export buttons
        this.enableExportButtons();
    }

    updateThreatOverview(data) {
        const threatScore = document.getElementById('threat-score');
        const reputationBadge = document.getElementById('reputation-badge');
        const maliciousCount = document.getElementById('malicious-count');
        const suspiciousCount = document.getElementById('suspicious-count');
        const cleanCount = document.getElementById('clean-count');
        
        if (data.scan_stats) {
            const stats = data.scan_stats;
            
            // Update threat score (percentage of malicious detections)
            const score = Math.round(stats.malicious_percentage || 0);
            if (threatScore) {
                threatScore.querySelector('.score-value').textContent = score;
            }
            
            // Update reputation badge
            if (reputationBadge) {
                const reputation = data.reputation || 'unknown';
                reputationBadge.className = `reputation-badge ${reputation}`;
                
                const iconMap = {
                    'clean': 'fa-shield-check',
                    'suspicious': 'fa-exclamation-triangle',
                    'malicious': 'fa-skull-crossbones',
                    'unknown': 'fa-question-circle'
                };
                
                reputationBadge.innerHTML = `
                    <i class="fas ${iconMap[reputation]}"></i>
                    <span>${reputation.charAt(0).toUpperCase() + reputation.slice(1)}</span>
                `;
            }
            
            // Update detection counts
            if (maliciousCount) maliciousCount.textContent = stats.malicious || 0;
            if (suspiciousCount) suspiciousCount.textContent = stats.suspicious || 0;
            if (cleanCount) cleanCount.textContent = stats.harmless || 0;
            
            // Update breakdown chart
            this.updateBreakdownChart(stats);
        }
    }

    updateBreakdownChart(stats) {
        const chart = document.getElementById('breakdown-chart');
        if (!chart || !stats.total) return;
        
        const maliciousPercentage = ((stats.malicious || 0) / stats.total) * 100;
        const suspiciousPercentage = ((stats.suspicious || 0) / stats.total) * 100;
        const cleanPercentage = ((stats.harmless || 0) / stats.total) * 100;
        
        chart.style.background = `conic-gradient(
            #e74c3c 0% ${maliciousPercentage}%,
            #f39c12 ${maliciousPercentage}% ${maliciousPercentage + suspiciousPercentage}%,
            #27ae60 ${maliciousPercentage + suspiciousPercentage}% 100%
        )`;
    }

    updateResourceInfo(data) {
        const resourceInfo = document.getElementById('resource-info');
        if (!resourceInfo) return;
        
        let infoHtml = '';
        
        // Resource header
        infoHtml += `
            <div class="resource-header">
                <h4><i class="fas fa-info-circle"></i> Resource Information</h4>
                <div class="resource-type-badge">
                    <i class="fas fa-${this.getResourceIcon(data.resource_type)}"></i>
                    ${data.resource_type.toUpperCase()}
                </div>
            </div>
        `;
        
        // Resource details based on type
        infoHtml += '<div class="resource-details">';
        
        if (data.resource_type === 'file' && data.file_info) {
            infoHtml += this.createFileInfoSection(data.file_info);
        } else if (data.resource_type === 'url' && data.url_info) {
            infoHtml += this.createUrlInfoSection(data.url_info);
        } else if (data.resource_type === 'domain' && data.domain_info) {
            infoHtml += this.createDomainInfoSection(data.domain_info);
        } else if (data.resource_type === 'ip' && data.ip_info) {
            infoHtml += this.createIpInfoSection(data.ip_info);
        }
        
        infoHtml += '</div>';
        
        resourceInfo.innerHTML = infoHtml;
        resourceInfo.classList.add('animate-fade-up');
    }

    createFileInfoSection(fileInfo) {
        return `
            <div class="detail-section">
                <h5><i class="fas fa-file"></i> File Details</h5>
                <div class="detail-list">
                    ${fileInfo.md5 ? `<div class="detail-item">
                        <span class="detail-label">MD5:</span>
                        <span class="detail-value hash">${fileInfo.md5}</span>
                    </div>` : ''}
                    ${fileInfo.sha1 ? `<div class="detail-item">
                        <span class="detail-label">SHA1:</span>
                        <span class="detail-value hash">${fileInfo.sha1}</span>
                    </div>` : ''}
                    ${fileInfo.sha256 ? `<div class="detail-item">
                        <span class="detail-label">SHA256:</span>
                        <span class="detail-value hash">${fileInfo.sha256}</span>
                    </div>` : ''}
                    ${fileInfo.file_size ? `<div class="detail-item">
                        <span class="detail-label">File Size:</span>
                        <span class="detail-value">${this.formatFileSize(fileInfo.file_size)}</span>
                    </div>` : ''}
                    ${fileInfo.file_type ? `<div class="detail-item">
                        <span class="detail-label">File Type:</span>
                        <span class="detail-value">${fileInfo.file_type}</span>
                    </div>` : ''}
                    ${fileInfo.times_submitted ? `<div class="detail-item">
                        <span class="detail-label">Submissions:</span>
                        <span class="detail-value">${fileInfo.times_submitted}</span>
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    createUrlInfoSection(urlInfo) {
        return `
            <div class="detail-section">
                <h5><i class="fas fa-globe"></i> URL Details</h5>
                <div class="detail-list">
                    ${urlInfo.final_url ? `<div class="detail-item">
                        <span class="detail-label">Final URL:</span>
                        <span class="detail-value">${urlInfo.final_url}</span>
                    </div>` : ''}
                    ${urlInfo.title ? `<div class="detail-item">
                        <span class="detail-label">Page Title:</span>
                        <span class="detail-value">${urlInfo.title}</span>
                    </div>` : ''}
                    ${urlInfo.last_http_response_code ? `<div class="detail-item">
                        <span class="detail-label">HTTP Response:</span>
                        <span class="detail-value">${urlInfo.last_http_response_code}</span>
                    </div>` : ''}
                    ${urlInfo.times_submitted ? `<div class="detail-item">
                        <span class="detail-label">Submissions:</span>
                        <span class="detail-value">${urlInfo.times_submitted}</span>
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    createDomainInfoSection(domainInfo) {
        return `
            <div class="detail-section">
                <h5><i class="fas fa-globe"></i> Domain Details</h5>
                <div class="detail-list">
                    ${domainInfo.registrar ? `<div class="detail-item">
                        <span class="detail-label">Registrar:</span>
                        <span class="detail-value">${domainInfo.registrar}</span>
                    </div>` : ''}
                    ${domainInfo.creation_date ? `<div class="detail-item">
                        <span class="detail-label">Created:</span>
                        <span class="detail-value">${new Date(domainInfo.creation_date * 1000).toLocaleDateString()}</span>
                    </div>` : ''}
                    ${domainInfo.last_update_date ? `<div class="detail-item">
                        <span class="detail-label">Updated:</span>
                        <span class="detail-value">${new Date(domainInfo.last_update_date * 1000).toLocaleDateString()}</span>
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    createIpInfoSection(ipInfo) {
        return `
            <div class="detail-section">
                <h5><i class="fas fa-server"></i> IP Details</h5>
                <div class="detail-list">
                    ${ipInfo.country ? `<div class="detail-item">
                        <span class="detail-label">Country:</span>
                        <span class="detail-value">${ipInfo.country}</span>
                    </div>` : ''}
                    ${ipInfo.asn ? `<div class="detail-item">
                        <span class="detail-label">ASN:</span>
                        <span class="detail-value">${ipInfo.asn}</span>
                    </div>` : ''}
                    ${ipInfo.as_owner ? `<div class="detail-item">
                        <span class="detail-label">AS Owner:</span>
                        <span class="detail-value">${ipInfo.as_owner}</span>
                    </div>` : ''}
                    ${ipInfo.network ? `<div class="detail-item">
                        <span class="detail-label">Network:</span>
                        <span class="detail-value">${ipInfo.network}</span>
                    </div>` : ''}
                </div>
            </div>
        `;
    }

    // FIXED updateDetectionResults - properly handles the new backend data structure
    updateDetectionResults(data) {
        const detectionTableBody = document.getElementById('detection-table-body');
        if (!detectionTableBody) {
            console.error('Detection table body not found');
            return;
        }
        
        if (!data.analysis_results || !Array.isArray(data.analysis_results)) {
            console.error('No analysis results found or invalid format');
            detectionTableBody.innerHTML = '<tr><td colspan="5">No detection results available</td></tr>';
            return;
        }
        
        console.log('Processing detection results:', data.analysis_results.length, 'engines');
        
        let tableHtml = '';
        
        data.analysis_results.forEach((result, index) => {
            const categoryClass = this.getResultCategoryClass(result.category);
            const categoryIcon = this.getCategoryIcon(result.category);
            
            tableHtml += `
                <tr class="detection-row" style="animation-delay: ${index * 0.05}s;">
                    <td data-label="Engine">
                        <span class="engine-name">${result.engine || 'Unknown'}</span>
                    </td>
                    <td data-label="Result">
                        <span class="detection-result ${categoryClass}">
                            <i class="fas fa-${categoryIcon}"></i>
                            ${result.result || result.category || 'No result'}
                        </span>
                    </td>
                    <td data-label="Category">
                        <span class="category-badge ${categoryClass}">${result.category || 'unknown'}</span>
                    </td>
                    <td data-label="Method">
                        <span class="method-info">${result.method || 'Unknown'}</span>
                    </td>
                    <td data-label="Version">
                        <span class="version-info">${result.engine_version || 'N/A'}</span>
                    </td>
                </tr>
            `;
        });
        
        detectionTableBody.innerHTML = tableHtml;
        
        console.log(`Updated detection table with ${data.analysis_results.length} results`);
    }

    getResourceIcon(resourceType) {
        const icons = {
            'file': 'file',
            'url': 'globe',
            'domain': 'globe-americas',
            'ip': 'server'
        };
        return icons[resourceType] || 'question-circle';
    }

    getResultCategoryClass(category) {
        const classMap = {
            'malicious': 'malicious',
            'suspicious': 'suspicious',
            'harmless': 'clean',
            'clean': 'clean',
            'undetected': 'clean',
            'timeout': 'timeout'
        };
        return classMap[category] || 'clean';
    }

    getCategoryIcon(category) {
        const iconMap = {
            'malicious': 'skull-crossbones',
            'suspicious': 'exclamation-triangle',
            'harmless': 'shield-check',
            'clean': 'shield-check',
            'undetected': 'question-circle',
            'timeout': 'clock'
        };
        return iconMap[category] || 'question-circle';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    enableExportButtons() {
        const buttons = ['export-json', 'export-csv', 'copy-results', 'share-results'];
        buttons.forEach(btnId => {
            const btn = document.getElementById(btnId);
            if (btn) {
                btn.disabled = false;
                btn.style.opacity = '1';
            }
        });
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
        const targetView = document.getElementById(`${view}-view`);
        if (targetView) {
            targetView.classList.add('active');
        }
        
        this.showEnhancedNotification(`Switched to ${view} view`, 'info', 2000);
    }

    // Export functions
    exportJson() {
        if (!this.lastResults) return;
        
        const dataStr = JSON.stringify(this.lastResults, null, 2);
        this.downloadFile(dataStr, 'virustotal_analysis_results.json', 'application/json');
        
        this.showEnhancedNotification('Results exported as JSON', 'success');
    }

    exportCsv() {
        if (!this.lastResults) return;
        
        let csvContent = 'Engine,Result,Category,Method,Version\n';
        
        if (this.lastResults.analysis_results) {
            this.lastResults.analysis_results.forEach(result => {
                csvContent += `"${result.engine}","${result.result || ''}","${result.category}","${result.method || ''}","${result.engine_version || ''}"\n`;
            });
        }
        
        this.downloadFile(csvContent, 'virustotal_analysis_results.csv', 'text/csv');
        
        this.showEnhancedNotification('Results exported as CSV', 'success');
    }

    copyResults() {
        if (!this.lastResults) return;
        
        let textContent = 'VirusTotal Analysis Results\n';
        textContent += '=============================\n\n';
        textContent += `Resource: ${this.lastResults.resource}\n`;
        textContent += `Type: ${this.lastResults.resource_type}\n`;
        textContent += `Scan Date: ${new Date().toLocaleString()}\n`;
        textContent += `Reputation: ${this.lastResults.reputation}\n\n`;
        
        if (this.lastResults.scan_stats) {
            textContent += 'Scan Statistics:\n';
            textContent += `- Malicious: ${this.lastResults.scan_stats.malicious}\n`;
            textContent += `- Suspicious: ${this.lastResults.scan_stats.suspicious}\n`;
            textContent += `- Clean: ${this.lastResults.scan_stats.harmless}\n`;
            textContent += `- Total Engines: ${this.lastResults.scan_stats.total}\n\n`;
        }
        
        if (this.lastResults.analysis_results) {
            textContent += 'Detection Results:\n';
            textContent += 'ENGINE\t\tRESULT\t\tCATEGORY\n';
            textContent += '------\t\t------\t\t--------\n';
            this.lastResults.analysis_results.forEach(result => {
                textContent += `${result.engine}\t\t${result.result || result.category}\t\t${result.category}\n`;
            });
        }
        
        navigator.clipboard.writeText(textContent).then(() => {
            this.showEnhancedNotification('Results copied to clipboard', 'success');
        }).catch(() => {
            this.showEnhancedNotification('Failed to copy results', 'error');
        });
    }

    shareResults() {
        if (!this.lastResults) return;
        
        const shareUrl = `${window.location.origin}/virustotal?resource=${encodeURIComponent(this.lastResults.resource)}`;
        
        if (navigator.share) {
            navigator.share({
                title: 'VirusTotal Analysis Results',
                text: `Analysis results for ${this.lastResults.resource}`,
                url: shareUrl
            }).then(() => {
                this.showEnhancedNotification('Results shared successfully', 'success');
            }).catch(() => {
                this.copyToClipboard(shareUrl);
            });
        } else {
            this.copyToClipboard(shareUrl);
        }
    }

    saveResults() {
        if (!this.lastResults) return;
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `virustotal_${this.lastResults.resource_type}_${timestamp}.json`;
        
        this.exportJson();
        this.showEnhancedNotification('Results saved locally', 'success');
    }

    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showEnhancedNotification('Share link copied to clipboard', 'success');
        }).catch(() => {
            this.showEnhancedNotification('Failed to copy share link', 'error');
        });
    }

    downloadFile(content, fileName, contentType) {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }

    // Dropdown functions
    toggleDropdown(e) {
        e.stopPropagation();
        const dropdown = e.currentTarget.closest('.dropdown');
        const isOpen = dropdown.classList.contains('open');
        
        // Close all other dropdowns
        document.querySelectorAll('.dropdown.open').forEach(dd => {
            dd.classList.remove('open');
        });
        
        // Toggle current dropdown
        if (!isOpen) {
            dropdown.classList.add('open');
        }
    }

    // Rescan resource
    rescanResource() {
        if (!this.lastResults) return;
        
        this.resourceInput.value = this.lastResults.resource;
        this.handleResourceInputEnhanced({ target: this.resourceInput });
        
        // Scroll to form        
        this.showEnhancedNotification('Ready to rescan resource', 'info');
    }

    // Cancel analysis
    cancelAnalysis() {
        if (!this.isAnalyzing) return;
        
        this.showEnhancedNotification('Analysis cancelled by user', 'warning');
        this.addAnalysisLogEntryEnhanced('Analysis cancelled by user', 'warning');
        
        // Stop all timers and intervals
        this.stopAnalysisTimer();
        if (this.realTimeInterval) {
            clearInterval(this.realTimeInterval);
            this.realTimeInterval = null;
        }
        
        // Reset state
        this.isAnalyzing = false;
        this.hideStatus();
        this.updateAnalysisButtonEnhanced('ready');
    }

    // Examples carousel
    initExamplesCarousel() {
        let currentExample = 0;
        const examples = document.querySelectorAll('.example-slide');
        const dots = document.querySelectorAll('.example-dots .dot');
        
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
        }, 8000);
    }

    // Enhanced notification system
    showEnhancedNotification(message, type = 'info', duration = 4000) {
        const notification = document.createElement('div');
        notification.className = 'analysis-notification enhanced-notification animate-fade-scale';
        
        const iconMap = {
            'success': 'check-circle',
            'error': 'exclamation-circle', 
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        
        notification.innerHTML = `
            <div class="notification-icon ${type}">
                <i class="fas fa-${iconMap[type]}"></i>
            </div>
            <div class="notification-content">
                <div class="notification-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
                <div class="notification-message">${message}</div>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
            <div class="notification-progress"></div>
        `;
        
        document.body.appendChild(notification);
        
        // Enhanced entrance animation
        setTimeout(() => {
            notification.style.transform = 'translateX(0) scale(1)';
            notification.style.opacity = '1';
        }, 10);
        
        // Close button functionality
        notification.querySelector('.notification-close').addEventListener('click', () => {
            this.removeNotificationEnhanced(notification);
        });
        
        // Progress bar animation
        const progressBar = notification.querySelector('.notification-progress');
        if (progressBar) {
            progressBar.style.animation = `notificationProgress ${duration}ms linear`;
        }
        
        // Auto-remove
        setTimeout(() => {
            this.removeNotificationEnhanced(notification);
        }, duration);
    }

    // Enhanced notification removal
    removeNotificationEnhanced(notification) {
        notification.style.transform = 'translateX(100%) scale(0.9)';
        notification.style.opacity = '0';
        
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }

    // Help system
    showHelp() {
        const helpContent = `
            <div class="modal-overlay active">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 class="modal-title">VirusTotal Analysis Help</h3>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        <h4>Getting Started</h4>
                        <p>The VirusTotal scanner allows you to analyze files, URLs, domains, and IP addresses using 70+ antivirus engines and threat intelligence sources.</p>
                        
                        <h5>Supported Resource Types</h5>
                        <ul>
                            <li><strong>File Hashes:</strong> MD5, SHA1, SHA256 checksums</li>
                            <li><strong>URLs:</strong> Complete web addresses (http/https)</li>
                            <li><strong>Domains:</strong> Domain names without protocol</li>
                            <li><strong>IP Addresses:</strong> IPv4 addresses</li>
                        </ul>
                        
                        <h5>Analysis Modes</h5>
                        <ul>
                            <li><strong>Auto-detection:</strong> Automatically detects resource type and applies optimal analysis</li>
                        </ul>
                        
                        <h5>Understanding Results</h5>
                        <ul>
                            <li><strong>Clean:</strong> No threats detected by antivirus engines</li>
                            <li><strong>Suspicious:</strong> Potentially unwanted or suspicious behavior</li>
                            <li><strong>Malicious:</strong> Confirmed threats or malware detected</li>
                        </ul>
                        
                        <h5>Legal Notice</h5>
                        <p><strong>Important:</strong> This tool is for security research and analysis purposes. Do not use it to analyze resources you don't own or lack permission to investigate.</p>
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

    // Performance optimizations
    initializePerformanceOptimizations() {
        // Use Intersection Observer for scroll animations
        this.setupIntersectionObserver();
        
        // Optimize resize handling
        this.setupOptimizedResize();
        
        // Preload critical resources
        this.preloadResources();
        
        // Setup visibility change handler
        this.setupVisibilityChange();
    }

    setupIntersectionObserver() {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-fade-up');
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '50px'
        });

        // Observe animation targets
        document.querySelectorAll('.stats-card, .tip-card, .detail-section').forEach(el => {
            observer.observe(el);
        });
    }

    setupOptimizedResize() {
        let resizeTimeout;
        this.resizeHandler = () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                this.handleResize();
            }, 250);
        };
        window.addEventListener('resize', this.resizeHandler);
    }

    setupVisibilityChange() {
        this.visibilityChangeHandler = () => {
            if (document.hidden && this.isAnalyzing) {
                // Pause animations when hidden
                document.body.classList.add('animations-paused');
            } else if (!document.hidden && this.isAnalyzing) {
                // Resume animations when visible
                document.body.classList.remove('animations-paused');
            }
        };
        document.addEventListener('visibilitychange', this.visibilityChangeHandler);
    }

    handleResize() {
        // Optimize layout for current viewport
        const isMobile = window.innerWidth < 768;
        
        if (isMobile && !document.body.classList.contains('mobile-optimized')) {
            document.body.classList.add('mobile-optimized');
            this.optimizeForMobile();
        } else if (!isMobile && document.body.classList.contains('mobile-optimized')) {
            document.body.classList.remove('mobile-optimized');
            this.optimizeForDesktop();
        }
    }

    optimizeForMobile() {
        // Mobile-specific optimizations
        document.querySelectorAll('.gpu-accelerated').forEach(el => {
            el.classList.remove('gpu-accelerated');
        });
    }

    optimizeForDesktop() {
        // Desktop-specific optimizations
        document.querySelectorAll('.option-card, .btn-analysis-launch').forEach(el => {
            el.classList.add('gpu-accelerated');
        });
    }

    preloadResources() {
        // Preload critical CSS animations
        const preloader = document.createElement('div');
        preloader.className = 'preloader visually-hidden';
        preloader.innerHTML = `
            <div class="loading-shimmer"></div>
            <div class="skeleton"></div>
        `;
        document.body.appendChild(preloader);
        setTimeout(() => preloader.remove(), 100);
    }

    // Initialize UI
    initializeUI() {
        // Initialize command preview
        this.updateResourceValidation();
        
        // Initialize real-time stats display
        this.updateRealTimeStats();
        
        // Load saved preferences
        this.loadUserPreferences();
        
        // Set initial estimated time
        this.updateEstimatedTime('~30 seconds');
    }

    updateResourceValidation() {
        // Trigger validation
        if (this.resourceInput) {
            this.resourceInput.dispatchEvent(new Event('input'));
        }
    }

    updateRealTimeStats() {
        // Update any real-time statistics displays
        const engines = document.getElementById('live-engines')?.textContent || '0';
        const threats = document.getElementById('live-threats')?.textContent || '0';
        
        // Update header stats if they exist
        const enginesScanned = document.getElementById('engines-scanned');
        const threatsFound = document.getElementById('threats-found');
        
        if (enginesScanned) enginesScanned.textContent = `${engines}/70+ Engines`;
        if (threatsFound) threatsFound.textContent = `${threats} Threats`;
    }

    // Initialize tooltips
    initializeTooltips() {
        document.querySelectorAll('[data-tooltip]').forEach(element => {
            element.classList.add('enhanced-tooltip');
        });
    }

    // Stats animation
    startStatsAnimation() {
        const statValues = document.querySelectorAll('.stat-value');
        
        statValues.forEach(stat => {
            const finalValue = parseInt(stat.textContent);
            if (isNaN(finalValue)) return;
            
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

    // Play notification sound (optional)
    playNotificationSound() {
        if ('AudioContext' in window) {
            try {
                const audioContext = new AudioContext();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                
                gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.3);
            } catch (e) {
                // Silently fail if audio context is not available
            }
        }
    }

    // Create success particles effect
    createSuccessParticles(element) {
        const rect = element.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        for (let i = 0; i < 10; i++) {
            const particle = document.createElement('div');
            particle.style.cssText = `
                position: fixed;
                width: 4px;
                height: 4px;
                background: #27ae60;
                border-radius: 50%;
                left: ${centerX}px;
                top: ${centerY}px;
                pointer-events: none;
                z-index: 1000;
                animation: particleAnimation 1s ease-out forwards;
            `;
            
            // Random direction and distance
            const angle = (i / 10) * Math.PI * 2;
            const distance = 50 + Math.random() * 50;
            const endX = centerX + Math.cos(angle) * distance;
            const endY = centerY + Math.sin(angle) * distance;
            
            particle.style.setProperty('--end-x', `${endX}px`);
            particle.style.setProperty('--end-y', `${endY}px`);
            
            document.body.appendChild(particle);
            
            setTimeout(() => particle.remove(), 1000);
        }
    }

    // Data persistence
    loadUserPreferences() {
        try {
            const prefs = localStorage.getItem('virustotal_scanner_prefs');
            if (prefs) {
                const preferences = JSON.parse(prefs);
                
                // Apply saved preferences
                if (preferences.defaultOption) {
                    this.currentOption = preferences.defaultOption;
                    document.querySelectorAll('.option-card').forEach(opt => {
                        opt.classList.toggle('active', opt.dataset.option === preferences.defaultOption);
                    });
                }
                
                if (preferences.lastResource && this.resourceInput) {
                    this.resourceInput.value = preferences.lastResource;
                }
            }
        } catch (e) {
            console.warn('Failed to load user preferences:', e);
        }
    }

    saveUserPreferences() {
        try {
            const preferences = {
                defaultOption: this.currentOption,
                lastResource: this.resourceInput?.value || ''
            };
            
            localStorage.setItem('virustotal_scanner_prefs', JSON.stringify(preferences));
        } catch (e) {
            console.warn('Failed to save user preferences:', e);
        }
    }

    // Enhanced cleanup
    destroy() {
        // Stop all intervals and timeouts
        if (this.realTimeInterval) clearInterval(this.realTimeInterval);
        if (this.analysisTimer) clearInterval(this.analysisTimer);
        if (this.progressAnimationFrame) cancelAnimationFrame(this.progressAnimationFrame);
        
        // Remove event listeners
        if (this.visibilityChangeHandler) {
            document.removeEventListener('visibilitychange', this.visibilityChangeHandler);
        }
        if (this.resizeHandler) {
            window.removeEventListener('resize', this.resizeHandler);
        }
        
        // Save preferences
        this.saveUserPreferences();
        
        console.log('Enhanced VirusTotalScanner destroyed');
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.virusTotalScanner = new VirusTotalScanner();
        console.log('Enhanced VirusTotal Scanner initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Enhanced VirusTotal Scanner:', error);
    }
});

// Global utility functions
window.selectSuggestion = function(suggestion) {
    if (window.virusTotalScanner) {
        window.virusTotalScanner.selectSuggestion(suggestion);
    }
};

// Enhanced cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.virusTotalScanner) {
        window.virusTotalScanner.destroy();
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VirusTotalScanner;
}